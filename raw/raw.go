package raw

import (
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/one-api/godivert/compile"
	"github.com/one-api/godivert/sys"
	"github.com/one-api/godivert/types"
)

var ErrInvalidParameter = fmt.Errorf("invalid parameter")

const (
	// VersionMajorMin is the minimum supported driver major version.
	VersionMajorMin = 2

	// VersionMajor is the current supported driver major version.
	VersionMajor = 2
	// VersionMinor is the current supported driver minor version.
	VersionMinor = 2

	magicDll uint64 = 0x4C4C447669645724
	magicSys uint64 = 0x5359537669645723
)

// NewOverlapped creates a new windows.Overlapped structure with a manual reset event.
func NewOverlapped() (*windows.Overlapped, error) {
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create event: %w", err)
	}

	var localOverlapped windows.Overlapped
	localOverlapped.HEvent = event

	return &localOverlapped, nil
}

// Open opens a handle with the default driver name.
func Open(filter string, layer types.Layer, priority int16, flags types.Flag) (windows.Handle, error) {
	return OpenWithName(sys.DefaultDriverName, filter, layer, priority, flags)
}

// OpenWithName open a custom driver with given name
// use sys.LoadDriver if you want to install you own driver before call this function
func OpenWithName(name string, filter string, layer types.Layer, priority int16, flags types.Flag) (windows.Handle, error) {

	if layer > types.LayerMax {
		return 0, fmt.Errorf("%w: invalid layer: %d", ErrInvalidParameter, layer)
	}

	// Apply mandatory layer-specific flags:
	switch layer {
	case types.LayerFlow:
		flags |= types.FlagSniff | types.FlagRecvOnly
	case types.LayerSocket:
		flags |= types.FlagRecvOnly
	case types.LayerReflect:
		flags |= types.FlagSniff | types.FlagRecvOnly
	}

	if !flags.Valid() {
		return 0, fmt.Errorf("%w: invalid flags", ErrInvalidParameter)
	}

	if priority < types.PriorityMin || priority > types.PriorityMax {
		return 0, fmt.Errorf("%w: invalid priority", ErrInvalidParameter)
	}

	// Compile & analyze the filter:
	object, err := compile.CompileFilter(filter, layer)
	if err != nil {
		return 0, fmt.Errorf("%w: compile filter: %v", ErrInvalidParameter, err)
	}
	filterFlags := compile.AnalyzeFilter(layer, object)

	handle, err := openOrInstallDriver(name, (flags&types.FlagNoInstall) != 0)
	if err != nil {
		return 0, fmt.Errorf("open or install driver: %w", err)
	}

	// init overlapped
	overlapped, err := NewOverlapped()
	if err != nil {
		return 0, fmt.Errorf("new overlapped: %w", err)
	}
	defer windows.Close(overlapped.HEvent)

	// Initialize the handle:
	ioctlInit := types.IoctlInitialize{
		Layer:    uint32(layer),
		Priority: uint32(int32(priority) + types.PriorityMax),
		Flags:    uint64(flags),
	}
	version := types.Version{
		Magic: magicDll,
		Major: VersionMajor,
		Minor: VersionMinor,
		Bits:  uint32(unsafe.Sizeof(uintptr(0)) * 8),
	}

	_, err = ioControl(handle, types.IoctlCodeInitialize,
		unsafe.Pointer(&ioctlInit), uint32(unsafe.Sizeof(ioctlInit)),
		unsafe.Pointer(&version), uint32(unsafe.Sizeof(version)),
		overlapped)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return 0, fmt.Errorf("ioctl initialize: %w", err)
	}

	if version.Magic != magicSys || version.Major < VersionMajorMin {
		_ = windows.CloseHandle(handle)
		return 0, fmt.Errorf("driver version mismatch")
	}

	// Emit
	ioctlStartup := types.IoctlStartup{
		Flags: filterFlags,
	}

	objectsBytes := make([]byte, 0, len(object)*types.SizeOfFilter)
	for _, f := range object {
		objectsBytes = append(objectsBytes, f.Marshal()...)
	}

	_, err = ioControl(handle,
		types.IoctlCodeStartup,
		unsafe.Pointer(&ioctlStartup), uint32(unsafe.Sizeof(ioctlStartup)),
		unsafe.Pointer(&objectsBytes[0]), uint32(len(objectsBytes)),
		overlapped,
	)
	runtime.KeepAlive(objectsBytes)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return 0, fmt.Errorf("ioctl startup: %w", err)
	}

	return handle, nil
}

// Recv receives a packet and its address from the driver.
// buffer and address MUST NOT be nil.
func Recv(handle windows.Handle, buffer []byte, address *types.Address, overlapped *windows.Overlapped) (uint32, error) {
	if address == nil {
		return 0, fmt.Errorf("%w: address is nil", ErrInvalidParameter)
	}
	// Create a slice that points to the same memory as address to ensure it gets updated.
	addrSlice := unsafe.Slice(address, 1)
	ioLen, _, err := RecvEx(handle, buffer, addrSlice, 0, overlapped)
	return ioLen, err
}

// RecvEx receives one or more packets and their addresses from the driver.
// buffer and addresses MUST NOT be nil or empty.
// flags is reserved and should be 0.
// Returns the total bytes received in buffer, the total bytes written to addresses, and an error.
func RecvEx(handle windows.Handle, buffer []byte, addresses []types.Address, flags uint64, overlapped *windows.Overlapped) (uint32, uint32, error) {
	if len(addresses) == 0 {
		return 0, 0, fmt.Errorf("%w: addresses slice is empty", ErrInvalidParameter)
	}
	if len(buffer) == 0 {
		return 0, 0, fmt.Errorf("%w: buffer is empty", ErrInvalidParameter)
	}

	addrLenPtr := new(uint32)
	*addrLenPtr = uint32(len(addresses) * int(unsafe.Sizeof(types.Address{})))
	recv := types.IoctlRecv{
		Addr:       uint64(uintptr(unsafe.Pointer(&addresses[0]))),
		AddrLenPtr: uint64(uintptr(unsafe.Pointer(addrLenPtr))),
	}

	ioLen, err := ioControl(handle, types.IoctlCodeRecv,
		unsafe.Pointer(&recv), uint32(unsafe.Sizeof(recv)),
		unsafe.Pointer(&buffer[0]), uint32(len(buffer)),
		overlapped)
	runtime.KeepAlive(addresses)
	runtime.KeepAlive(addrLenPtr)
	runtime.KeepAlive(buffer)
	if err != nil {
		return ioLen, 0, err
	}

	return ioLen, atomic.LoadUint32(addrLenPtr), nil
}

// Send injects a packet into the network stack.
// buffer and address MUST NOT be nil.
func Send(handle windows.Handle, buffer []byte, address *types.Address, overlapped *windows.Overlapped) (uint32, error) {
	if address == nil {
		return 0, fmt.Errorf("%w: address is nil", ErrInvalidParameter)
	}
	return SendEx(handle, buffer, []types.Address{*address}, 0, overlapped)
}

// SendEx injects one or more packets into the network stack.
// buffer and addresses MUST NOT be nil or empty.
// flags is reserved and should be 0.
func SendEx(handle windows.Handle, buffer []byte, addresses []types.Address, flags uint64, overlapped *windows.Overlapped) (uint32, error) {
	if len(addresses) == 0 {
		return 0, fmt.Errorf("%w: addresses slice is empty", ErrInvalidParameter)
	}
	if len(buffer) == 0 {
		return 0, fmt.Errorf("%w: buffer is empty", ErrInvalidParameter)
	}

	send := types.IoctlSend{
		Addr:    uint64(uintptr(unsafe.Pointer(&addresses[0]))),
		AddrLen: uint64(len(addresses) * int(unsafe.Sizeof(types.Address{}))),
	}

	ioLen, err := ioControl(handle, types.IoctlCodeSend,
		unsafe.Pointer(&send), uint32(unsafe.Sizeof(send)),
		unsafe.Pointer(&buffer[0]), uint32(len(buffer)),
		overlapped)
	runtime.KeepAlive(addresses)
	runtime.KeepAlive(buffer)
	if err != nil {
		return ioLen, err
	}

	return ioLen, nil
}

func SetParam(handle windows.Handle, param types.Param, value uint64) error {
	p := types.IoctlSetParam{Param: param, Val: value}
	_, err := ioControl(handle,
		types.IoctlCodeSetParam,
		unsafe.Pointer(&p), uint32(unsafe.Sizeof(p)),
		nil, 0,
		nil)
	return err
}

func GetParam(handle windows.Handle, param types.Param) (uint64, error) {
	var value uint64
	p := types.IoctlGetParam{
		Param: param,
	}

	_, err := ioControl(handle,
		types.IoctlCodeGetParam,
		unsafe.Pointer(&p), uint32(unsafe.Sizeof(p)),
		unsafe.Pointer(&value), uint32(unsafe.Sizeof(value)),

		nil)
	return value, err
}

func Shutdown(handle windows.Handle, how types.Shutdown) error {
	s := types.IoctlShutdown{
		How: uint32(how),
	}
	_, err := ioControl(handle, types.IoctlCodeShutdown,
		unsafe.Pointer(&s), uint32(unsafe.Sizeof(s)),
		nil, 0, nil)
	return err
}

func Close(handle windows.Handle) error {
	return windows.Close(handle)
}

// ioControl Perform a IO request to driver,
// bytesReturned and overlapped must be provided.
func ioControl(
	handle windows.Handle,
	ioControlCode uint32,
	inbuf unsafe.Pointer,
	inBufferSize uint32,
	outbuf unsafe.Pointer,
	outBufferSize uint32,
	overlapped *windows.Overlapped,
) (bytesReturned uint32, err error) {

	err = windows.DeviceIoControl(
		handle,
		ioControlCode,
		(*byte)(inbuf),
		inBufferSize,
		(*byte)(outbuf),
		outBufferSize,
		&bytesReturned,
		overlapped,
	)

	if err != nil {
		if errors.Is(err, windows.ERROR_IO_PENDING) {
			err = windows.GetOverlappedResult(handle, overlapped, &bytesReturned, true)
			if err != nil {
				return 0, fmt.Errorf("GetOverlappedResult: %w", err)
			}
		} else {
			return 0, fmt.Errorf("DeviceIoControl: %w", err)
		}
	}

	return bytesReturned, nil
}

func openOrInstallDriver(driverName string, noInstall bool) (handle windows.Handle, err error) {
	utf16Name, err := syscall.UTF16PtrFromString("\\\\.\\" + driverName)
	if err != nil {
		return 0, fmt.Errorf("convert driver name [%s] to UTF16: %w", driverName, err)
	}

	for i := 0; i < 2; i++ {
		handle, err = windows.CreateFile(
			utf16Name,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED,
			windows.InvalidHandle,
		)
		if err == nil {
			return handle, nil
		}

		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			if noInstall {
				return 0, fmt.Errorf("driver not found and FlagNoInstall is set: %w", err)
			}

			if i == 0 && sys.DefaultDriverName == driverName {
				if loadErr := sys.LoadEmbedSysFile(); loadErr != nil {
					return 0, fmt.Errorf("failed to load embedded driver: %w", loadErr)
				}
				continue
			}
		}
		return 0, fmt.Errorf("failed to open Divert device: %w", err)
	}

	return 0, fmt.Errorf("failed to open Divert device after installation")
}

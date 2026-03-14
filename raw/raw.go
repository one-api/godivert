package raw

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/one-api/godivert/compile"
	"github.com/one-api/godivert/sys"
	"github.com/one-api/godivert/types"
)

var ErrInvalidParameter = fmt.Errorf("invalid parameter")

const (
	VersionMajorMin = 2

	VersionMajor = 2
	VersionMinor = 2

	magicDll uint64 = 0x4C4C447669645724
	magicSys uint64 = 0x5359537669645723
)

func NewOverlapped() (*windows.Overlapped, error) {
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateEvent: %w", err)
	}

	var localOverlapped windows.Overlapped
	localOverlapped.HEvent = event

	return &localOverlapped, nil
}

func Open(filter string, layer types.Layer, priority int16, flags types.Flag) (windows.Handle, error) {
	return OpenWithName(sys.DefaultDriverName, filter, layer, priority, flags)
}

// OpenWithName open a custom driver with given name
// use sys.LoadDriver if you want to install you own driver before call this function
func OpenWithName(name string, filter string, layer types.Layer, priority int16, flags types.Flag) (windows.Handle, error) {

	if layer > types.LayerMax {
		return 0, fmt.Errorf("%w: invalid layer: %d", ErrInvalidParameter, layer)
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
	if err != nil {
		_ = windows.CloseHandle(handle)
		return 0, fmt.Errorf("ioctl startup: %w", err)
	}

	return handle, nil
}

// Recv receive packet and address from driver,
// buffer and address MUST be provided, can't be nil
func Recv(handle windows.Handle, buffer []byte, address *types.Address, overlapped *windows.Overlapped) (uint32, error) {

	addrLen := uint32(unsafe.Sizeof(types.Address{}))
	recv := types.IoctlRecv{
		Addr:       uint64(uintptr(unsafe.Pointer(address))),
		AddrLenPtr: uint64(uintptr(unsafe.Pointer(&addrLen))),
	}

	ioLen, err := ioControl(handle, types.IoctlCodeRecv,
		unsafe.Pointer(&recv), uint32(unsafe.Sizeof(recv)),
		unsafe.Pointer(&buffer[0]), uint32(len(buffer)),
		overlapped)
	if err != nil {
		return ioLen, fmt.Errorf("ioctl: %w", err)
	}

	return ioLen, nil
}

// Send inject packet into kernel
// buffer and address MUST be provided, can't be nil
func Send(handle windows.Handle, buffer []byte, address *types.Address, overlapped *windows.Overlapped) (uint32, error) {
	if address == nil {
		return 0, fmt.Errorf("address parameter is nil")
	}

	send := types.IoctlSend{
		Addr:    uint64(uintptr(unsafe.Pointer(address))),
		AddrLen: uint64(unsafe.Sizeof(types.Address{})),
	}

	ioLen, err := ioControl(handle, types.IoctlCodeSend,
		unsafe.Pointer(&send), uint32(unsafe.Sizeof(send)),
		unsafe.Pointer(&buffer[0]), uint32(len(buffer)),
		overlapped)
	if err != nil {
		return ioLen, fmt.Errorf("ioctl: %w", err)
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
		return 0, fmt.Errorf("convert string [%s] to utf16: %w", driverName, err)
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
			break
		} else {
			err = fmt.Errorf("win api CreateFile: %w", err)
		}

		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			if noInstall {
				return 0, fmt.Errorf("open file with no install flag set: %w", err)
			}

			if sys.DefaultDriverName == driverName {
				err := sys.LoadEmbedSysFile()
				if err != nil {
					return 0, fmt.Errorf("load embed driver: %w", err)
				}
			}
			continue
		}
	}

	return handle, err
}

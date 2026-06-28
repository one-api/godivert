package godivert

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/one-api/godivert/raw"
	"github.com/one-api/godivert/types"
)

// Divert represents a handle to the driver.
type Divert struct {
	handle     windows.Handle
	overlapped *windows.Overlapped
}

type (
	// Layer represents the layer (e.g., Network, Flow, etc.)
	Layer = types.Layer
	// Flag represents the flags (e.g., Sniff, Drop, etc.)
	Flag = types.Flag
	// Address represents the address structure for packets.
	Address = types.Address
)

const (
	LayerNetwork        = types.LayerNetwork
	LayerNetworkForward = types.LayerNetworkForward
	LayerFlow           = types.LayerFlow
	LayerSocket         = types.LayerSocket
	LayerReflect        = types.LayerReflect
	LayerMax            = types.LayerMax

	FlagSniff     = types.FlagSniff
	FlagDrop      = types.FlagDrop
	FlagRecvOnly  = types.FlagRecvOnly
	FlagReadOnly  = types.FlagReadOnly
	FlagSendOnly  = types.FlagSendOnly
	FlagWriteOnly = types.FlagWriteOnly
	FlagNoInstall = types.FlagNoInstall
	FlagFragments = types.FlagFragments
)

// New creates a new Divert handle using the default driver name.
// filter is a filter string.
// layer specifies the capture layer.
// priority is the priority of the handle.
// flags specify additional options.
func New(filter string, layer Layer, priority int16, flags Flag) (*Divert, error) {
	handle, err := raw.Open(filter, layer, priority, flags)
	if err != nil {
		return nil, err
	}
	d := &Divert{handle: handle}
	d.overlapped, err = d.newOverlapped()
	if err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("new overlapped: %w", err)
	}
	return d, nil
}

// NewWithName creates a new Divert handle using a custom driver name.
func NewWithName(name string, filter string, layer Layer, priority int16, flags Flag) (*Divert, error) {
	handle, err := raw.OpenWithName(name, filter, layer, priority, flags)
	if err != nil {
		return nil, err
	}

	d := &Divert{handle: handle}
	d.overlapped, err = d.newOverlapped()
	if err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("new overlapped: %w", err)
	}
	return d, nil
}

func (d *Divert) newOverlapped() (*windows.Overlapped, error) {
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateEvent: %w", err)
	}

	var localOverlapped windows.Overlapped
	localOverlapped.HEvent = event

	return &localOverlapped, nil
}

// Recv receives a packet from the driver.
// buffer must be large enough to hold the packet.
// address will be populated with the packet's metadata.
func (d *Divert) Recv(buffer []byte, address *Address) (uint32, error) {
	return raw.Recv(d.handle, buffer, address, d.overlapped)
}

// RecvEx receives one or more packets from the driver.
// Returns the number of bytes received in buffer and the number of addresses received.
func (d *Divert) RecvEx(buffer []byte, addresses []Address) (uint32, uint32, error) {
	ioLen, addrLen, err := raw.RecvEx(d.handle, buffer, addresses, 0, d.overlapped)
	return ioLen, addrLen / uint32(unsafe.Sizeof(Address{})), err
}

// Send injects a packet into the network stack.
func (d *Divert) Send(buffer []byte, address *Address) (uint32, error) {
	return raw.Send(d.handle, buffer, address, d.overlapped)
}

// SendEx injects one or more packets into the network stack.
func (d *Divert) SendEx(buffer []byte, addresses []Address) (uint32, error) {
	return raw.SendEx(d.handle, buffer, addresses, 0, d.overlapped)
}

// Close closes the Divert handle and releases resources.
func (d *Divert) Close() error {
	if d.overlapped != nil && d.overlapped.HEvent != 0 {
		_ = windows.CloseHandle(d.overlapped.HEvent)
		d.overlapped.HEvent = 0
	}
	return raw.Close(d.handle)
}

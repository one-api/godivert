package godivert

import (
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/one-api/godivert/raw"
	"github.com/one-api/godivert/types"
)

type Divert struct {
	handle     windows.Handle
	overlapped *windows.Overlapped
}

type (
	Layer   = types.Layer
	Flag    = types.Flag
	Address = types.Address
)

const (
	LayerNetwork        = types.LayerNetwork
	LayerNetworkForward = types.LayerNetworkForward
	LayerFlow           = types.LayerFlow
	LayerSocket         = types.LayerSocket
	LayerReflect        = types.LayerReflect
	LayerMax            = types.LayerMax
)

const (
	FlagSniff     = types.FlagSniff
	FlagDrop      = types.FlagDrop
	FlagRecvOnly  = types.FlagRecvOnly
	FlagReadOnly  = types.FlagReadOnly
	FlagSendOnly  = types.FlagSendOnly
	FlagWriteOnly = types.FlagWriteOnly
	FlagNoInstall = types.FlagNoInstall
	FlagFragments = types.FlagFragments
)

func New(filter string, layer Layer, priority int16, flags Flag) (*Divert, error) {
	handle, err := raw.Open(filter, layer, priority, flags)
	if err != nil {
		return nil, err
	}
	d := &Divert{handle: handle}
	d.overlapped, err = d.newOverlapped()
	if err != nil {
		return nil, fmt.Errorf("new overlapped: %w", err)
	}
	return d, nil
}

func NewWithName(name string, filter string, layer Layer, priority int16, flags Flag) (*Divert, error) {
	handle, err := raw.OpenWithName(name, filter, layer, priority, flags)
	if err != nil {
		return nil, err
	}

	d := &Divert{handle: handle}
	d.overlapped, err = d.newOverlapped()
	if err != nil {
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

func (d *Divert) Recv(buffer []byte, address *Address) (uint32, error) {
	return raw.Recv(d.handle, buffer, address, d.overlapped)
}

func (d *Divert) Send(buffer []byte, address *Address) (uint32, error) {
	return raw.Send(d.handle, buffer, address, d.overlapped)
}

func (d *Divert) Close() error {
	return raw.Close(d.handle)
}

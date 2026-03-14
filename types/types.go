package types

import "unsafe"

type Layer int

const (
	LayerNetwork Layer = iota
	LayerNetworkForward
	LayerFlow
	LayerSocket
	LayerReflect

	LayerMax = LayerReflect
)

type Event int

const (
	EventNetworkPacket Event = iota
	EventFlowEstablished
	EventFlowDeleted
	EventSocketBind
	EventSocketConnect
	EventSocketListen
	EventSocketAccept
	EventSocketClose
	EventReflectOpen
	EventReflectClose

	EventMax = EventReflectClose
)

type Shutdown int

const (
	ShutdownRecv Shutdown = 0x1
	ShutdownSend Shutdown = 0x2
	ShutdownBoth Shutdown = 0x3

	ShutdownMax = ShutdownBoth
)

type Param uint32

const (
	ParamQueueLength Param = iota
	ParamQueueTime
	ParamQueueSize
	ParamVersionMajor
	ParamVersionMinor

	ParamMax = ParamVersionMinor
)

const (
	PriorityHighest         = 30000
	PriorityLowest          = -PriorityHighest
	ParamQueueLengthDefault = 4096
	ParamQueueLengthMin     = 32
	ParamQueueLengthMax     = 16384
	ParamQueueTimeDefault   = 2000     // 2s
	ParamQueueTimeMin       = 100      // 100ms
	ParamQueueTimeMax       = 16000    // 16s
	ParamQueueSizeDefault   = 4194304  // 4MB
	ParamQueueSizeMin       = 65535    // 64KB
	ParamQueueSizeMax       = 33554432 // 32MB
	BatchMax                = 0xFF     // 255
	MtuMax                  = 40 + 0xFFFF
)

type Address struct {
	Timestamp int64
	Layer     uint8
	Event     uint8
	Flags     uint8
	_         uint8
	Reserved2 uint32
	union     [64]byte
}

func (a *Address) Network() *DataNetwork {
	return (*DataNetwork)(unsafe.Pointer(&a.union[0]))
}

func (a *Address) Flow() *DataFlow {
	return (*DataFlow)(unsafe.Pointer(&a.union[0]))
}

func (a *Address) Socket() *DataSocket {
	return (*DataSocket)(unsafe.Pointer(&a.union[0]))
}

func (a *Address) Reflect() *DataReflect {
	return (*DataReflect)(unsafe.Pointer(&a.union[0]))
}

func (a *Address) Sniffed() bool     { return (a.Flags & 0x01) != 0 }
func (a *Address) Outbound() bool    { return (a.Flags & 0x02) != 0 }
func (a *Address) Loopback() bool    { return (a.Flags & 0x04) != 0 }
func (a *Address) Impostor() bool    { return (a.Flags & 0x08) != 0 }
func (a *Address) IPv6() bool        { return (a.Flags & 0x10) != 0 }
func (a *Address) IPChecksum() bool  { return (a.Flags & 0x20) != 0 }
func (a *Address) TCPChecksum() bool { return (a.Flags & 0x40) != 0 }
func (a *Address) UDPChecksum() bool { return (a.Flags & 0x80) != 0 }

func (a *Address) SetSniffed(v bool) {
	if v {
		a.Flags |= 0x01
	} else {
		a.Flags &^= 0x01
	}
}
func (a *Address) SetOutbound(v bool) {
	if v {
		a.Flags |= 0x02
	} else {
		a.Flags &^= 0x02
	}
}
func (a *Address) SetLoopback(v bool) {
	if v {
		a.Flags |= 0x04
	} else {
		a.Flags &^= 0x04
	}
}
func (a *Address) SetImpostor(v bool) {
	if v {
		a.Flags |= 0x08
	} else {
		a.Flags &^= 0x08
	}
}
func (a *Address) SetIPv6(v bool) {
	if v {
		a.Flags |= 0x10
	} else {
		a.Flags &^= 0x10
	}
}
func (a *Address) SetIPChecksum(v bool) {
	if v {
		a.Flags |= 0x20
	} else {
		a.Flags &^= 0x20
	}
}
func (a *Address) SetTCPChecksum(v bool) {
	if v {
		a.Flags |= 0x40
	} else {
		a.Flags &^= 0x40
	}
}
func (a *Address) SetUDPChecksum(v bool) {
	if v {
		a.Flags |= 0x80
	} else {
		a.Flags &^= 0x80
	}
}

type DataNetwork struct {
	IfIdx    uint32
	SubIfIdx uint32
}

type DataFlow struct {
	EndpointId       uint64
	ParentEndpointId uint64
	ProcessId        uint32
	LocalAddr        [4]uint32
	RemoteAddr       [4]uint32
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
}

type DataSocket struct {
	EndpointId       uint64
	ParentEndpointId uint64
	ProcessId        uint32
	LocalAddr        [4]uint32
	RemoteAddr       [4]uint32
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
}

type DataReflect struct {
	Timestamp int64
	ProcessId uint32
	Layer     Layer
	Flags     uint64
	Priority  int16
}

type IProto uint8

const (
	IProtoHopopts  IProto = 0
	IProtoIcmp     IProto = 1
	IProtoTcp      IProto = 6
	IProtoUdp      IProto = 17
	IProtoRouting  IProto = 43
	IProtoFragment IProto = 44
	IProtoAh       IProto = 51
	IProtoIcmpV6   IProto = 58
	IProtoNone     IProto = 59
	IProtoDstOpts  IProto = 60
)

package types

import (
	"encoding/binary"
)

// Filter Fields
const (
	FilterFieldZero = iota
	FilterFieldInbound
	FilterFieldOutbound
	FilterFieldIfIdx
	FilterFieldSubIfIdx
	FilterFieldIp
	FilterFieldIpv6
	FilterFieldIcmp
	FilterFieldTcp
	FilterFieldUdp
	FilterFieldIcmpv6
	FilterFieldIpHdrLength
	FilterFieldIpTos
	FilterFieldIpLength
	FilterFieldIpId
	FilterFieldIpDf
	FilterFieldIpMf
	FilterFieldIpFragOff
	FilterFieldIpTtl
	FilterFieldIpProtocol
	FilterFieldIpChecksum
	FilterFieldIpSrcAddr
	FilterFieldIpDstAddr
	FilterFieldIpv6TrafficClass
	FilterFieldIpv6FlowLabel
	FilterFieldIpv6Length
	FilterFieldIpv6NextHdr
	FilterFieldIpv6HopLimit
	FilterFieldIpv6SrcAddr
	FilterFieldIpv6DstAddr
	FilterFieldIcmpType
	FilterFieldIcmpCode
	FilterFieldIcmpChecksum
	FilterFieldIcmpBody
	FilterFieldIcmpv6Type
	FilterFieldIcmpv6Code
	FilterFieldIcmpv6Checksum
	FilterFieldIcmpv6Body
	FilterFieldTcpSrcPort
	FilterFieldTcpDstPort
	FilterFieldTcpSeqNum
	FilterFieldTcpAckNum
	FilterFieldTcpHdrLength
	FilterFieldTcpUrg
	FilterFieldTcpAck
	FilterFieldTcpPsh
	FilterFieldTcpRst
	FilterFieldTcpSyn
	FilterFieldTcpFin
	FilterFieldTcpWindow
	FilterFieldTcpChecksum
	FilterFieldTcpUrgPtr
	FilterFieldTcpPayloadLength
	FilterFieldUdpSrcPort
	FilterFieldUdpDstPort
	FilterFieldUdpLength
	FilterFieldUdpChecksum
	FilterFieldUdpPayloadLength
	FilterFieldLoopback
	FilterFieldImpostor
	FilterFieldProcessId
	FilterFieldLocalAddr
	FilterFieldRemoteAddr
	FilterFieldLocalPort
	FilterFieldRemotePort
	FilterFieldProtocol
	FilterFieldEndpointId
	FilterFieldParentEndpointId
	FilterFieldLayer
	FilterFieldPriority
	FilterFieldEvent
	FilterFieldPacket
	FilterFieldPacket16
	FilterFieldPacket32
	FilterFieldTcpPayload
	FilterFieldTcpPayload16
	FilterFieldTcpPayload32
	FilterFieldUdpPayload
	FilterFieldUdpPayload16
	FilterFieldUdpPayload32
	FilterFieldLength
	FilterFieldTimestamp
	FilterFieldRandom8
	FilterFieldRandom16
	FilterFieldRandom32
	FilterFieldFragment

	FilterFieldMax = FilterFieldFragment
)

const (
	FilterTestEq  = 0
	FilterTestNeq = 1
	FilterTestLt  = 2
	FilterTestLeq = 3
	FilterTestGt  = 4
	FilterTestGeq = 5

	FilterTestMax = FilterTestGeq
)

const (
	FilterResultAccept = 0x7FFE
	FilterResultReject = 0x7FFF
)

// filter flags
type FilterFlag uint64

const (
	FilterFlagInbound            FilterFlag = 0x0000000000000010
	FilterFlagOutbound           FilterFlag = 0x0000000000000020
	FilterFlagIp                 FilterFlag = 0x0000000000000040
	FilterFlagIpv6               FilterFlag = 0x0000000000000080
	FilterFlagEventFlowDeleted   FilterFlag = 0x0000000000000100
	FilterFlagEventSocketBind    FilterFlag = 0x0000000000000200
	FilterFlagEventSocketConnect FilterFlag = 0x0000000000000400
	FilterFlagEventSocketListen  FilterFlag = 0x0000000000000800
	FilterFlagEventSocketAccept  FilterFlag = 0x0000000000001000
	FilterFlagEventSocketClose   FilterFlag = 0x0000000000002000
)

// priorities
const (
	PriorityMax = PriorityHighest
	PriorityMin = PriorityLowest
)

//  message definitions

type IoctlRecv struct {
	Addr       uint64 // *Address
	AddrLenPtr uint64 // *uint
}

type IoctlSend struct {
	Addr    uint64 // *Address
	AddrLen uint64 // sizeof(Address)
}

type IoctlInitialize struct {
	Layer    uint32
	Priority uint32
	Flags    uint64
}

type IoctlStartup struct {
	Flags uint64
	_     [8]byte // Padding to 16 bytes (union size)
}

type IoctlShutdown struct {
	How uint32   // Shutdown*
	_   [12]byte // Padding to 16 bytes (union size)
}

type IoctlGetParam struct {
	Param Param    // Param*
	_     [12]byte // Padding to 16 bytes (union size)
}

type IoctlSetParam struct {
	Val   uint64
	Param Param
	_     [4]byte // Padding to 16 bytes (union size)
}

// Version is initialization structure.
type Version struct {
	Magic      uint64
	Major      uint32
	Minor      uint32
	Bits       uint32
	Reserved32 [3]uint32
	Reserved64 [4]uint64
}

//	{
//	   UINT32 field:11;
//	   UINT32 test:5;
//	   UINT32 success:16;
//	   UINT32 failure:16;
//	   UINT32 neg:1;
//	   UINT32 reserved:15;
//	   UINT32 arg[4];
//	}
type Filter struct {
	field    uint32    // 11 bits
	test     uint32    // 5 bits
	success  uint16    // 16 bits
	failure  uint16    // 16 bits
	neg      uint32    // 1 bit
	reserved uint32    // 15 bits
	arg      [4]uint32 // 4 * 32 bits
}

const SizeOfFilter = 24

func (f *Filter) Field() uint32       { return f.field }
func (f *Filter) SetField(val uint32) { f.field = val & 0x7FF }

func (f *Filter) Test() uint32       { return f.test }
func (f *Filter) SetTest(val uint32) { f.test = val & 0x1F }

func (f *Filter) Success() uint16       { return f.success }
func (f *Filter) SetSuccess(val uint16) { f.success = val }

func (f *Filter) Failure() uint16       { return f.failure }
func (f *Filter) SetFailure(val uint16) { f.failure = val }

func (f *Filter) Neg() uint32 { return f.neg }
func (f *Filter) SetNeg(val uint32) {
	f.neg = val
}

func (f *Filter) Arg() [4]uint32 {
	return f.arg
}

func (f *Filter) SetArg(idx int, val uint32) {
	if idx >= 0 && idx < 4 {
		f.arg[idx] = val
	}
}

// Marshal return C layout byte slice of the Filter struct, suitable for IOCTL calls.
func (f *Filter) Marshal() []byte {
	buf := make([]byte, 24)

	// [Success:16][Test:5][Field:11]
	var first uint32
	first |= f.field & 0x7FF
	first |= (f.test & 0x1F) << 11
	first |= uint32(f.success) << 16
	binary.LittleEndian.PutUint32(buf[0:4], first)

	// [Reserved:15][Neg:1][Failure:16]
	var second uint32
	second |= uint32(f.failure)
	second |= (f.neg & 0x1) << 16
	second |= (f.reserved & 0x7FFF) << 17
	binary.LittleEndian.PutUint32(buf[4:8], second)

	// Arg
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(buf[8+i*4:12+i*4], f.arg[i])
	}

	return buf
}

// from windows sdk
const (
	FILE_DEVICE_NETWORK = 0x00000012

	FILE_READ_DATA  = 0x00000001
	FILE_WRITE_DATA = 0x00000002

	METHOD_IN_DIRECT  = 1
	METHOD_OUT_DIRECT = 2
)

func CtlCode(DeviceType, Function, Method, Access uint32) uint32 {
	return ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)
}

var (
	IoctlCodeInitialize = CtlCode(FILE_DEVICE_NETWORK, 0x921, METHOD_OUT_DIRECT, FILE_READ_DATA|FILE_WRITE_DATA)
	IoctlCodeStartup    = CtlCode(FILE_DEVICE_NETWORK, 0x922, METHOD_IN_DIRECT, FILE_READ_DATA|FILE_WRITE_DATA)
	IoctlCodeRecv       = CtlCode(FILE_DEVICE_NETWORK, 0x923, METHOD_OUT_DIRECT, FILE_READ_DATA)
	IoctlCodeSend       = CtlCode(FILE_DEVICE_NETWORK, 0x924, METHOD_IN_DIRECT, FILE_READ_DATA|FILE_WRITE_DATA)
	IoctlCodeSetParam   = CtlCode(FILE_DEVICE_NETWORK, 0x925, METHOD_IN_DIRECT, FILE_READ_DATA|FILE_WRITE_DATA)
	IoctlCodeGetParam   = CtlCode(FILE_DEVICE_NETWORK, 0x926, METHOD_OUT_DIRECT, FILE_READ_DATA)
	IoctlCodeShutdown   = CtlCode(FILE_DEVICE_NETWORK, 0x927, METHOD_IN_DIRECT, FILE_READ_DATA|FILE_WRITE_DATA)
)

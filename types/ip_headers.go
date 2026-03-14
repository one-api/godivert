package types

// IPHdr IPv4 header
type IPHdr struct {
	VerLen   uint8
	TOS      uint8
	Length   uint16
	Id       uint16
	FragOff0 uint16
	TTL      uint8
	Protocol uint8
	Checksum uint16
	SrcAddr  uint32
	DstAddr  uint32
}

func (h *IPHdr) Version() uint8 { return (h.VerLen >> 4) & 0x0F }

func (h *IPHdr) HdrLength() uint8 {
	return h.VerLen & 0x0F
}

func (h *IPHdr) FragOff() uint16 {
	return ((h.FragOff0 & 0xFF00) >> 8) | ((h.FragOff0 & 0x001F) << 8)
}

func (h *IPHdr) SetFragOff(val uint16) {
	h.FragOff0 = (h.FragOff0 & 0x00E0) | ((val & 0xFF) << 8) | ((val >> 8) & 0x1F)
}

func (h *IPHdr) MF() bool {
	return (h.FragOff0 & 0x0020) != 0
}

func (h *IPHdr) SetMF(val bool) {
	if val {
		h.FragOff0 |= 0x0020
	} else {
		h.FragOff0 &= ^uint16(0x0020)
	}
}

func (h *IPHdr) DF() bool {
	return (h.FragOff0 & 0x0040) != 0
}

func (h *IPHdr) SetDF(val bool) {
	if val {
		h.FragOff0 |= 0x0040
	} else {
		h.FragOff0 &= ^uint16(0x0040)
	}
}

func (h *IPHdr) Reserved() bool {
	return (h.FragOff0 & 0x0080) != 0
}

func (h *IPHdr) SetReserved(val bool) {
	if val {
		h.FragOff0 |= 0x0080
	} else {
		h.FragOff0 &= ^uint16(0x0080)
	}
}

// IPv6Hdr IPv6 header
type IPv6Hdr struct {
	TVFT       uint16 // TrafficClass0:4, Version:4, FlowLabel0:4, TrafficClass1:4
	FlowLabel1 uint16
	Length     uint16
	NextHdr    uint8
	HopLimit   uint8
	SrcAddr    [4]uint32
	DstAddr    [4]uint32
}

func (h *IPv6Hdr) TrafficClass() uint8 {
	return uint8((h.TVFT&0x0F)<<4) | uint8((h.TVFT>>12)&0x0F)
}

func (h *IPv6Hdr) SetTrafficClass(val uint8) {
	h.TVFT = (h.TVFT & 0x0FF0) | uint16(val>>4) | (uint16(val&0x0F) << 12)
}

func (h *IPv6Hdr) FlowLabel() uint32 {
	return (uint32((h.TVFT>>8)&0x0F) << 16) | uint32(h.FlowLabel1)
}

func (h *IPv6Hdr) SetFlowLabel(val uint32) {
	h.TVFT = (h.TVFT & 0xF0FF) | (uint16((val>>16)&0x0F) << 8)
	h.FlowLabel1 = uint16(val & 0xFFFF)
}

func (h *IPv6Hdr) Version() uint8 {
	return uint8((h.TVFT >> 4) & 0x0F)
}

func (h *IPv6Hdr) SetVersion(val uint8) {
	h.TVFT = (h.TVFT & 0xFF0F) | (uint16(val&0x0F) << 4)
}

type ICMPHdr struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Body     uint32
}

type ICMPv6Hdr struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Body     uint32
}

type TCPHdr struct {
	SrcPort            uint16
	DstPort            uint16
	SeqNum             uint32
	AckNum             uint32
	R1HdrLengthFlagsR2 uint16
	Window             uint16
	Checksum           uint16
	UrgPtr             uint16
}

func (h *TCPHdr) HdrLength() uint8 {
	return uint8((h.R1HdrLengthFlagsR2 >> 12) & 0xF)
}

func (h *TCPHdr) SetHdrLength(val uint8) {
	h.R1HdrLengthFlagsR2 = (h.R1HdrLengthFlagsR2 & 0x0FFF) | (uint16(val&0x0F) << 12)
}

func (h *TCPHdr) Fin() bool {
	return (h.R1HdrLengthFlagsR2 & 0x01) != 0
}
func (h *TCPHdr) SetFin(val bool) {
	if val {
		h.R1HdrLengthFlagsR2 |= 0x01
	} else {
		h.R1HdrLengthFlagsR2 &= ^uint16(0x01)
	}
}

func (h *TCPHdr) Syn() bool {
	return (h.R1HdrLengthFlagsR2 & 0x02) != 0
}
func (h *TCPHdr) SetSyn(val bool) {
	if val {
		h.R1HdrLengthFlagsR2 |= 0x02
	} else {
		h.R1HdrLengthFlagsR2 &= ^uint16(0x02)
	}
}

func (h *TCPHdr) Rst() bool {
	return (h.R1HdrLengthFlagsR2 & 0x04) != 0
}
func (h *TCPHdr) SetRst(val bool) {
	if val {
		h.R1HdrLengthFlagsR2 |= 0x04
	} else {
		h.R1HdrLengthFlagsR2 &= ^uint16(0x04)
	}
}

func (h *TCPHdr) Psh() bool {
	return (h.R1HdrLengthFlagsR2 & 0x08) != 0
}
func (h *TCPHdr) SetPsh(val bool) {
	if val {
		h.R1HdrLengthFlagsR2 |= 0x08
	} else {
		h.R1HdrLengthFlagsR2 &= ^uint16(0x08)
	}
}

func (h *TCPHdr) Ack() bool {
	return (h.R1HdrLengthFlagsR2 & 0x10) != 0
}
func (h *TCPHdr) SetAck(val bool) {
	if val {
		h.R1HdrLengthFlagsR2 |= 0x10
	} else {
		h.R1HdrLengthFlagsR2 &= ^uint16(0x10)
	}
}

func (h *TCPHdr) Urg() bool {
	return (h.R1HdrLengthFlagsR2 & 0x20) != 0
}
func (h *TCPHdr) SetUrg(val bool) {
	if val {
		h.R1HdrLengthFlagsR2 |= 0x20
	} else {
		h.R1HdrLengthFlagsR2 &= ^uint16(0x20)
	}
}

type UDPHdr struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

type IPv6FragHdr struct {
	NextHdr  uint8
	Reserved uint8
	FragOff0 uint16
	Id       uint32
}

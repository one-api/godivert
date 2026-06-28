package godivert

import (
	"encoding/binary"
	"unsafe"

	"github.com/one-api/godivert/types"
)

// Helper flags for CalcChecksums
const (
	HelperNoIPChecksum     = types.HelperNoIPChecksum
	HelperNoICMPChecksum   = types.HelperNoICMPChecksum
	HelperNoICMPV6Checksum = types.HelperNoICMPV6Checksum
	HelperNoTCPChecksum    = types.HelperNoTCPChecksum
	HelperNoUDPChecksum    = types.HelperNoUDPChecksum
)

// PacketHeaders represents the parsed headers of a packet.
type PacketHeaders struct {
	IP      *types.IPHdr
	IPv6    *types.IPv6Hdr
	TCP     *types.TCPHdr
	UDP     *types.UDPHdr
	ICMP    *types.ICMPHdr
	ICMPv6  *types.ICMPv6Hdr
	Payload []byte
}

// ParsePacket parses a raw packet into its constituent headers.
func ParsePacket(packet []byte) *PacketHeaders {
	if len(packet) < 20 {
		return nil
	}

	headers := &PacketHeaders{}
	version := packet[0] >> 4

	var protocol uint8
	var nextHeader []byte

	if version == 4 {
		headers.IP = (*types.IPHdr)(unsafe.Pointer(&packet[0]))
		ihl := int(headers.IP.VerLen&0x0F) * 4
		if len(packet) < ihl {
			return nil
		}
		protocol = headers.IP.Protocol
		nextHeader = packet[ihl:]
	} else if version == 6 {
		if len(packet) < 40 {
			return nil
		}
		headers.IPv6 = (*types.IPv6Hdr)(unsafe.Pointer(&packet[0]))
		protocol = headers.IPv6.NextHdr
		nextHeader = packet[40:]
	} else {
		return nil
	}

	switch protocol {
	case 1: // ICMP
		if len(nextHeader) >= 8 {
			headers.ICMP = (*types.ICMPHdr)(unsafe.Pointer(&nextHeader[0]))
		}
	case 58: // ICMPv6
		if len(nextHeader) >= 8 {
			headers.ICMPv6 = (*types.ICMPv6Hdr)(unsafe.Pointer(&nextHeader[0]))
		}
	case 6: // TCP
		if len(nextHeader) >= 20 {
			headers.TCP = (*types.TCPHdr)(unsafe.Pointer(&nextHeader[0]))
			thl := int(headers.TCP.HdrLength()) * 4
			if len(nextHeader) >= thl {
				headers.Payload = nextHeader[thl:]
			}
		}
	case 17: // UDP
		if len(nextHeader) >= 8 {
			headers.UDP = (*types.UDPHdr)(unsafe.Pointer(&nextHeader[0]))
			headers.Payload = nextHeader[8:]
		}
	}

	return headers
}

// CalcChecksums recalculates the checksums for a packet.
func CalcChecksums(packet []byte, flags uint64) {
	headers := ParsePacket(packet)
	if headers == nil {
		return
	}

	if headers.IP != nil && (flags&HelperNoIPChecksum) == 0 {
		headers.IP.Checksum = 0
		headers.IP.Checksum = calculateChecksum(packet[:int(headers.IP.VerLen&0x0F)*4], 0)
	}

	if headers.TCP != nil && (flags&HelperNoTCPChecksum) == 0 {
		headers.TCP.Checksum = 0
		var pseudoSum uint32
		if headers.IP != nil {
			pseudoSum = pseudoHeaderChecksum(headers.IP.SrcAddr, headers.IP.DstAddr, 6, uint32(len(packet)-int(headers.IP.VerLen&0x0F)*4))
		} else if headers.IPv6 != nil {
			pseudoSum = pseudoHeaderIPv6Checksum(headers.IPv6.SrcAddr, headers.IPv6.DstAddr, 6, uint32(len(packet)-40))
		}
		headers.TCP.Checksum = calculateChecksum(packet[len(packet)-int(len(headers.Payload))-int(headers.TCP.HdrLength())*4:], pseudoSum)
	}

	if headers.UDP != nil && (flags&HelperNoUDPChecksum) == 0 {
		headers.UDP.Checksum = 0
		var pseudoSum uint32
		if headers.IP != nil {
			pseudoSum = pseudoHeaderChecksum(headers.IP.SrcAddr, headers.IP.DstAddr, 17, uint32(len(packet)-int(headers.IP.VerLen&0x0F)*4))
		} else if headers.IPv6 != nil {
			pseudoSum = pseudoHeaderIPv6Checksum(headers.IPv6.SrcAddr, headers.IPv6.DstAddr, 17, uint32(len(packet)-40))
		}
		headers.UDP.Checksum = calculateChecksum(packet[len(packet)-int(len(headers.Payload))-8:], pseudoSum)
	}

	// ICMP/ICMPv6 can be added similarly if needed.
}

func calculateChecksum(data []byte, initial uint32) uint16 {
	sum := initial
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func pseudoHeaderChecksum(src, dst uint32, proto uint8, length uint32) uint32 {
	var sum uint32
	sum += src >> 16
	sum += src & 0xFFFF
	sum += dst >> 16
	sum += dst & 0xFFFF
	sum += uint32(proto)
	sum += length
	return sum
}

func pseudoHeaderIPv6Checksum(src, dst [4]uint32, proto uint8, length uint32) uint32 {
	var sum uint32
	for i := 0; i < 4; i++ {
		sum += src[i] >> 16
		sum += src[i] & 0xFFFF
		sum += dst[i] >> 16
		sum += dst[i] & 0xFFFF
	}
	sum += uint32(proto)
	sum += length
	return sum
}

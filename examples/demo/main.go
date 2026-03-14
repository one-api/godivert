package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"runtime"

	"golang.org/x/net/ipv4"

	"github.com/one-api/godivert"
)

func main() {

	// Open driver
	filter := "!loopback and (tcp or udp)"
	divert, err := godivert.New(filter, godivert.LayerNetwork, 0, 0)
	if err != nil {
		log.Fatalf("Failed to open godivert: %v", err)
	}
	defer divert.Close()

	log.Println("Waiting for packets...")

	// Buffer for packet data
	packet := make([]byte, 2000)
	var addr godivert.Address

	runtime.LockOSThread()

	for i := 0; ; i++ {
		readLen, err := divert.Recv(packet, &addr)
		if err != nil {
			log.Printf("Failed to receive packet: %v", err)
			continue
		}

		showPacketInfo(packet[:readLen])

		_, err = divert.Send(packet[:readLen], &addr)
		if err != nil {
			log.Printf("Failed to send packet: %v", err)
		}

	}
}

func showPacketInfo(packet []byte) {

	// 1. Parse the IPv4 Header
	iph, err := ipv4.ParseHeader(packet)
	if err != nil {
		fmt.Printf("Error parsing IPv4: %v\n", err)
		return
	}

	// 2. Identify the Protocol
	proto := ""
	details := ""

	// Jump to the payload start
	payload := packet[iph.Len:]

	switch iph.Protocol {
	case 6: // TCP
		proto = "TCP"
		if len(payload) >= 20 {
			srcPort := binary.BigEndian.Uint16(payload[0:2])
			dstPort := binary.BigEndian.Uint16(payload[2:4])
			seq := binary.BigEndian.Uint16(payload[4:8])
			details = fmt.Sprintf("Port: %d -> %d, Seq: %d", srcPort, dstPort, seq)
		}
	case 17: // UDP
		proto = "UDP"
		if len(payload) >= 8 {
			srcPort := binary.BigEndian.Uint16(payload[0:2])
			dstPort := binary.BigEndian.Uint16(payload[2:4])
			details = fmt.Sprintf("Port: %d -> %d, Len: %d", srcPort, dstPort, binary.BigEndian.Uint16(payload[4:6]))
		}
	case 1: // ICMP
		proto = "ICMP"
		details = fmt.Sprintf("Type: %d, Code: %d", payload[0], payload[1])
	default:
		proto = fmt.Sprintf("Proto(%d)", iph.Protocol)
	}

	// 3. Print in tcpdump-style format
	fmt.Printf("%s > %s: %s %s (len %d, ttl %d)\n",
		iph.Src, iph.Dst, proto, details, iph.TotalLen, iph.TTL)

}

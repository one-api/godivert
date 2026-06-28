package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/one-api/godivert"
)

// Blocklist matching criteria
var blocklistKeywords = []string{
	"ads.", "ad.", "adservice", "doubleclick", "telemetry", "analytics",
	"tracker", "adsystem", "amazon-adsystem", "adnxs", "googlesyndication",
}

func main() {
	// Title Banner
	fmt.Println("\033[36m===================================================\033[0m")
	fmt.Println("\033[36m🛡️  GoDivert Pure Go DNS Sinkhole & Spoofing Firewall 🛡️\033[0m")
	fmt.Println("\033[36m===================================================\033[0m")
	fmt.Println("This demo intercepts outbound DNS queries (UDP port 53).")
	fmt.Println("Queries matching blocklist keywords will be spoofed to \033[31m127.0.0.1\033[0m / \033[31m::\033[0m instantly.")
	fmt.Println("\033[36m---------------------------------------------------\033[0m")
	fmt.Println("Starting DNS sinkhole. Please make sure you are running as Administrator...")

	// Lock OS thread for driver interaction
	runtime.LockOSThread()

	// Capture outbound DNS queries (UDP port 53)
	// We use "!impostor" to prevent infinite loop of injected packets.
	filter := "outbound and udp.DstPort == 53 and !impostor"
	divert, err := godivert.New(filter, godivert.LayerNetwork, 0, 0)
	if err != nil {
		log.Fatalf("\033[31mError opening GoDivert driver: %v\033[0m\n(Hint: Are you running as Administrator?)", err)
	}
	defer divert.Close()

	// Signal handling for clean exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n\033[33mExiting and restoring normal DNS settings...\033[0m")
		divert.Close()
		os.Exit(0)
	}()

	packetBuffer := make([]byte, 40+0xFFFF)
	var addr godivert.Address

	for {
		readLen, err := divert.Recv(packetBuffer, &addr)
		if err != nil {
			log.Printf("\033[31mRecv error: %v\033[0m", err)
			continue
		}

		packet := packetBuffer[:readLen]
		headers := godivert.ParsePacket(packet)
		if headers == nil || headers.UDP == nil || len(headers.Payload) == 0 {
			// Not a valid UDP packet or empty payload, forward as-is
			_, _ = divert.Send(packet, &addr)
			continue
		}

		dnsPayload := headers.Payload
		txID, qName, qType, qEnd, err := parseDNSQuery(dnsPayload)
		if err != nil {
			// DNS parse error, forward as-is
			_, _ = divert.Send(packet, &addr)
			continue
		}

		qTypeStr := dnsTypeToString(qType)

		// Check blocklist
		shouldBlock := false
		for _, kw := range blocklistKeywords {
			if strings.Contains(strings.ToLower(qName), kw) {
				shouldBlock = true
				break
			}
		}

		if shouldBlock {
			// BLOCK & SPOOF!
			fmt.Printf("\033[31m[BLOCK] [%-4s] %-35s -> Spoofing to local IP (ID: 0x%04X)\033[0m\n", qTypeStr, qName, txID)

			spoofedPayload := buildSpoofedDNSPayload(dnsPayload, txID, qType, qEnd)
			if len(spoofedPayload) == 0 {
				// Fallback to dropping the packet
				continue
			}

			// Construct the final spoofed packet with IP and UDP headers
			var iphLen int
			if headers.IP != nil {
				iphLen = int(headers.IP.VerLen&0x0F) * 4
			} else if headers.IPv6 != nil {
				iphLen = 40
			} else {
				continue
			}

			spoofedPacket := make([]byte, iphLen+8+len(spoofedPayload))
			copy(spoofedPacket[:iphLen+8], packet[:iphLen+8]) // Copy original headers
			copy(spoofedPacket[iphLen+8:], spoofedPayload)    // Copy spoofed DNS payload

			newHeaders := godivert.ParsePacket(spoofedPacket)
			if newHeaders == nil || newHeaders.UDP == nil {
				continue
			}

			// Swap IP addresses
			if newHeaders.IP != nil {
				newHeaders.IP.SrcAddr, newHeaders.IP.DstAddr = newHeaders.IP.DstAddr, newHeaders.IP.SrcAddr
				newHeaders.IP.Length = htons(uint16(len(spoofedPacket)))
			} else if newHeaders.IPv6 != nil {
				newHeaders.IPv6.SrcAddr, newHeaders.IPv6.DstAddr = newHeaders.IPv6.DstAddr, newHeaders.IPv6.SrcAddr
				newHeaders.IPv6.Length = htons(uint16(8 + len(spoofedPayload)))
			}

			// Swap UDP ports
			newHeaders.UDP.SrcPort, newHeaders.UDP.DstPort = newHeaders.UDP.DstPort, newHeaders.UDP.SrcPort
			newHeaders.UDP.Length = htons(uint16(8 + len(spoofedPayload)))

			// Set packet direction to inbound and recalculate checksums
			addr.SetOutbound(false)
			godivert.CalcChecksums(spoofedPacket, 0)

			// Send the spoofed packet back to the network stack
			_, err = divert.Send(spoofedPacket, &addr)
			if err != nil {
				log.Printf("\033[31mError sending spoofed packet: %v\033[0m", err)
			}
		} else {
			// ALLOW & FORWARD
			fmt.Printf("\033[32m[ALLOW] [%-4s] %-35s -> Forwarded (ID: 0x%04X)\033[0m\n", qTypeStr, qName, txID)
			_, _ = divert.Send(packet, &addr)
		}
	}
}

// htons converts a uint16 from host byte order to network byte order.
func htons(val uint16) uint16 {
	return (val << 8) | (val >> 8)
}

// parseDNSQuery parses Transaction ID, Question Name, Question Type, and Question End offset from a DNS payload.
func parseDNSQuery(payload []byte) (uint16, string, uint16, int, error) {
	if len(payload) < 12 {
		return 0, "", 0, 0, fmt.Errorf("payload too short")
	}

	txID := binary.BigEndian.Uint16(payload[0:2])
	flags := binary.BigEndian.Uint16(payload[2:4])
	qdCount := binary.BigEndian.Uint16(payload[4:6])

	isQuery := (flags & 0x8000) == 0
	if !isQuery || qdCount == 0 {
		return 0, "", 0, 0, fmt.Errorf("not a query or zero questions")
	}

	// Parse first question name
	qName, qEnd, err := parseDNSName(payload, 12)
	if err != nil {
		return 0, "", 0, 0, err
	}

	if qEnd+4 > len(payload) {
		return 0, "", 0, 0, fmt.Errorf("payload truncated in question block")
	}

	qType := binary.BigEndian.Uint16(payload[qEnd : qEnd+2])
	return txID, qName, qType, qEnd + 4, nil
}

// parseDNSName parses the DNS label-encoded domain name.
func parseDNSName(payload []byte, offset int) (string, int, error) {
	var parts []string
	curr := offset

	for {
		if curr >= len(payload) {
			return "", 0, fmt.Errorf("out of bounds parsing DNS name")
		}

		length := int(payload[curr])
		if length == 0 {
			curr++
			break
		}

		// Check for compression pointer (starts with 11xxxxxx in binary)
		if length >= 192 {
			if curr+1 >= len(payload) {
				return "", 0, fmt.Errorf("out of bounds compression pointer")
			}
			ptrOffset := int(binary.BigEndian.Uint16(payload[curr:curr+2]) & 0x3FFF)
			refName, _, err := parseDNSName(payload, ptrOffset)
			if err != nil {
				return "", 0, err
			}
			if len(parts) > 0 {
				return strings.Join(parts, ".") + "." + refName, curr + 2, nil
			}
			return refName, curr + 2, nil
		}

		curr++
		if curr+length > len(payload) {
			return "", 0, fmt.Errorf("out of bounds label")
		}

		parts = append(parts, string(payload[curr:curr+length]))
		curr += length
	}

	return strings.Join(parts, "."), curr, nil
}

// buildSpoofedDNSPayload constructs a DNS response payload.
func buildSpoofedDNSPayload(request []byte, txID uint16, qType uint16, qEnd int) []byte {
	// Create response payload buffer by copying the original request question block
	payload := make([]byte, qEnd)
	copy(payload, request[:qEnd])

	// Modify Header
	// Flags: 0x8180 (Standard Query Response, Recursion Desired, Recursion Available, No Error)
	binary.BigEndian.PutUint16(payload[2:4], 0x8180)
	// ANCOUNT: 1 (1 Answer)
	binary.BigEndian.PutUint16(payload[6:8], 1)
	// NSCOUNT: 0, ARCOUNT: 0
	binary.BigEndian.PutUint16(payload[8:10], 0)
	binary.BigEndian.PutUint16(payload[10:12], 0)

	// Append Answer Record
	answer := []byte{}

	// Name: Pointer to the question domain at offset 12 (0xC00C)
	answer = append(answer, 0xC0, 0x0C)

	// Type (2 bytes)
	tBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(tBytes, qType)
	answer = append(answer, tBytes...)

	// Class: IN (0x0001)
	answer = append(answer, 0x00, 0x01)

	// TTL: 60 seconds (0x0000003C)
	answer = append(answer, 0x00, 0x00, 0x00, 0x3C)

	// RDLENGTH & RDATA
	if qType == 1 { // A Record (IPv4)
		answer = append(answer, 0x00, 0x04)   // RDLENGTH = 4
		answer = append(answer, 127, 0, 0, 1) // RDATA = 127.0.0.1
	} else if qType == 28 { // AAAA Record (IPv6)
		answer = append(answer, 0x00, 0x16) // RDLENGTH = 16
		// RDATA = :: (16 bytes of 0)
		answer = append(answer, make([]byte, 16)...)
	} else {
		// For other types, return Name Error (RCODE: 3, Flags: 0x8183, ANCOUNT: 0)
		binary.BigEndian.PutUint16(payload[2:4], 0x8183)
		binary.BigEndian.PutUint16(payload[6:8], 0)
		return payload
	}

	return append(payload, answer...)
}

func dnsTypeToString(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	default:
		return fmt.Sprintf("TYPE:%d", t)
	}
}

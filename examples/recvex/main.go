package main

import (
	"log"
	"runtime"

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
	packet := make([]byte, 2000*10)
	var addr = make([]godivert.Address, 10)

	runtime.LockOSThread()

	for i := 0; ; i++ {
		nBytes, nAddresses, err := divert.RecvEx(packet, addr)
		if err != nil {
			log.Printf("Failed to receive packet: %v", err)
			continue
		}

		log.Printf("Received %d packets", nAddresses)

		_, err = divert.SendEx(packet[:nBytes], addr[:nAddresses])
		if err != nil {
			log.Printf("Failed to send packet: %v", err)
		}

	}
}

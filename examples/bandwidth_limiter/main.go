package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/one-api/godivert"
)

// ScheduledPacket represents a packet scheduled for transmission.
type ScheduledPacket struct {
	data     []byte
	addr     godivert.Address
	sendTime time.Time
}

func main() {
	// Parse CLI arguments
	latencyMs := flag.Int("latency", 0, "Artificial latency to inject in milliseconds (e.g., 100)")
	lossPercent := flag.Float64("loss", 0.0, "Packet loss probability in percent (e.g., 5.0 for 5%)")
	bandwidthKb := flag.Float64("bandwidth", 0.0, "Bandwidth limit in KB/s (e.g., 100.0 for 100KB/s). 0 means unlimited")
	filterFlag := flag.String("filter", "!loopback and (tcp or udp)", "WinDivert filter string")
	flag.Parse()

	// Title Banner
	fmt.Println("\033[35m===================================================\033[0m")
	fmt.Println("\033[35m⚡ GoDivert Network Bandwidth Limiter & Latency Shaper ⚡\033[0m")
	fmt.Println("\033[35m===================================================\033[0m")
	fmt.Printf("Filter   : %s\n", *filterFlag)
	if *latencyMs > 0 {
		fmt.Printf("Latency  : \033[33m%d ms\033[0m\n", *latencyMs)
	} else {
		fmt.Println("Latency  : Disabled")
	}
	if *lossPercent > 0 {
		fmt.Printf("Loss     : \033[31m%.2f%%\033[0m\n", *lossPercent)
	} else {
		fmt.Println("Loss     : Disabled")
	}
	if *bandwidthKb > 0 {
		fmt.Printf("Bandwidth: \033[32m%.2f KB/s\033[0m\n", *bandwidthKb)
	} else {
		fmt.Println("Bandwidth: Unlimited")
	}
	fmt.Println("\033[35m---------------------------------------------------\033[0m")
	fmt.Println("Starting GoDivert driver. Please make sure you are running as Administrator...")

	// Lock OS Thread for driver interaction
	runtime.LockOSThread()

	// Initialize GoDivert
	divert, err := godivert.New(*filterFlag, godivert.LayerNetwork, 0, 0)
	if err != nil {
		log.Fatalf("\033[31mError opening GoDivert driver: %v\033[0m\n(Hint: Are you running as Administrator?)", err)
	}
	defer divert.Close()

	// Seed random number generator
	rand.Seed(time.Now().UnixNano())

	// Channel to pass packets to the scheduler
	packetQueue := make(chan ScheduledPacket, 50000)

	// Mutext to protect divert.Send calls
	var sendMutex sync.Mutex

	// Monitor stats
	var totalPackets, sentPackets, droppedPackets uint64
	var totalBytes uint64

	// Start the Background Scheduler Loop
	// Because of our scheduling algorithm, sendTime is strictly monotonic,
	// so a FIFO channel is perfectly ordered.
	go func() {
		for p := range packetQueue {
			now := time.Now()
			if p.sendTime.After(now) {
				time.Sleep(p.sendTime.Sub(now))
			}

			sendMutex.Lock()
			_, err := divert.Send(p.data, &p.addr)
			sendMutex.Unlock()

			if err != nil {
				log.Printf("\033[31mError injecting packet: %v\033[0m", err)
			} else {
				sentPackets++
			}
		}
	}()

	// Background ticker to print stats
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			fmt.Printf("\033[34m[STATS] Captured: %5d | Transmitted: %5d | Dropped: %5d | Bytes: %d KB\033[0m\n",
				totalPackets, sentPackets, droppedPackets, totalBytes/1024)
		}
	}()

	// Signal handling for clean exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n\033[33mExiting and restoring normal network operations...\033[0m")
		divert.Close()
		os.Exit(0)
	}()

	// Packet buffer
	packetBuffer := make([]byte, 40+0xFFFF)
	var addr godivert.Address

	// Virtual clock for bandwidth throttling
	var nextAvailableTime time.Time = time.Now()
	bandwidthLimitBytesPerSec := *bandwidthKb * 1024.0

	// Main packet forwarding and scheduling loop
	for {
		readLen, err := divert.Recv(packetBuffer, &addr)
		if err != nil {
			log.Printf("\033[31mRecv error: %v\033[0m", err)
			continue
		}

		totalPackets++
		totalBytes += uint64(readLen)

		// 1. Packet Loss Simulation
		if *lossPercent > 0 {
			if rand.Float64()*100.0 < *lossPercent {
				droppedPackets++
				// Simply drop the packet by not sending it
				continue
			}
		}

		// 2. Base Scheduled Time (Latency Injection)
		sendTime := time.Now()
		if *latencyMs > 0 {
			sendTime = sendTime.Add(time.Duration(*latencyMs) * time.Millisecond)
		}

		// 3. Rate Limiting Throttling (Virtual Clock Scheduling)
		if bandwidthLimitBytesPerSec > 0 {
			now := time.Now()
			if now.After(nextAvailableTime) {
				nextAvailableTime = now
			}

			// Assign the packet its virtual transmission time
			if sendTime.Before(nextAvailableTime) {
				sendTime = nextAvailableTime
			}

			// Calculate transmission duration for this packet size: duration = size / rate
			packetDuration := time.Duration(float64(readLen) / bandwidthLimitBytesPerSec * float64(time.Second))
			nextAvailableTime = sendTime.Add(packetDuration)
		}

		// Deep copy packet payload (crucial because packetBuffer gets overwritten in the next loop)
		packetCopy := make([]byte, readLen)
		copy(packetCopy, packetBuffer[:readLen])

		// Queue the packet into our background sender
		select {
		case packetQueue <- ScheduledPacket{data: packetCopy, addr: addr, sendTime: sendTime}:
		default:
			// Buffer overflow, drop packet to prevent blocking
			droppedPackets++
		}
	}
}

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/one-api/godivert"
	"github.com/one-api/godivert/types"
)

// FlowRecord represents an active network connection.
type FlowRecord struct {
	PID         uint32
	ProcessName string
	Protocol    string
	LocalIP     string
	LocalPort   uint16
	RemoteIP    string
	RemotePort  uint16
	Outbound    bool
	StartTime   time.Time
}

var (
	activeFlows = make(map[uint64]FlowRecord)
	flowsMutex  sync.Mutex
)

func main() {
	// Setup terminal clean-up on exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Lock OS thread for driver interaction
	runtime.LockOSThread()

	// Capture all flow established/deleted events.
	// We use "true" filter to listen to all events in this layer.
	divert, err := godivert.New("true", godivert.LayerFlow, 0, 0)
	if err != nil {
		log.Fatalf("\033[31mError opening GoDivert driver: %v\033[0m\n", err)
	}
	defer divert.Close()

	go func() {
		<-sigChan
		divert.Close()
		fmt.Print("\033[?25h") // Restore cursor visibility
		fmt.Println("\n\033[33mFlow monitor stopped.\033[0m")
		os.Exit(0)
	}()

	// Hide cursor for a clean terminal dashboard experience
	fmt.Print("\033[?25l")

	// Start the drawing loop in a background goroutine
	go drawDashboardLoop()

	packetBuffer := make([]byte, 2048)
	var addr godivert.Address

	for {
		_, err := divert.Recv(packetBuffer, &addr)
		if err != nil {
			log.Printf("Recv error: %v", err)
			continue
		}

		flowData := addr.Flow()
		if flowData == nil {
			continue
		}

		endpointID := flowData.EndpointId

		flowsMutex.Lock()
		if addr.Event == uint8(types.EventFlowEstablished) {
			// Established flow
			var localIP, remoteIP string
			if addr.IPv6() {
				localIP = ip6ToString(flowData.LocalAddr)
				remoteIP = ip6ToString(flowData.RemoteAddr)
			} else {
				localIP = ip4ToString(flowData.LocalAddr[0])
				remoteIP = ip4ToString(flowData.RemoteAddr[0])
			}

			protoStr := "TCP"
			if flowData.Protocol == 17 {
				protoStr = "UDP"
			} else if flowData.Protocol == 1 {
				protoStr = "ICMP"
			}

			procName := getProcessName(flowData.ProcessId)

			activeFlows[endpointID] = FlowRecord{
				PID:         flowData.ProcessId,
				ProcessName: procName,
				Protocol:    protoStr,
				LocalIP:     localIP,
				LocalPort:   flowData.LocalPort,
				RemoteIP:    remoteIP,
				RemotePort:  flowData.RemotePort,
				Outbound:    addr.Outbound(),
				StartTime:   time.Now(),
			}
		} else if addr.Event == uint8(types.EventFlowDeleted) {
			// Flow deleted
			delete(activeFlows, endpointID)
		}
		flowsMutex.Unlock()
	}
}

// ip4ToString converts a uint32 IPv4 address (Big Endian) to string.
func ip4ToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip),
	)
}

// ip6ToString converts a [4]uint32 IPv6 address to string.
func ip6ToString(ip [4]uint32) string {
	var buf [16]byte
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(buf[i*4:(i+1)*4], ip[i])
	}
	return net.IP(buf[:]).String()
}

// getProcessName resolves PID to its executable name on Windows.
func getProcessName(pid uint32) string {
	if pid == 0 {
		return "System (Idle)"
	}
	if pid == 4 {
		return "System"
	}

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "unknown"
	}
	defer windows.CloseHandle(h)

	var size uint32 = 1024
	buf := make([]uint16, size)
	err = windows.QueryFullProcessImageName(h, 0, &buf[0], &size)
	if err != nil {
		return "unknown"
	}

	path := syscall.UTF16ToString(buf[:size])
	// Extract base name
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' || path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

// drawDashboardLoop clears the screen and redraws the flows table.
func drawDashboardLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		flowsMutex.Lock()
		// Copy flow records so we can sort them and release the lock quickly
		var sortedRecords []FlowRecord
		for _, record := range activeFlows {
			sortedRecords = append(sortedRecords, record)
		}
		flowsMutex.Unlock()

		// Sort by ProcessName, then Protocol
		sort.Slice(sortedRecords, func(i, j int) bool {
			if sortedRecords[i].ProcessName != sortedRecords[j].ProcessName {
				return sortedRecords[i].ProcessName < sortedRecords[j].ProcessName
			}
			return sortedRecords[i].Protocol < sortedRecords[j].Protocol
		})

		// Clear screen and reset cursor
		fmt.Print("\033[H\033[2J")

		// Header
		fmt.Println("\033[33m=========================================================================================\033[0m")
		fmt.Println("\033[33m🚀  GoDivert Live Process Connection & Traffic Flow Monitor  🚀\033[0m")
		fmt.Printf("Active Connections: \033[32m%d\033[0m | Local Time: %s\n", len(sortedRecords), time.Now().Format("15:04:05"))
		fmt.Println("\033[33m=========================================================================================\033[0m")

		// Table Header
		fmt.Printf("\033[1m%-6s %-20s %-5s %-22s %-22s %-8s %-7s\033[0m\n",
			"PID", "PROCESS", "PROTO", "LOCAL ENDPOINT", "REMOTE ENDPOINT", "DIR", "ELAPSED")
		fmt.Println("-----------------------------------------------------------------------------------------")

		// Table Rows (limit to top 25 to fit nicely in terminal)
		maxRows := 25
		if len(sortedRecords) < maxRows {
			maxRows = len(sortedRecords)
		}

		for i := 0; i < maxRows; i++ {
			r := sortedRecords[i]
			elapsed := time.Since(r.StartTime).Round(time.Second)

			localEp := fmt.Sprintf("%s:%d", r.LocalIP, r.LocalPort)
			remoteEp := fmt.Sprintf("%s:%d", r.RemoteIP, r.RemotePort)

			dirStr := "\033[32mINBOUND\033[0m"
			if r.Outbound {
				dirStr = "\033[34mOUTBOUND\033[0m"
			}

			procColor := "\033[37m" // Default white
			if r.ProcessName == "System" || r.ProcessName == "System (Idle)" {
				procColor = "\033[90m" // Dark gray
			} else if r.ProcessName != "unknown" {
				procColor = "\033[36m" // Cyan for active user apps
			}

			fmt.Printf("%-6d %s%-20s\033[0m %-5s %-22s %-22s %-17s %-7s\n",
				r.PID, procColor, truncateString(r.ProcessName, 20), r.Protocol,
				truncateString(localEp, 22), truncateString(remoteEp, 22), dirStr, elapsed)
		}

		if len(sortedRecords) > maxRows {
			fmt.Printf("\n\033[90m... and %d more active connections\033[0m\n", len(sortedRecords)-maxRows)
		}

		fmt.Println("\nPress \033[33mCtrl+C\033[0m to exit.")
	}
}

func truncateString(s string, l int) string {
	if len(s) > l {
		return s[:l-3] + "..."
	}
	return s
}

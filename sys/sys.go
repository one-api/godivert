package sys

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

//go:embed WinDivert32.sys
var sysFile32 []byte

//go:embed WinDivert64.sys
var sysFile64 []byte

const (
	// DefaultDriverName is the default name for the WinDivert driver.
	DefaultDriverName = "WinDivert"
	// DefaultInstallMutexName is the name of the global mutex used to synchronize driver installation.
	DefaultInstallMutexName = "WinDivertDriverInstallMutex"
)

// LoadEmbedSysFile extracts the embedded driver and loads it into the system.
func LoadEmbedSysFile() error {
	var sysFile []byte
	var sysFileName string

	switch runtime.GOARCH {
	case "amd64":
		sysFile = sysFile64
		sysFileName = "WinDivert64.sys"
	case "386":
		sysFile = sysFile32
		sysFileName = "WinDivert32.sys"
	default:
		return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	if len(sysFile) == 0 {
		return fmt.Errorf("embedded driver file is empty or not found for architecture %s", runtime.GOARCH)
	}

	// Extract to a temporary directory
	tmpDir := filepath.Join(os.TempDir(), "godivert")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	driverPath := filepath.Join(tmpDir, sysFileName)

	// Always write the file to ensure it exists.
	// Ignore error if file is locked (e.g. driver running).
	if err := os.WriteFile(driverPath, sysFile, 0644); err != nil {
		// If error is not "access denied" (which happens if driver is running), return error.
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			// On Windows, sharing violation or access denied usually means it's in use.
			// We can ignore those, but others should be reported.
		}
	}

	return LoadDriver(DefaultDriverName, driverPath, DefaultInstallMutexName)
}

// LoadDriver installs and starts driver.
func LoadDriver(driverName, sysPath, mutexName string) error {
	// Mutex to synchronize installation
	mutexNameUTF16, err := syscall.UTF16PtrFromString(mutexName)
	if err != nil {
		return fmt.Errorf("convert mutex name: %w", err)
	}
	mutex, err := windows.CreateMutex(nil, false, mutexNameUTF16)
	if err != nil {
		return fmt.Errorf("create mutex: %w", err)
	}
	defer windows.CloseHandle(mutex)

	event, err := windows.WaitForSingleObject(mutex, windows.INFINITE)
	if err != nil {
		return fmt.Errorf("failed to wait for mutex: %w", err)
	}
	if event == windows.WAIT_FAILED {
		return fmt.Errorf("wait for mutex failed: %w", windows.GetLastError())
	}
	defer windows.ReleaseMutex(mutex)

	// Connect to Service Manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Try to open service
	s, err := m.OpenService(driverName)
	if err != nil {
		// Service doesn't exist, create it
		s, err = m.CreateService(driverName, sysPath,
			mgr.Config{
				DisplayName:  driverName,
				StartType:    windows.SERVICE_DEMAND_START,
				ServiceType:  windows.SERVICE_KERNEL_DRIVER,
				ErrorControl: mgr.ErrorNormal,
			})
		if err != nil {
			if errors.Is(err, windows.ERROR_SERVICE_EXISTS) {
				// Race condition? Try open again
				s, err = m.OpenService(driverName)
				if err != nil {
					return fmt.Errorf("open existing service: %w", err)
				}
			} else {
				return fmt.Errorf("create service: %w", err)
			}
		}
	}
	defer s.Close()

	// Register Event Source
	registerEventSource(sysPath)

	// Start service
	err = s.Start()
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			// Already running, fine.
		} else {
			// Check if disabled
			config, cfgErr := s.Config()
			if cfgErr == nil && config.StartType == windows.SERVICE_DISABLED {
				config.StartType = windows.SERVICE_DEMAND_START
				s.UpdateConfig(config)
			}

			// Try to stop first if there's a problem (e.g. pending stop, or weird state)
			// Ignore error from Stop as it might not be running.
			s.Control(svc.Stop)

			// Retry Start
			err = s.Start()
			if err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
				return fmt.Errorf("failed to start service: %w", err)
			}
		}
	}

	// Mark for deletion
	_ = s.Delete()

	return nil
}

// no error need raised if fail
func registerEventSource(sysPath string) {
	keyPath := `System\CurrentControlSet\Services\EventLog\System\WinDivert`
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()

	k.SetStringValue("EventMessageFile", sysPath)
	k.SetDWordValue("TypesSupported", 7)
}

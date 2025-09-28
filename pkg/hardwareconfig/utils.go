package hardwareconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/glog"

	dpll "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/dpll-netlink"
)

// DpllPinsGetter is a function type for getting DPLL pins
type DpllPinsGetter func() (*PinCache, error)

// defaultDpllPinsGetter is the default implementation that connects to real DPLL
var defaultDpllPinsGetter DpllPinsGetter = getRealDpllPins

// dpllPinsGetter holds the current implementation (can be swapped for testing)
var dpllPinsGetter DpllPinsGetter = defaultDpllPinsGetter

// SetDpllPinsGetter allows tests to inject a mock implementation
func SetDpllPinsGetter(getter DpllPinsGetter) {
	dpllPinsGetter = getter
}

// ResetDpllPinsGetter resets to the default implementation
func ResetDpllPinsGetter() {
	dpllPinsGetter = defaultDpllPinsGetter
}

// GetDpllPins returns the DPLL pin cache using the current getter implementation
func GetDpllPins() (*PinCache, error) {
	return dpllPinsGetter()
}

// PinCache is a cache of DPLL pins with O1 access, hashed by clock ID and board label
type PinCache struct {
	Pins map[uint64]map[string]dpll.PinInfo
}

// Count returns the total number of pins in the cache
func (pc *PinCache) Count() int {
	count := 0
	for _, clockPins := range pc.Pins {
		count += len(clockPins)
	}
	return count
}

// GetPin returns the pin info for a specific clock ID and board label
func (pc *PinCache) GetPin(clockID uint64, boardLabel string) (*dpll.PinInfo, bool) {
	if clockPins, exists := pc.Pins[clockID]; exists {
		if pinInfo, exists := clockPins[boardLabel]; exists {
			return &pinInfo, true
		}
	}
	glog.Infof("Pin cache miss: clockID=%#x boardLabel=%s", clockID, boardLabel)
	return nil, false
}

// getRealDpllPins connects to the real DPLL and returns the DPLL pin cache
func getRealDpllPins() (*PinCache, error) {
	conn, err := dpll.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to dial DPLL: %v", err)
	}
	//nolint:errcheck
	defer conn.Close()
	dpllPins, err := conn.DumpPinGet()
	if err != nil {
		return nil, fmt.Errorf("failed to dump DPLL pins: %v", err)
	}
	return buildPinCacheFromPins(dpllPins), nil
}

// CreateMockDpllPinsGetter creates a DpllPinsGetter function that returns mock pins
func CreateMockDpllPinsGetter(pins []*dpll.PinInfo, returnError error) DpllPinsGetter {
	return func() (*PinCache, error) {
		if returnError != nil {
			return nil, returnError
		}
		return buildPinCacheFromPins(pins), nil
	}
}

func buildPinCacheFromPins(pins []*dpll.PinInfo) *PinCache {
	cache := &PinCache{
		Pins: make(map[uint64]map[string]dpll.PinInfo),
	}
	for _, pin := range pins {
		if pin == nil {
			continue
		}
		if pin.BoardLabel == "" {
			continue
		}
		if cache.Pins[pin.ClockID] == nil {
			cache.Pins[pin.ClockID] = make(map[string]dpll.PinInfo)
		}
		cache.Pins[pin.ClockID][pin.BoardLabel] = *pin
		glog.Infof("Pin cache add: clock=%#x boardLabel=%s id=%d", pin.ClockID, pin.BoardLabel, pin.ID)
	}
	return cache
}

type PinParentControl struct {
	EecPriority    uint8
	PpsPriority    uint8
	EecOutputState uint8
	PpsOutputState uint8
}
type PinControl struct {
	Label         string
	ParentControl PinParentControl
}

// GetPinState returns DPLL pin state as a string
func GetPinStateUint32(s string) (uint32, error) {
	stateMap := map[string]uint32{
		"connected":    dpll.PinStateConnected,
		"disconnected": dpll.PinStateDisconnected,
		"selectable":   dpll.PinStateSelectable,
	}
	r, found := stateMap[s]
	if found {
		return r, nil
	}
	return 0, fmt.Errorf("invalid pin state: %s", s)
}

func BatchPinSet(commands *[]dpll.PinParentDeviceCtl) error {
	conn, err := dpll.Dial(nil)
	if err != nil {
		return fmt.Errorf("failed to dial DPLL: %v", err)
	}
	//nolint:errcheck
	defer conn.Close()
	for _, command := range *commands {
		glog.Infof("DPLL pin command %++v", command)
		b, err := dpll.EncodePinControl(command)
		if err != nil {
			return err
		}
		err = conn.SendCommand(dpll.DpllCmdPinSet, b)
		if err != nil {
			glog.Error("failed to send pin command: ", err)
			return err
		}
		info, err := conn.DoPinGet(dpll.DoPinGetRequest{ID: command.ID})
		if err != nil {
			glog.Error("failed to get pin: ", err)
			return err
		}
		reply, err := dpll.GetPinInfoHR(info, time.Now())
		if err != nil {
			glog.Error("failed to convert pin reply to human readable: ", err)
			return err
		}
		glog.Info("pin reply: ", string(reply))
	}
	return nil
}

// SetupMockDpllPinsForTests sets up mock DPLL pins for daemon tests using simple test data
func SetupMockDpllPinsForTests() error {
	// Create simple mock data for tests that don't need real pin data
	// Include all board labels used in triple-t-bc-wpc.yaml
	mockPins := []*dpll.PinInfo{
		{
			ID:           0,
			ClockID:      0x507c6fffff5c4ae8,
			BoardLabel:   "CVL-SDP22",
			ModuleName:   "ice",
			Type:         4, // int-oscillator
			Frequency:    1,
			Capabilities: 6, // state-can-change,priority-can-change
			ParentDevice: []dpll.PinParentDevice{
				{ParentID: 0, Direction: dpll.PinDirectionInput, Prio: 255, State: dpll.PinStateSelectable},
			},
		},
		{
			ID:           6,
			ClockID:      0x507c6fffff5c4ae8,
			BoardLabel:   "GNSS-1PPS",
			ModuleName:   "ice",
			Type:         5, // gnss
			Frequency:    1,
			Capabilities: 6, // state-can-change,priority-can-change
			ParentDevice: []dpll.PinParentDevice{
				{ParentID: 0, Direction: dpll.PinDirectionInput, Prio: 255, State: dpll.PinStateSelectable},
			},
		},
		// Add pins for Leader clock ID (0x507c6fffff1fb1b8)
		{
			ID:           10,
			ClockID:      0x507c6fffff1fb1b8,
			BoardLabel:   "CVL-SDP20",
			ModuleName:   "ice",
			Type:         4, // int-oscillator
			Frequency:    1,
			Capabilities: 6, // state-can-change,priority-can-change
			ParentDevice: []dpll.PinParentDevice{
				{ParentID: 2, Direction: dpll.PinDirectionInput, Prio: 255, State: dpll.PinStateSelectable},
			},
		},
		{
			ID:           11,
			ClockID:      0x507c6fffff1fb1b8,
			BoardLabel:   "CVL-SDP21",
			ModuleName:   "ice",
			Type:         2, // ext
			Frequency:    1,
			Capabilities: 6, // state-can-change,priority-can-change
			ParentDevice: []dpll.PinParentDevice{
				{ParentID: 2, Direction: dpll.PinDirectionOutput, Prio: 0, State: dpll.PinStateConnected},
			},
		},
		{
			ID:           12,
			ClockID:      0x507c6fffff1fb1b8,
			BoardLabel:   "CVL-SDP22",
			ModuleName:   "ice",
			Type:         4, // int-oscillator
			Frequency:    1,
			Capabilities: 6, // state-can-change,priority-can-change
			ParentDevice: []dpll.PinParentDevice{
				{ParentID: 2, Direction: dpll.PinDirectionInput, Prio: 255, State: dpll.PinStateSelectable},
			},
		},
		{
			ID:           13,
			ClockID:      0x507c6fffff1fb1b8,
			BoardLabel:   "CVL-SDP23",
			ModuleName:   "ice",
			Type:         2, // ext
			Frequency:    1,
			Capabilities: 6, // state-can-change,priority-can-change
			ParentDevice: []dpll.PinParentDevice{
				{ParentID: 2, Direction: dpll.PinDirectionOutput, Prio: 0, State: dpll.PinStateConnected},
			},
		},
		{
			ID:           14,
			ClockID:      0x507c6fffff1fb1b8,
			BoardLabel:   "GNSS-1PPS",
			ModuleName:   "ice",
			Type:         5, // gnss
			Frequency:    1,
			Capabilities: 6, // state-can-change,priority-can-change
			ParentDevice: []dpll.PinParentDevice{
				{ParentID: 2, Direction: dpll.PinDirectionInput, Prio: 255, State: dpll.PinStateSelectable},
			},
		},
		// Add pins for Follower clock ID (0x507c6fffff1fb580)
		{
			ID:           20,
			ClockID:      0x507c6fffff1fb580,
			BoardLabel:   "GNSS-1PPS",
			ModuleName:   "ice",
			Type:         5, // gnss
			Frequency:    1,
			Capabilities: 6, // state-can-change,priority-can-change
			ParentDevice: []dpll.PinParentDevice{
				{ParentID: 4, Direction: dpll.PinDirectionInput, Prio: 255, State: dpll.PinStateSelectable},
			},
		},
	}
	mockGetter := CreateMockDpllPinsGetter(mockPins, nil)
	SetDpllPinsGetter(mockGetter)
	return nil
}

// SetupMockDpllPinsForTestsWithData sets up mock DPLL pins with custom data
func SetupMockDpllPinsForTestsWithData(pins []*dpll.PinInfo) {
	mockGetter := CreateMockDpllPinsGetter(pins, nil)
	SetDpllPinsGetter(mockGetter)
}

// SetupMockDpllPinsForTestsWithError sets up mock DPLL pins that returns an error
func SetupMockDpllPinsForTestsWithError(err error) {
	mockGetter := CreateMockDpllPinsGetter(nil, err)
	SetDpllPinsGetter(mockGetter)
}

func TeardownMockDpllPinsForTests() {
	ResetDpllPinsGetter()
}

// PtpDeviceResolver is a function type for resolving PTP device paths
type PtpDeviceResolver func(interfacePath string) ([]string, error)

// defaultResolveSysFSPtpDevice is the default implementation that reads from the real file system
func defaultResolveSysFSPtpDevice(interfacePath string) ([]string, error) {
	// If path doesn't contain "ptp*" placeholder, return as-is
	if !strings.Contains(interfacePath, "ptp*") {
		return []string{interfacePath}, nil
	}

	// Extract the directory path and filename
	pathParts := strings.Split(interfacePath, "ptp*")
	if len(pathParts) != 2 {
		return nil, fmt.Errorf("invalid ptp* pattern in path: %s", interfacePath)
	}

	ptpDir := filepath.Dir(pathParts[0] + "ptp0") // Use ptp0 as template to get the directory
	filename := pathParts[1]

	// Read the PTP devices directory
	entries, err := os.ReadDir(ptpDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read ptp devices directory %s: %w", ptpDir, err)
	}

	var resolvedPaths []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "ptp") {
			// Construct the full path
			fullPath := filepath.Join(ptpDir, entry.Name()) + filename

			// Check if the target file exists and is writable
			if info, statErr := os.Stat(fullPath); statErr == nil && !info.IsDir() {
				// Try to open the file for writing to check if it's writable
				if file, openErr := os.OpenFile(fullPath, os.O_WRONLY, 0); openErr == nil {
					file.Close()
					resolvedPaths = append(resolvedPaths, fullPath)
				}
			}
		}
	}

	if len(resolvedPaths) == 0 {
		return nil, fmt.Errorf("no writable files found for path %s", interfacePath)
	}

	return resolvedPaths, nil
}

// Global variables for PTP device resolution mocking
var (
	defaultPtpDeviceResolver PtpDeviceResolver = defaultResolveSysFSPtpDevice
	ptpDeviceResolver        PtpDeviceResolver = defaultPtpDeviceResolver
)

// SetPtpDeviceResolver allows injection of a mock PTP device resolver for testing
func SetPtpDeviceResolver(resolver PtpDeviceResolver) {
	ptpDeviceResolver = resolver
}

// ResetPtpDeviceResolver resets the PTP device resolver to the default implementation
func ResetPtpDeviceResolver() {
	ptpDeviceResolver = defaultPtpDeviceResolver
}

// CreateMockPtpDeviceResolver creates a mock PTP device resolver
func CreateMockPtpDeviceResolver(mockDevices map[string][]string, returnError error) PtpDeviceResolver {
	return func(interfacePath string) ([]string, error) {
		if returnError != nil {
			return nil, returnError
		}

		if devices, exists := mockDevices[interfacePath]; exists {
			return devices, nil
		}

		// If no specific mock is provided, try to extract a pattern and return mock devices
		if strings.Contains(interfacePath, "ptp*") {
			// Replace ptp* with mock devices
			var result []string
			for i := 0; i < 2; i++ { // Default to 2 mock devices
				mockPath := strings.Replace(interfacePath, "ptp*", fmt.Sprintf("ptp%d", i), 1)
				result = append(result, mockPath)
			}
			return result, nil
		}

		return []string{interfacePath}, nil
	}
}

// SetupMockPtpDeviceResolver sets up a default mock PTP device resolver for tests
func SetupMockPtpDeviceResolver() {
	mockDevices := make(map[string][]string)
	mockResolver := CreateMockPtpDeviceResolver(mockDevices, nil)
	SetPtpDeviceResolver(mockResolver)
}

// SetupMockPtpDeviceResolverWithDevices sets up a mock PTP device resolver with specific devices
func SetupMockPtpDeviceResolverWithDevices(mockDevices map[string][]string) {
	mockResolver := CreateMockPtpDeviceResolver(mockDevices, nil)
	SetPtpDeviceResolver(mockResolver)
}

// SetupMockPtpDeviceResolverWithError sets up a mock PTP device resolver that returns an error
func SetupMockPtpDeviceResolverWithError(err error) {
	mockResolver := CreateMockPtpDeviceResolver(nil, err)
	SetPtpDeviceResolver(mockResolver)
}

// TeardownMockPtpDeviceResolver resets the PTP device resolver to the default implementation
func TeardownMockPtpDeviceResolver() {
	ResetPtpDeviceResolver()
}

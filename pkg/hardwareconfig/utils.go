package hardwareconfig

import (
	"fmt"
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
	cache := &PinCache{
		Pins: make(map[uint64]map[string]dpll.PinInfo),
	}
	for _, pin := range dpllPins {
		if pin.BoardLabel == "" {
			continue
		}
		if cache.Pins[pin.ClockID] == nil {
			cache.Pins[pin.ClockID] = make(map[string]dpll.PinInfo)
		}
		cache.Pins[pin.ClockID][pin.BoardLabel] = *pin
	}
	return cache, nil
}

// CreateMockDpllPinsGetter creates a DpllPinsGetter function that returns mock pins
func CreateMockDpllPinsGetter(pins []*dpll.PinInfo, returnError error) DpllPinsGetter {
	return func() (*PinCache, error) {
		if returnError != nil {
			return nil, returnError
		}
		cache := &PinCache{
			Pins: make(map[uint64]map[string]dpll.PinInfo),
		}
		for _, pin := range pins {
			if pin.BoardLabel == "" {
				continue
			}
			if cache.Pins[pin.ClockID] == nil {
				cache.Pins[pin.ClockID] = make(map[string]dpll.PinInfo)
			}
			cache.Pins[pin.ClockID][pin.BoardLabel] = *pin
		}
		return cache, nil
	}
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
	mockPins := []*dpll.PinInfo{
		{
			ID:           0,
			ClockID:      0x507c6fffff5c4ae8,
			BoardLabel:   "CVL-SDP22",
			ModuleName:   "ice",
			Type:         4, // int-oscillator
			Frequency:    1,
			Capabilities: 6, // state-can-change,priority-can-change
		},
		{
			ID:           6,
			ClockID:      0x507c6fffff5c4ae8,
			BoardLabel:   "GNSS-1PPS",
			ModuleName:   "ice",
			Type:         5, // gnss
			Frequency:    1,
			Capabilities: 6, // state-can-change,priority-can-change
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

// TeardownMockDpllPinsForTests resets the DPLL pins getter to default
func TeardownMockDpllPinsForTests() {
	ResetDpllPinsGetter()
}

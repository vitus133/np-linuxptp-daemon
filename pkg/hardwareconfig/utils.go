package hardwareconfig

import (
	"fmt"

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
	Pins map[uint64]map[string][]dpll.PinParentDevice
}

// Count returns the total number of pins in the cache
func (pc *PinCache) Count() int {
	count := 0
	for _, clockPins := range pc.Pins {
		count += len(clockPins)
	}
	return count
}

// GetPin returns the parent devices for a specific clock ID and board label
func (pc *PinCache) GetPin(clockID uint64, boardLabel string) ([]dpll.PinParentDevice, bool) {
	if clockPins, exists := pc.Pins[clockID]; exists {
		if parentDevices, exists := clockPins[boardLabel]; exists {
			return parentDevices, true
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
		Pins: make(map[uint64]map[string][]dpll.PinParentDevice),
	}
	for _, pin := range dpllPins {
		if pin.BoardLabel == "" {
			continue
		}
		if cache.Pins[pin.ClockID] == nil {
			cache.Pins[pin.ClockID] = make(map[string][]dpll.PinParentDevice)
		}
		cache.Pins[pin.ClockID][pin.BoardLabel] = pin.ParentDevice
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
			Pins: make(map[uint64]map[string][]dpll.PinParentDevice),
		}
		for _, pin := range pins {
			if pin.BoardLabel == "" {
				continue
			}
			if cache.Pins[pin.ClockID] == nil {
				cache.Pins[pin.ClockID] = make(map[string][]dpll.PinParentDevice)
			}
			cache.Pins[pin.ClockID][pin.BoardLabel] = pin.ParentDevice
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

const (
	eecDpllIndex = 0
	ppsDpllIndex = 1
)

// func SetPinsControl(pins []PinControl) (*[]dpll.PinParentDeviceCtl, error) {
// 	pinCommands := []dpll.PinParentDeviceCtl{}
// 	for _, pinCtl := range pins {
// 		dpllPin, found := c.LeadingNIC.Pins[pinCtl.Label]
// 		if !found {
// 			return nil, fmt.Errorf("%s pin not found in the leading card", pinCtl.Label)
// 		}
// 		pinCommand := SetPinControlData(dpllPin, pinCtl.ParentControl)
// 		pinCommands = append(pinCommands, *pinCommand)
// 	}
// 	return &pinCommands, nil
// }

// func SetPinControlData(pin dpll.PinInfo, control PinParentControl) *dpll.PinParentDeviceCtl {
// 	Pin := dpll.PinParentDeviceCtl{
// 		ID:           pin.ID,
// 		PinParentCtl: make([]dpll.PinControl, 0),
// 	}

// 	for deviceIndex, parentDevice := range pin.ParentDevice {
// 		var prio uint32
// 		var outputState uint32
// 		pc := dpll.PinControl{}
// 		pc.PinParentID = parentDevice.ParentID
// 		switch deviceIndex {
// 		case eecDpllIndex:
// 			prio = uint32(control.EecPriority)
// 			outputState = uint32(control.EecOutputState)
// 		case ppsDpllIndex:
// 			prio = uint32(control.PpsPriority)
// 			outputState = uint32(control.PpsOutputState)
// 		}
// 		if parentDevice.Direction == dpll.PinDirectionInput {
// 			pc.Prio = &prio
// 		} else {
// 			pc.State = &outputState
// 		}
// 		Pin.PinParentCtl = append(Pin.PinParentCtl, pc)
// 	}
// 	return &Pin
// }

// SetupMockDpllPinsForTests sets up mock DPLL pins for daemon tests using test file data
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

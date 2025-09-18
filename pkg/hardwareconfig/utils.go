package hardwareconfig

import (
	"fmt"

	dpll "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/dpll-netlink"
)

// DpllPinsGetter is a function type for getting DPLL pins
type DpllPinsGetter func() ([]*dpll.PinInfo, error)

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

// GetDpllPins returns the list of DPLL pins using the current getter implementation
func GetDpllPins() ([]*dpll.PinInfo, error) {
	return dpllPinsGetter()
}

// getRealDpllPins is the original implementation that connects to real DPLL
func getRealDpllPins() ([]*dpll.PinInfo, error) {
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

	return dpllPins, nil
}

// CreateMockDpllPinsGetter creates a DpllPinsGetter function that returns mock pins
func CreateMockDpllPinsGetter(pins []*dpll.PinInfo, returnError error) DpllPinsGetter {
	return func() ([]*dpll.PinInfo, error) {
		if returnError != nil {
			return nil, returnError
		}
		return pins, nil
	}
}

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

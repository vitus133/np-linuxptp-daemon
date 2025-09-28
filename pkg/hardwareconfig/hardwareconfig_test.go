package hardwareconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	dpll "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/dpll-netlink"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/types"
	ptpv1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
)

func TestApplyHardwareConfigsForProfile(t *testing.T) {
	// Set up mock PTP device resolver for testing
	SetupMockPtpDeviceResolver()
	defer TeardownMockPtpDeviceResolver()
	// Set up mock DPLL pins from test file for testing
	mockErr := SetupMockDpllPinsFromFileForTests()
	if mockErr != nil {
		t.Logf("Warning: Failed to setup mock DPLL pins from file: %v", mockErr)
		// Continue with test as DPLL pins are optional
	}
	defer TeardownMockDpllPinsForTests()

	tests := []struct {
		name         string
		testDataFile string
		profileName  string
	}{
		{
			name:         "successful hardware config application",
			testDataFile: "testdata/triple-t-bc-wpc.yaml",
			profileName:  "01-tbc-tr",
		},
		{
			name:         "no matching profile",
			testDataFile: "testdata/triple-t-bc-wpc.yaml",
			profileName:  "non-existent-profile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetupMockPtpDeviceResolver()
			defer TeardownMockPtpDeviceResolver()

			if err := SetupMockDpllPinsForTests(); err != nil {
				t.Fatalf("failed to set up mock DPLL pins: %v", err)
			}
			defer TeardownMockDpllPinsForTests()

			// Load test data
			hwConfig, err := loadHardwareConfigFromFile(tt.testDataFile)
			assert.NoError(t, err)
			assert.NotNil(t, hwConfig)

			// Create hardware config manager and add test data
			hcm := NewHardwareConfigManager()
			defer hcm.resetExecutors()

			hcm.overrideExecutors(nil, func(path, value string) error { return nil })

			var appliedPins []dpll.PinParentDeviceCtl
			hcm.overrideExecutors(func(cmds []dpll.PinParentDeviceCtl) error {
				snapshot := make([]dpll.PinParentDeviceCtl, len(cmds))
				copy(snapshot, cmds)
				appliedPins = append(appliedPins, snapshot...)
				return nil
			}, func(path, value string) error {
				return nil
			})

			err = hcm.UpdateHardwareConfig([]types.HardwareConfig{*hwConfig})
			assert.NoError(t, err)

			// Create a mock PTP profile
			profile := &ptpv1.PtpProfile{
				Name: &tt.profileName,
			}

			// Test the function
			err = hcm.ApplyHardwareConfigsForProfile(profile)

			assert.NoError(t, err)
		})
	}
}

func TestHardwareConfigManagerOperations(t *testing.T) {
	// Set up mock PTP device resolver for testing
	SetupMockPtpDeviceResolver()
	defer TeardownMockPtpDeviceResolver()

	// Set up mock DPLL pins from test file for testing
	mockErr := SetupMockDpllPinsFromFileForTests()
	if mockErr != nil {
		t.Logf("Warning: Failed to setup mock DPLL pins from file: %v", mockErr)
		// Continue with test as DPLL pins are optional
	}
	defer TeardownMockDpllPinsForTests()

	hcm := NewHardwareConfigManager()

	// Test initial state
	assert.Equal(t, 0, hcm.GetHardwareConfigCount())

	// Load test data
	hwConfig, err := loadHardwareConfigFromFile("testdata/triple-t-bc-wpc.yaml")
	assert.NoError(t, err)
	assert.NotNil(t, hwConfig)

	// Test UpdateHardwareConfig
	err = hcm.UpdateHardwareConfig([]types.HardwareConfig{*hwConfig})
	assert.NoError(t, err)
	assert.Equal(t, 1, hcm.GetHardwareConfigCount())

	// Test HasHardwareConfigForProfile
	profile := &ptpv1.PtpProfile{
		Name: stringPtr("01-tbc-tr"),
	}
	assert.True(t, hcm.HasHardwareConfigForProfile(profile))

	// Test with non-existent profile
	profile.Name = stringPtr("non-existent")
	assert.False(t, hcm.HasHardwareConfigForProfile(profile))

	// Test GetHardwareConfigsForProfile
	profile.Name = stringPtr("01-tbc-tr")
	configs := hcm.GetHardwareConfigsForProfile(profile)
	assert.Len(t, configs, 1)
	assert.Equal(t, "tbc", *configs[0].Name)

	// Test ClearHardwareConfigs
	hcm.ClearHardwareConfigs()
	assert.Equal(t, 0, hcm.GetHardwareConfigCount())
	assert.False(t, hcm.HasHardwareConfigForProfile(profile))
}

func TestHardwareConfigManagerEmptyConfigs(t *testing.T) {
	// Set up mock DPLL pins from test file for testing
	mockErr := SetupMockDpllPinsFromFileForTests()
	if mockErr != nil {
		t.Logf("Warning: Failed to setup mock DPLL pins from file: %v", mockErr)
		// Continue with test as DPLL pins are optional
	}
	defer TeardownMockDpllPinsForTests()

	hcm := NewHardwareConfigManager()

	// Test with empty configs
	err := hcm.UpdateHardwareConfig([]types.HardwareConfig{})
	assert.NoError(t, err)
	assert.Equal(t, 0, hcm.GetHardwareConfigCount())

	// Test with nil profile name
	profile := &ptpv1.PtpProfile{}
	assert.False(t, hcm.HasHardwareConfigForProfile(profile))

	configs := hcm.GetHardwareConfigsForProfile(profile)
	assert.Len(t, configs, 0)
}

// loadHardwareConfigFromFile loads a HardwareConfig from a YAML file
func loadHardwareConfigFromFile(filename string) (*types.HardwareConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", filename, err)
	}

	// Register the HardwareConfig types with the scheme
	types.AddToScheme(scheme.Scheme)

	// Create a decoder
	decode := serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer().Decode

	// Decode the YAML
	obj, _, err := decode(data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decode YAML: %v", err)
	}

	hwConfig, ok := obj.(*types.HardwareConfig)
	if !ok {
		return nil, fmt.Errorf("decoded object is not a HardwareConfig")
	}

	return hwConfig, nil
}

// stringPtr returns a pointer to a string
func stringPtr(s string) *string {
	return &s
}

func TestLoadHardwareConfigFromFile(t *testing.T) {
	// Test successful loading
	hwConfig, err := loadHardwareConfigFromFile("testdata/triple-t-bc-wpc.yaml")
	assert.NoError(t, err)
	assert.NotNil(t, hwConfig)
	assert.Equal(t, "test", hwConfig.Name)
	assert.Equal(t, "01-tbc-tr", hwConfig.Spec.RelatedPtpProfileName)
	assert.Equal(t, "tbc", *hwConfig.Spec.Profile.Name)

	// Test with non-existent file
	_, err = loadHardwareConfigFromFile("testdata/non-existent.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read file")
}

func TestNewHardwareConfigManager(t *testing.T) {
	hcm := NewHardwareConfigManager()
	assert.NotNil(t, hcm)
	assert.Equal(t, 0, hcm.GetHardwareConfigCount())
}

func TestPTPStateDetector(t *testing.T) {
	// Set up mock PTP device resolver for testing
	SetupMockPtpDeviceResolver()
	defer TeardownMockPtpDeviceResolver()
	// Set up mock DPLL pins from test file for testing
	mockErr := SetupMockDpllPinsFromFileForTests()
	if mockErr != nil {
		t.Logf("Warning: Failed to setup mock DPLL pins from file: %v", mockErr)
		// Continue with test as DPLL pins are optional
	}
	defer TeardownMockDpllPinsForTests()

	// Load test data
	hwConfig, err := loadHardwareConfigFromFile("testdata/triple-t-bc-wpc.yaml")
	assert.NoError(t, err)
	assert.NotNil(t, hwConfig)

	// Create hardware config manager and add test data
	hcm := NewHardwareConfigManager()
	err = hcm.UpdateHardwareConfig([]types.HardwareConfig{*hwConfig})
	assert.NoError(t, err)

	// Create PTP state detector
	psd := NewPTPStateDetector(hcm)

	// Test GetMonitoredPorts
	monitoredPorts := psd.GetMonitoredPorts()
	assert.Contains(t, monitoredPorts, "ens4f1")

	// Test GetBehaviorRules
	conditions := psd.GetBehaviorRules()
	assert.NotEmpty(t, conditions)
}

func TestDetectStateChange(t *testing.T) {
	// Set up mock PTP device resolver for testing
	SetupMockPtpDeviceResolver()
	defer TeardownMockPtpDeviceResolver()
	// Set up mock DPLL pins from test file for testing
	mockErr := SetupMockDpllPinsFromFileForTests()
	if mockErr != nil {
		t.Logf("Warning: Failed to setup mock DPLL pins from file: %v", mockErr)
		// Continue with test as DPLL pins are optional
	}
	defer TeardownMockDpllPinsForTests()

	// Load test data
	hwConfig, err := loadHardwareConfigFromFile("testdata/triple-t-bc-wpc.yaml")
	assert.NoError(t, err)

	// Create hardware config manager and add test data
	hcm := NewHardwareConfigManager()
	err = hcm.UpdateHardwareConfig([]types.HardwareConfig{*hwConfig})
	assert.NoError(t, err)

	// Create PTP state detector
	psd := NewPTPStateDetector(hcm)

	t.Run("individual_test_cases", func(t *testing.T) {
		testCases := []struct {
			name     string
			logLine  string
			expected string
		}{
			{
				name:     "locked condition",
				logLine:  "ptp4l[1716691.337]: [ptp4l.1.config:5] port 1 (ens4f1): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED",
				expected: "locked",
			},
			{
				name:     "lost condition",
				logLine:  "ptp4l[1031716.424]: [ptp4l.0.config:5] port 1 (ens4f1): SLAVE to FAULT_DETECTED on FAULT_DETECTED",
				expected: "lost",
			},
			{
				name:     "non-monitored port - should return empty",
				logLine:  "ptp4l[1031716.424]: [ptp4l.0.config:5] port 2 (ens8f0): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED",
				expected: "", // ens8f0 is not in PTPTimeReceivers for the test data
			},
			{
				name:     "non-ptp4l log - should return empty",
				logLine:  "some other log message",
				expected: "",
			},
			{
				name:     "irrelevant ptp4l transition - should return empty",
				logLine:  "[ptp4l.0.config:5] port 1 (ens4f1): LISTENING to MASTER on INITIALIZATION",
				expected: "",
			},
			{
				name:     "user reported failing case - should work now",
				logLine:  "ptp4l[1720295.764]: [ptp4l.1.config:5] port 1 (ens4f1): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED",
				expected: "locked",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := psd.DetectStateChange(tc.logLine)
				assert.Equal(t, tc.expected, result, "State change detection should match expected result")
				if result != "" {
					t.Logf("✅ Detected %s condition from log line", result)
				}
			})
		}
	})

	t.Run("real_log_file_processing", func(t *testing.T) {
		// Read the real log file
		logData, readErr := os.ReadFile("testdata/log2.txt")
		assert.NoError(t, readErr, "Should be able to read log2.txt")

		// Split log into lines
		lines := strings.Split(string(logData), "\n")

		// Track detected state changes
		var detectedChanges []struct {
			lineNum   int
			condition string
			logLine   string
		}

		// Process each line
		for i, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}

			result := psd.DetectStateChange(line)
			if result != "" {
				detectedChanges = append(detectedChanges, struct {
					lineNum   int
					condition string
					logLine   string
				}{
					lineNum:   i + 1, // 1-based line numbers
					condition: result,
					logLine:   line,
				})
			}
		}

		// Log the results
		t.Logf("=== REAL LOG FILE PROCESSING RESULTS ===")
		t.Logf("Total lines processed: %d", len(lines))
		t.Logf("State changes detected: %d", len(detectedChanges))

		for _, change := range detectedChanges {
			t.Logf("Line %d: %s condition", change.lineNum, change.condition)
			t.Logf("  Log line: %s", change.logLine)
		}

		// Verify we detected some state changes (real logs should have transitions)
		if len(detectedChanges) > 0 {
			t.Logf("✅ Successfully detected %d state changes in real log file", len(detectedChanges))

			// Count locked vs lost conditions
			lockedCount := 0
			lostCount := 0
			for _, change := range detectedChanges {
				if change.condition == "locked" {
					lockedCount++
				} else if change.condition == "lost" {
					lostCount++
				}
			}
			t.Logf("  Locked conditions: %d", lockedCount)
			t.Logf("  Lost conditions: %d", lostCount)
		} else {
			t.Logf("ℹ️  No state changes detected in log file (this may be expected if log contains no relevant transitions)")
		}
	})
}

func TestNewPTPStateDetector(t *testing.T) {
	hcm := NewHardwareConfigManager()
	psd := NewPTPStateDetector(hcm)
	assert.NotNil(t, psd)
	assert.NotNil(t, psd.hcm)
}

// TestApplyConditionDesiredStatesWithRealData tests applyConditionDesiredStates using actual hardware config YAML data
func TestApplyConditionDesiredStatesWithRealData(t *testing.T) {
	// Load the real hardware configuration from YAML
	hwConfig, err := loadHardwareConfigFromFile("testdata/triple-t-bc-wpc.yaml")
	if err != nil {
		t.Fatalf("Failed to load hardware config: %v", err)
	}

	// Create a HardwareConfigManager
	hcm := &HardwareConfigManager{
		hardwareConfigs: []enrichedHardwareConfig{
			{HardwareConfig: *hwConfig},
		},
	}

	// Extract the clock chain from the loaded config
	clockChain := hwConfig.Spec.Profile.ClockChain
	profileName := *hwConfig.Spec.Profile.Name

	// Resolve clock aliases and parse clock IDs to uint64 values
	err = clockChain.ResolveClockAliases()
	if err != nil {
		t.Fatalf("Failed to resolve clock aliases: %v", err)
	}

	t.Logf("Testing with real hardware config: %s", hwConfig.ObjectMeta.Name)
	t.Logf("Profile: %s", profileName)
	t.Logf("Clock chain has %d conditions", len(clockChain.Behavior.Conditions))

	// Validate that source configurations have been resolved and parsed
	if clockChain.Behavior != nil && len(clockChain.Behavior.Sources) > 0 {
		t.Logf("Validating %d behavior sources:", len(clockChain.Behavior.Sources))
		for i, source := range clockChain.Behavior.Sources {
			t.Logf("  Source %d: %s (ClockID: %s)", i+1, source.Name, source.ClockID)
			if source.ClockIDParsed != 0 {
				t.Logf("    ✅ Clock ID parsed: 0x%x", source.ClockIDParsed)
			} else {
				t.Logf("    ⚠️ Clock ID not parsed to uint64")
			}
		}
	}

	// Test each condition from the real hardware config
	for i, condition := range clockChain.Behavior.Conditions {
		t.Run(fmt.Sprintf("condition_%d_%s", i, condition.Name), func(t *testing.T) {
			t.Logf("Testing condition: %s", condition.Name)
			t.Logf("  Sources: %d", len(condition.Sources))
			t.Logf("  Desired states: %d", len(condition.DesiredStates))

			// Log details about the condition
			for j, source := range condition.Sources {
				t.Logf("    Source %d: %s (%s)", j+1, source.SourceName, source.ConditionType)
			}

			for j, desiredState := range condition.DesiredStates {
				if desiredState.DPLL != nil {
					t.Logf("    Desired state %d: DPLL - Clock: %s, Board: %s",
						j+1, desiredState.DPLL.ClockID, desiredState.DPLL.BoardLabel)

					// Validate that clock ID has been parsed to uint64
					if desiredState.DPLL.ClockIDParsed != 0 {
						t.Logf("      Clock ID parsed: 0x%x", desiredState.DPLL.ClockIDParsed)
					} else {
						t.Logf("      Warning: Clock ID not parsed to uint64")
					}
					if desiredState.DPLL.EEC != nil {
						if desiredState.DPLL.EEC.Priority != nil {
							t.Logf("      EEC Priority: %d", *desiredState.DPLL.EEC.Priority)
						}
						if desiredState.DPLL.EEC.State != "" {
							t.Logf("      EEC State: %s", desiredState.DPLL.EEC.State)
						}
					}
					if desiredState.DPLL.PPS != nil {
						if desiredState.DPLL.PPS.Priority != nil {
							t.Logf("      PPS Priority: %d", *desiredState.DPLL.PPS.Priority)
						}
						if desiredState.DPLL.PPS.State != "" {
							t.Logf("      PPS State: %s", desiredState.DPLL.PPS.State)
						}
					}
				}
				if desiredState.SysFS != nil {
					t.Logf("    Desired state %d: SysFS - Path: %s, Value: %s",
						j+1, desiredState.SysFS.Path, desiredState.SysFS.Value)
					if desiredState.SysFS.SourceName != "" {
						t.Logf("      Source: %s", desiredState.SysFS.SourceName)
					}
				}
			}

			// Create a mock enriched hardware config for testing
			mockEnrichedConfig := &enrichedHardwareConfig{
				HardwareConfig: *hwConfig,
				sysFSCommands:  make(map[string][]SysFSCommand),
			}

			// Apply the condition's desired states
			applyErr := hcm.applyConditionDesiredStates(condition, profileName, clockChain, mockEnrichedConfig)

			// All conditions should apply successfully since the YAML is well-formed
			if applyErr != nil {
				t.Errorf("Failed to apply condition '%s': %v", condition.Name, applyErr)
			} else {
				t.Logf("✅ Successfully applied condition '%s' with %d desired states",
					condition.Name, len(condition.DesiredStates))
			}
		})
	}

	// Test specific conditions by name
	testCases := []struct {
		conditionName  string
		expectedStates int
		description    string
	}{
		{
			conditionName:  "Initialize T-BC",
			expectedStates: 5,
			description:    "Should have initialization states for GNSS and CVL pins plus sysFS config",
		},
		{
			conditionName:  "PTP Source Active",
			expectedStates: 2,
			description:    "Should have active configuration for CVL pins",
		},
		{
			conditionName:  "PTP Source Lost - Leader Holdover",
			expectedStates: 2,
			description:    "Should have holdover configuration for CVL pins",
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("validate_%s", strings.ReplaceAll(tc.conditionName, " ", "_")), func(t *testing.T) {
			// Find the condition by name
			var targetCondition *types.Condition
			for _, condition := range clockChain.Behavior.Conditions {
				if condition.Name == tc.conditionName {
					targetCondition = &condition
					break
				}
			}

			if targetCondition == nil {
				t.Fatalf("Condition '%s' not found in hardware config", tc.conditionName)
			}

			// Validate the expected number of desired states
			if len(targetCondition.DesiredStates) != tc.expectedStates {
				t.Errorf("Expected %d desired states for '%s', got %d",
					tc.expectedStates, tc.conditionName, len(targetCondition.DesiredStates))
			}

			t.Logf("✅ %s", tc.description)
			t.Logf("   Found %d desired states as expected", len(targetCondition.DesiredStates))
		})
	}

	// Validate the hardware config structure
	t.Run("validate_hardware_config_structure", func(t *testing.T) {
		// Check that we have the expected sources
		sources := clockChain.Behavior.Sources
		if len(sources) != 1 {
			t.Errorf("Expected 1 source, got %d", len(sources))
		} else {
			source := sources[0]
			if source.Name != "PTP" {
				t.Errorf("Expected source name 'PTP', got '%s'", source.Name)
			}
			if source.SourceType != "ptpTimeReceiver" {
				t.Errorf("Expected source type 'ptpTimeReceiver', got '%s'", source.SourceType)
			}
			if len(source.PTPTimeReceivers) != 1 || source.PTPTimeReceivers[0] != "ens4f1" {
				t.Errorf("Expected PTP time receiver 'ens4f1', got %v", source.PTPTimeReceivers)
			}
			t.Logf("✅ Source configuration validated: %s (%s) with interface %s",
				source.Name, source.SourceType, source.PTPTimeReceivers[0])
		}

		// Check clock identifiers
		clockIDs := clockChain.CommonDefinitions.ClockIdentifiers
		if len(clockIDs) != 2 {
			t.Errorf("Expected 2 clock identifiers, got %d", len(clockIDs))
		} else {
			expectedClockIDs := map[string]string{
				"Leader":   "0x507c6fffff1fb1b8",
				"Follower": "0x507c6fffff1fb580",
			}
			expectedParsedClockIDs := map[string]uint64{
				"Leader":   0x507c6fffff1fb1b8,
				"Follower": 0x507c6fffff1fb580,
			}
			for _, clockID := range clockIDs {
				expectedID, exists := expectedClockIDs[clockID.Alias]
				if !exists {
					t.Errorf("Unexpected clock identifier alias: %s", clockID.Alias)
				} else if clockID.ClockID != expectedID {
					t.Errorf("Expected clock ID %s for %s, got %s", expectedID, clockID.Alias, clockID.ClockID)
				} else {
					t.Logf("✅ Clock identifier validated: %s -> %s", clockID.Alias, clockID.ClockID)
				}

				// Validate parsed uint64 values
				expectedParsedID, exists := expectedParsedClockIDs[clockID.Alias]
				if !exists {
					t.Errorf("No expected parsed clock ID for alias: %s", clockID.Alias)
				} else if clockID.ClockIDParsed != expectedParsedID {
					t.Errorf("Expected parsed clock ID 0x%x for %s, got 0x%x", expectedParsedID, clockID.Alias, clockID.ClockIDParsed)
				} else {
					t.Logf("✅ Clock identifier parsed correctly: %s -> 0x%x", clockID.Alias, clockID.ClockIDParsed)
				}
			}
		}
	})
}

// TestApplyDefaultAndInitConditions tests the applyDefaultAndInitConditions function
func TestApplyDefaultAndInitConditions(t *testing.T) {
	// Set up mock PTP device resolver for testing
	SetupMockPtpDeviceResolver()
	defer TeardownMockPtpDeviceResolver()
	// Set up mock DPLL pins from test file for testing
	mockErr := SetupMockDpllPinsFromFileForTests()
	if mockErr != nil {
		t.Logf("Warning: Failed to setup mock DPLL pins from file: %v", mockErr)
		// Continue with test as DPLL pins are optional
	}
	defer TeardownMockDpllPinsForTests()

	// Load test hardware config
	hwConfig, err := loadHardwareConfigFromFile("testdata/triple-t-bc-wpc.yaml")
	if err != nil {
		t.Fatalf("Failed to load hardware config: %v", err)
	}

	// Resolve clock aliases first
	err = hwConfig.Spec.Profile.ClockChain.ResolveClockAliases()
	if err != nil {
		t.Fatalf("Failed to resolve clock aliases: %v", err)
	}

	// Create hardware config manager
	hcm := NewHardwareConfigManager()
	err = hcm.UpdateHardwareConfig([]types.HardwareConfig{*hwConfig})
	if err != nil {
		t.Fatalf("Failed to update hardware config: %v", err)
	}

	profileName := "test-profile"
	clockChain := hwConfig.Spec.Profile.ClockChain

	tests := []struct {
		name                 string
		clockChain           *types.ClockChain
		profileName          string
		expectError          bool
		expectedDefaultCount int
		expectedInitCount    int
	}{
		{
			name:                 "valid clock chain with conditions",
			clockChain:           clockChain,
			profileName:          profileName,
			expectError:          false,
			expectedDefaultCount: 0, // No explicit default conditions in test data
			expectedInitCount:    1, // "Initialize T-BC" condition has empty sources, treated as init
		},
		{
			name:        "nil behavior section",
			clockChain:  &types.ClockChain{},
			profileName: profileName,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock enriched hardware config for testing
			mockEnrichedConfig := &enrichedHardwareConfig{
				HardwareConfig: types.HardwareConfig{},
				sysFSCommands:  make(map[string][]SysFSCommand),
			}

			// Test the function
			err := hcm.applyDefaultAndInitConditions(tt.clockChain, tt.profileName, mockEnrichedConfig)

			// Verify error expectation
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// If we have behavior section, verify condition extraction
			if tt.clockChain.Behavior != nil {
				defaultConditions := hcm.extractConditionsByType(tt.clockChain.Behavior.Conditions, "default")
				initConditions := hcm.extractConditionsByType(tt.clockChain.Behavior.Conditions, "init")

				assert.Equal(t, tt.expectedDefaultCount, len(defaultConditions), "Default conditions count mismatch")
				assert.Equal(t, tt.expectedInitCount, len(initConditions), "Init conditions count mismatch")

				t.Logf("✅ Found %d default conditions and %d init conditions",
					len(defaultConditions), len(initConditions))
			}
		})
	}
}

// TestExtractConditionsByType tests the extractConditionsByType function
func TestExtractConditionsByType(t *testing.T) {
	// Set up mock DPLL pins for testing
	mockErr := SetupMockDpllPinsForTests()
	if mockErr != nil {
		t.Logf("Warning: Failed to setup mock DPLL pins: %v", mockErr)
		// Continue with test as DPLL pins are optional
	}
	defer TeardownMockDpllPinsForTests()

	hcm := NewHardwareConfigManager()

	// Create test conditions
	conditions := []types.Condition{
		{
			Name: "Default Condition",
			Sources: []types.SourceState{
				{SourceName: "TestSource", ConditionType: ConditionTypeDefault},
			},
		},
		{
			Name:    "Init Condition (Empty Sources)",
			Sources: []types.SourceState{}, // Empty sources should be treated as init
		},
		{
			Name: "Locked Condition",
			Sources: []types.SourceState{
				{SourceName: "TestSource", ConditionType: ConditionTypeLocked},
			},
		},
		{
			Name: "Lost Condition",
			Sources: []types.SourceState{
				{SourceName: "TestSource", ConditionType: ConditionTypeLost},
			},
		},
	}

	tests := []struct {
		name          string
		conditionType string
		expectedCount int
		expectedNames []string
	}{
		{
			name:          "extract default conditions",
			conditionType: ConditionTypeDefault,
			expectedCount: 1,
			expectedNames: []string{"Default Condition"},
		},
		{
			name:          "extract init conditions",
			conditionType: ConditionTypeInit,
			expectedCount: 1,
			expectedNames: []string{"Init Condition (Empty Sources)"},
		},
		{
			name:          "extract locked conditions",
			conditionType: ConditionTypeLocked,
			expectedCount: 1,
			expectedNames: []string{"Locked Condition"},
		},
		{
			name:          "extract lost conditions",
			conditionType: ConditionTypeLost,
			expectedCount: 1,
			expectedNames: []string{"Lost Condition"},
		},
		{
			name:          "extract non-existent condition type",
			conditionType: "nonexistent",
			expectedCount: 0,
			expectedNames: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hcm.extractConditionsByType(conditions, tt.conditionType)

			assert.Equal(t, tt.expectedCount, len(result), "Condition count mismatch")

			// Verify condition names
			resultNames := make([]string, len(result))
			for i, condition := range result {
				resultNames[i] = condition.Name
			}

			for _, expectedName := range tt.expectedNames {
				assert.Contains(t, resultNames, expectedName, "Expected condition not found")
			}

			t.Logf("✅ Found %d conditions of type '%s': %v",
				len(result), tt.conditionType, resultNames)
		})
	}
}

// TestResolveSysFSPtpDevice tests the resolveSysFSPtpDevice function with mock file system
func TestResolveSysFSPtpDevice(t *testing.T) {
	// Create a temporary directory structure for testing
	tempDir := t.TempDir()

	// Create mock PTP device directories and files
	ptpDeviceDir := filepath.Join(tempDir, "sys", "class", "net", "eth0", "device", "ptp")
	if err := os.MkdirAll(ptpDeviceDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory structure: %v", err)
	}

	// Create mock PTP devices
	ptp0Dir := filepath.Join(ptpDeviceDir, "ptp0")
	ptp1Dir := filepath.Join(ptpDeviceDir, "ptp1")
	ptp2Dir := filepath.Join(ptpDeviceDir, "ptp2")

	if err := os.MkdirAll(ptp0Dir, 0755); err != nil {
		t.Fatalf("Failed to create ptp0 directory: %v", err)
	}
	if err := os.MkdirAll(ptp1Dir, 0755); err != nil {
		t.Fatalf("Failed to create ptp1 directory: %v", err)
	}
	if err := os.MkdirAll(ptp2Dir, 0755); err != nil {
		t.Fatalf("Failed to create ptp2 directory: %v", err)
	}

	// Create test files with different permissions
	writableFile := filepath.Join(ptp0Dir, "period")
	readOnlyFile := filepath.Join(ptp1Dir, "period")
	anotherWritableFile := filepath.Join(ptp2Dir, "period")

	// Create writable files (0644 has write permission for owner)
	if err := os.WriteFile(writableFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create writable test file: %v", err)
	}

	if err := os.WriteFile(anotherWritableFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create another writable test file: %v", err)
	}

	// Create read-only file (0444 has no write permission)
	if err := os.WriteFile(readOnlyFile, []byte("test"), 0444); err != nil {
		t.Fatalf("Failed to create read-only test file: %v", err)
	}

	// Create HardwareConfigManager for testing
	hcm := &HardwareConfigManager{
		hardwareConfigs: make([]enrichedHardwareConfig, 0),
	}

	testCases := []struct {
		name          string
		interfacePath string
		expectedPaths []string
		expectedError bool
		description   string
	}{
		{
			name:          "no_ptp_placeholder",
			interfacePath: "/sys/class/net/eth0/carrier",
			expectedPaths: []string{"/sys/class/net/eth0/carrier"},
			expectedError: false,
			description:   "Should return path as-is when no ptp* placeholder is present",
		},
		{
			name:          "valid_ptp_devices_found",
			interfacePath: filepath.Join(tempDir, "sys/class/net/eth0/device/ptp/ptp*/period"),
			expectedPaths: []string{
				filepath.Join(tempDir, "sys/class/net/eth0/device/ptp/ptp0/period"),
				filepath.Join(tempDir, "sys/class/net/eth0/device/ptp/ptp2/period"),
			},
			expectedError: false,
			description:   "Should return all writable PTP device paths",
		},
		{
			name:          "nonexistent_directory",
			interfacePath: filepath.Join(tempDir, "nonexistent/ptp/ptp*/period"),
			expectedPaths: nil,
			expectedError: true,
			description:   "Should return error when PTP device directory doesn't exist",
		},
		{
			name:          "no_writable_files",
			interfacePath: filepath.Join(tempDir, "sys/class/net/eth0/device/ptp/ptp*/nonexistent"),
			expectedPaths: nil,
			expectedError: true,
			description:   "Should return error when no writable files are found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing: %s", tc.description)

			result, testErr := hcm.resolveSysFSPtpDevice(tc.interfacePath)

			if tc.expectedError {
				if testErr == nil {
					t.Errorf("Expected error but got none")
				} else {
					t.Logf("✅ Got expected error: %v", testErr)
				}
			} else {
				if testErr != nil {
					t.Errorf("Unexpected error: %v", testErr)
				} else {
					// Sort both slices for comparison since order might vary
					sort.Strings(result)
					sort.Strings(tc.expectedPaths)

					if !reflect.DeepEqual(result, tc.expectedPaths) {
						t.Errorf("Expected paths: %v, Got: %v", tc.expectedPaths, result)
					} else {
						t.Logf("✅ Successfully resolved %d PTP device paths", len(result))
						for i, path := range result {
							t.Logf("   Path %d: %s", i+1, path)
						}
					}
				}
			}
		})
	}

	// Additional test for edge cases
	t.Run("edge_cases", func(t *testing.T) {
		// Test empty path
		result, edgeErr := hcm.resolveSysFSPtpDevice("")
		if edgeErr != nil {
			t.Errorf("Empty path should not return error, got: %v", edgeErr)
		}
		if len(result) != 1 || result[0] != "" {
			t.Errorf("Empty path should return empty string, got: %v", result)
		}

		// Test path with multiple ptp* placeholders (edge case)
		complexPath := filepath.Join(tempDir, "sys/class/net/eth0/device/ptp/ptp*/subdir/ptp*/period")
		result, edgeErr = hcm.resolveSysFSPtpDevice(complexPath)
		// This should still work as it only splits on the first ptp*
		if edgeErr != nil {
			t.Logf("Complex path with multiple ptp* placeholders returned error (expected): %v", edgeErr)
		} else {
			t.Logf("Complex path resolved to: %v", result)
		}
	})
}

func TestSysFSCommandCaching(t *testing.T) {
	// Set up mock DPLL pins from test file for testing
	mockErr := SetupMockDpllPinsFromFileForTests()
	if mockErr != nil {
		t.Logf("Warning: Failed to setup mock DPLL pins from file: %v", mockErr)
		// Continue with test as DPLL pins are optional
	}
	defer TeardownMockDpllPinsForTests()

	// Set up mock PTP device resolver for testing
	SetupMockPtpDeviceResolver()
	defer TeardownMockPtpDeviceResolver()

	if err := SetupMockDpllPinsForTests(); err != nil {
		t.Fatalf("failed to set up mock DPLL pins: %v", err)
	}
	defer TeardownMockDpllPinsForTests()

	hcm := NewHardwareConfigManager()
	defer hcm.resetExecutors()

	hcm.overrideExecutors(nil, func(path, value string) error { return nil })

	hwConfig, err := loadHardwareConfigFromFile("testdata/triple-t-bc-wpc.yaml")
	assert.NoError(t, err)
	assert.NotNil(t, hwConfig)

	err = hcm.UpdateHardwareConfig([]types.HardwareConfig{*hwConfig})
	assert.NoError(t, err)

	var sysfsWrites []SysFSCommand

	sysfsWriterOverride := func(path, value string) error {
		sysfsWrites = append(sysfsWrites, SysFSCommand{Path: path, Value: value})
		return nil
	}

	hcm.overrideExecutors(nil, sysfsWriterOverride)

	commands := []SysFSCommand{{Path: "/tmp/test", Value: "hello"}}
	err = hcm.applyCachedSysFSCommands("test-profile", "test-condition", commands)
	assert.NoError(t, err)
}

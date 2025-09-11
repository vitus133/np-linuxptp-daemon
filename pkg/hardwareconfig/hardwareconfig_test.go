package hardwareconfig

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/parser"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/types"
	ptpv1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
)

func TestApplyHardwareConfigsForProfile(t *testing.T) {
	tests := []struct {
		name          string
		testDataFile  string
		profileName   string
		expectError   bool
		expectedError string
	}{
		{
			name:          "successful hardware config application",
			testDataFile:  "testdata/triple-t-bc-wpc.yaml",
			profileName:   "01-tbc-tr",
			expectError:   true, // Should return error indicating fallback to plugins
			expectedError: "hardware config application not implemented, use plugin fallback",
		},
		{
			name:          "no matching profile",
			testDataFile:  "testdata/triple-t-bc-wpc.yaml",
			profileName:   "non-existent-profile",
			expectError:   true,
			expectedError: "hardware config application not implemented, use plugin fallback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load test data
			hwConfig, err := loadHardwareConfigFromFile(tt.testDataFile)
			assert.NoError(t, err)
			assert.NotNil(t, hwConfig)

			// Create hardware config manager and add test data
			hcm := NewHardwareConfigManager()
			err = hcm.UpdateHardwareConfig([]types.HardwareConfig{*hwConfig})
			assert.NoError(t, err)

			// Create a mock PTP profile
			profile := &ptpv1.PtpProfile{
				Name: &tt.profileName,
			}

			// Test the function
			err = hcm.ApplyHardwareConfigsForProfile(profile)

			// Verify error
			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHardwareConfigManagerOperations(t *testing.T) {
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

func TestPTPStateDetectorProcessLog(t *testing.T) {
	// Load test data
	hwConfig, err := loadHardwareConfigFromFile("testdata/triple-t-bc-wpc.yaml")
	assert.NoError(t, err)

	// Create hardware config manager and add test data
	hcm := NewHardwareConfigManager()
	err = hcm.UpdateHardwareConfig([]types.HardwareConfig{*hwConfig})
	assert.NoError(t, err)

	// Create PTP state detector
	psd := NewPTPStateDetector(hcm)

	// Test cases for different log messages
	testCases := []struct {
		name              string
		logLine           string
		expectCall        bool
		expectedSource    string
		expectedCondition string
		expectedPort      string
	}{
		{
			name:              "locked condition - UNCALIBRATED to SLAVE",
			logLine:           "ptp4l[1031716.424]: [ptp4l.0.config:5] port 1 (ens4f1): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED",
			expectCall:        true,
			expectedSource:    "PTP", // From the test data
			expectedCondition: "locked",
			expectedPort:      "ens4f1",
		},
		{
			name:              "lost condition - SLAVE to FAULT",
			logLine:           "ptp4l[1031716.424]: [ptp4l.0.config:5] port 1 (ens4f1): SLAVE to FAULT_DETECTED on FAULT_DETECTED",
			expectCall:        true,
			expectedSource:    "PTP",
			expectedCondition: "lost",
			expectedPort:      "ens4f1",
		},
		{
			name:       "non-monitored port",
			logLine:    "ptp4l[1031716.424]: [ptp4l.0.config:5] port 2 (ens8f0): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED",
			expectCall: false, // ens8f0 is not in PTPTimeReceivers for the test data
		},
		{
			name:       "non-ptp4l log",
			logLine:    "some other log message",
			expectCall: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			callCount := 0
			var capturedSource, capturedCondition, capturedPort string

			handler := func(sourceName string, conditionType string, portName string) {
				callCount++
				capturedSource = sourceName
				capturedCondition = conditionType
				capturedPort = portName
			}

			// Process the log line
			psd.ProcessPTP4LLog(tc.logLine, handler)

			if tc.expectCall {
				assert.Equal(t, 1, callCount, "Handler should have been called once")
				assert.Equal(t, tc.expectedSource, capturedSource)
				assert.Equal(t, tc.expectedCondition, capturedCondition)
				assert.Equal(t, tc.expectedPort, capturedPort)
			} else {
				assert.Equal(t, 0, callCount, "Handler should not have been called")
			}
		})
	}
}

func TestDetermineConditionType(t *testing.T) {
	hcm := NewHardwareConfigManager()
	psd := NewPTPStateDetector(hcm)

	testCases := []struct {
		name     string
		event    string
		expected string
	}{
		{
			name:     "locked - to slave",
			event:    "UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED",
			expected: "locked",
		},
		{
			name:     "lost - slave to fault",
			event:    "SLAVE to FAULT_DETECTED on FAULT_DETECTED",
			expected: "lost",
		},
		{
			name:     "lost - slave to uncalibrated",
			event:    "SLAVE to UNCALIBRATED on ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES",
			expected: "lost",
		},
		{
			name:     "lost - fault detected",
			event:    "FAULT_DETECTED",
			expected: "lost",
		},
		{
			name:     "lost - announce receipt timeout",
			event:    "MASTER to MASTER on ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES",
			expected: "lost",
		},
		{
			name:     "no condition",
			event:    "LISTENING to MASTER on INITIALIZATION",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := psd.determineConditionTypeOptimized(tc.event)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestNewPTPStateDetector(t *testing.T) {
	hcm := NewHardwareConfigManager()
	psd := NewPTPStateDetector(hcm)
	assert.NotNil(t, psd)
	assert.NotNil(t, psd.hcm)
}

func TestPTPStateDetectorWithRealLogData(t *testing.T) {
	// Load test data
	hwConfig, err := loadHardwareConfigFromFile("testdata/triple-t-bc-wpc.yaml")
	assert.NoError(t, err)

	// Create hardware config manager and add test data
	hcm := NewHardwareConfigManager()
	err = hcm.UpdateHardwareConfig([]types.HardwareConfig{*hwConfig})
	assert.NoError(t, err)

	// Create PTP state detector
	psd := NewPTPStateDetector(hcm)

	// Read the real log file
	logData, err := os.ReadFile("testdata/log.txt")
	assert.NoError(t, err)
	logContent := string(logData)

	// Split log into lines and filter for ptp4l entries
	lines := strings.Split(logContent, "\n")

	// Track detected state changes
	var detectedChanges []struct {
		lineNum    int
		sourceName string
		condition  string
		portName   string
		logLine    string
	}

	// Process each line
	for i, line := range lines {
		if strings.TrimSpace(line) == "" || !strings.Contains(line, "[ptp4l.1.config") {
			continue
		}

		// Track state changes
		callCount := 0
		handler := func(sourceName string, conditionType string, portName string) {
			callCount++
			detectedChanges = append(detectedChanges, struct {
				lineNum    int
				sourceName string
				condition  string
				portName   string
				logLine    string
			}{
				lineNum:    i + 1, // 1-based line numbers
				sourceName: sourceName,
				condition:  conditionType,
				portName:   portName,
				logLine:    line,
			})
		}

		// Process the log line
		psd.ProcessPTP4LLog(line, handler)
	}

	// Verify that state changes were detected on expected lines
	expectedLines := []int{3500, 11215, 15808, 32434} // Lines with "UNCALIBRATED to SLAVE"

	// Check that we detected state changes on the expected lines
	detectedLineNums := make([]int, len(detectedChanges))
	for i, change := range detectedChanges {
		detectedLineNums[i] = change.lineNum
		t.Logf("Detected state change on line %d: %s -> %s on %s", change.lineNum, change.condition, change.sourceName, change.portName)
		t.Logf("  Log line: %s", change.logLine)
	}

	// Verify all expected lines were detected
	for _, expectedLine := range expectedLines {
		assert.Contains(t, detectedLineNums, expectedLine,
			"Expected state change detection on line %d but it was not detected", expectedLine)
	}

	// Verify the details of detected changes
	for _, change := range detectedChanges {
		assert.Equal(t, "PTP", change.sourceName, "Source name should be 'PTP'")
		assert.Equal(t, "locked", change.condition, "Condition should be 'locked' for 'to SLAVE' transitions")
		assert.Equal(t, "ens4f1", change.portName, "Port name should be 'ens4f1'")
		assert.Contains(t, change.logLine, "UNCALIBRATED to SLAVE", "Log line should contain the state transition")
	}

	t.Logf("Total state changes detected: %d", len(detectedChanges))
	for _, change := range detectedChanges {
		t.Logf("  Line %d: %s condition on %s for source %s",
			change.lineNum, change.condition, change.portName, change.sourceName)
	}
}

func TestPTPStateDetectorLogLineNumbers(t *testing.T) {
	// Load test data
	hwConfig, err := loadHardwareConfigFromFile("testdata/triple-t-bc-wpc.yaml")
	assert.NoError(t, err)

	// Create hardware config manager and add test data
	hcm := NewHardwareConfigManager()
	err = hcm.UpdateHardwareConfig([]types.HardwareConfig{*hwConfig})
	assert.NoError(t, err)

	// Create PTP state detector
	psd := NewPTPStateDetector(hcm)

	// Test specific log lines that should trigger detection
	testCases := []struct {
		lineNumber int
		logLine    string
		expectCall bool
	}{
		{
			lineNumber: 3500,
			logLine:    "ptp4l[1031618.627]: [ptp4l.1.config:5] port 1 (ens4f1): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED",
			expectCall: true,
		},
		{
			lineNumber: 11215,
			logLine:    "ptp4l[1031716.424]: [ptp4l.1.config:5] port 1 (ens4f1): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED",
			expectCall: true,
		},
		{
			lineNumber: 633,
			logLine:    "ptp4l[1031590.641]: [ptp4l.0.config:5] port 2 (ens8f0): LISTENING to MASTER on ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES",
			expectCall: false, // ens8f0 is not in PTPTimeReceivers
		},
		{
			lineNumber: 704,
			logLine:    "ptp4l[1031602.492]: [ptp4l.1.config:5] port 1 (ens4f1): LISTENING to UNCALIBRATED on RS_SLAVE",
			expectCall: false, // This is a different transition pattern
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Line_%d", tc.lineNumber), func(t *testing.T) {
			callCount := 0
			handler := func(sourceName string, conditionType string, portName string) {
				callCount++
			}

			psd.ProcessPTP4LLog(tc.logLine, handler)

			if tc.expectCall {
				assert.Equal(t, 1, callCount, "Expected handler to be called once for line %d", tc.lineNumber)
			} else {
				assert.Equal(t, 0, callCount, "Expected handler not to be called for line %d", tc.lineNumber)
			}
		})
	}
}

func BenchmarkPTPStateDetectorPerformance(b *testing.B) {
	// Load test data with multiple hardware configs
	hwConfig, err := loadHardwareConfigFromFile("testdata/triple-t-bc-wpc.yaml")
	if err != nil {
		b.Fatal(err)
	}

	// Create multiple hardware configs to simulate real-world scenario
	hwConfigs := make([]types.HardwareConfig, 10)
	for i := range hwConfigs {
		hwConfigs[i] = *hwConfig
	}

	// Create hardware config manager and add test data
	hcm := NewHardwareConfigManager()
	err = hcm.UpdateHardwareConfig(hwConfigs)
	if err != nil {
		b.Fatal(err)
	}

	// Create PTP state detector
	psd := NewPTPStateDetector(hcm)

	// Test log line
	logLine := "ptp4l[1031618.627]: [ptp4l.1.config:5] port 1 (ens4f1): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED"

	// Benchmark the optimized version
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callCount := 0
		handler := func(sourceName string, conditionType string, portName string) {
			callCount++
		}
		psd.ProcessPTP4LLog(logLine, handler)
	}
}

func TestOptimizedVsOriginalPerformance(t *testing.T) {
	// Load test data
	hwConfig, err := loadHardwareConfigFromFile("testdata/triple-t-bc-wpc.yaml")
	assert.NoError(t, err)

	// Create multiple hardware configs to amplify performance difference
	hwConfigs := make([]types.HardwareConfig, 5)
	for i := range hwConfigs {
		hwConfigs[i] = *hwConfig
	}

	// Test log line that should trigger detection
	logLine := "ptp4l[1031618.627]: [ptp4l.1.config:5] port 1 (ens4f1): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED"

	// Create hardware config manager
	hcm := NewHardwareConfigManager()
	err = hcm.UpdateHardwareConfig(hwConfigs)
	assert.NoError(t, err)

	// Create optimized PTP state detector
	psd := NewPTPStateDetector(hcm)

	// Test that the optimized version works correctly
	callCount := 0
	handler := func(sourceName string, conditionType string, portName string) {
		callCount++
		assert.Equal(t, "locked", conditionType, "Should detect locked condition")
		assert.Equal(t, "ens4f1", portName, "Should detect correct port")
	}

	psd.ProcessPTP4LLog(logLine, handler)
	assert.Equal(t, 5, callCount, "Handler should be called 5 times (once per hardware config)")

	// Verify caches are built correctly
	monitoredPorts := psd.GetMonitoredPorts()
	assert.Contains(t, monitoredPorts, "ens4f1", "ens4f1 should be in monitored ports")

	// Verify port-to-sources mapping
	sources, exists := psd.portToSources["ens4f1"]
	assert.True(t, exists, "ens4f1 should have sources mapping")
	assert.True(t, len(sources) > 0, "ens4f1 should have at least one source")
}

func BenchmarkParsingApproaches(b *testing.B) {
	logLine := "ptp4l[1031618.627]: [ptp4l.1.config:5] port 1 (ens4f1): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED"

	// Benchmark creating new parser for each log line (original approach)
	b.Run("FullParser_NewInstance", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			extractor := parser.NewPTP4LExtractor()
			_, _, err := extractor.Extract(logLine)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Benchmark using reusable parser (previous optimization)
	b.Run("FullParser_Reusable", func(b *testing.B) {
		extractor := parser.NewPTP4LExtractor()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := extractor.Extract(logLine)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Benchmark direct regex approach (current ultra-optimization)
	b.Run("DirectRegex_UltraFast", func(b *testing.B) {
		// Simulate the direct regex approach
		stateChangeRegex := regexp.MustCompile(`^ptp4l\[\d+\.?\d*\]:\s+\[.*?\]\s+port\s+\d+(?:\s+\(([\d\w]+)\))?:\s+(.+)$`)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			matches := stateChangeRegex.FindStringSubmatch(logLine)
			if len(matches) >= 3 {
				_ = matches[1] // port name
				_ = matches[2] // event
			}
		}
	})
}

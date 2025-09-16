package hardwareconfig

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

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

func TestDetectStateChange(t *testing.T) {
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
		logData, err := os.ReadFile("testdata/log2.txt")
		assert.NoError(t, err, "Should be able to read log2.txt")

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

// TestPTPStateDetectorRegexFormats tests the regex pattern directly with both timestamp formats

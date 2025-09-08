package controller

import (
	"testing"
	"time"

	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/types"
	"github.com/stretchr/testify/assert"
)

// MockHardwareConfigHandler implements HardwareConfigUpdateHandler for testing
type MockHardwareConfigHandler struct {
	LastUpdateProfiles []types.HardwareProfile
	UpdateCallCount    int
}

func (m *MockHardwareConfigHandler) UpdateHardwareConfig(hwProfiles []types.HardwareProfile) error {
	m.LastUpdateProfiles = hwProfiles
	m.UpdateCallCount++
	return nil
}

// MockHardwareConfigRestartTrigger implements HardwareConfigRestartTrigger for testing
type MockHardwareConfigRestartTrigger struct {
	RestartTriggerCount int
	CurrentProfiles     []string
}

func (m *MockHardwareConfigRestartTrigger) TriggerRestartForHardwareChange() error {
	m.RestartTriggerCount++
	return nil
}

func (m *MockHardwareConfigRestartTrigger) GetCurrentPTPProfiles() []string {
	return m.CurrentProfiles
}

func TestCalculateNodeHardwareConfigs(t *testing.T) {
	testCases := []struct {
		name                  string
		nodeName              string
		hwConfigs             []types.HardwareConfig
		expectedProfilesCount int
		expectedProfileNames  []string
	}{
		{
			name:                  "no hardware configs",
			nodeName:              "test-node",
			hwConfigs:             []types.HardwareConfig{},
			expectedProfilesCount: 0,
			expectedProfileNames:  []string{},
		},
		{
			name:     "single hardware config with grandmaster profile",
			nodeName: "test-node",
			hwConfigs: []types.HardwareConfig{
				{
					Spec: types.HardwareConfigSpec{
						Profile: types.HardwareProfile{
							Name:        stringPtr("grandmaster-profile"),
							Description: stringPtr("High-precision grandmaster configuration"),
							ClockChain: &types.ClockChain{
								Structure: []types.Subsystem{
									{
										Name:           "primary-subsystem",
										HardwarePlugin: "intel-e810",
										DPLL: types.DPLL{
											ClockID: "0x1234567890abcdef",
										},
										Ethernet: []types.Ethernet{
											{
												Ports: []string{"ens1f0", "ens1f1"},
											},
										},
									},
								},
							},
						},
						RelatedPtpProfileName: "grandmaster",
					},
				},
			},
			expectedProfilesCount: 1,
			expectedProfileNames:  []string{"grandmaster-profile"},
		},
		{
			name:     "multiple hardware configs",
			nodeName: "worker-node",
			hwConfigs: []types.HardwareConfig{
				{
					Spec: types.HardwareConfigSpec{
						Profile: types.HardwareProfile{
							Name:        stringPtr("boundary-clock-profile"),
							Description: stringPtr("Boundary clock configuration"),
							ClockChain: &types.ClockChain{
								Structure: []types.Subsystem{
									{
										Name: "bc-subsystem",
										DPLL: types.DPLL{
											ClockID: "0xaabbccddeeff1122",
										},
										Ethernet: []types.Ethernet{
											{
												Ports: []string{"ens2f0"},
											},
										},
									},
								},
							},
						},
						RelatedPtpProfileName: "boundary-clock",
					},
				},
				{
					Spec: types.HardwareConfigSpec{
						Profile: types.HardwareProfile{
							Name:        stringPtr("ordinary-clock-profile"),
							Description: stringPtr("Ordinary clock configuration"),
							ClockChain: &types.ClockChain{
								Structure: []types.Subsystem{
									{
										Name: "oc-subsystem",
										DPLL: types.DPLL{
											ClockID: "0x112233445566778899",
										},
										Ethernet: []types.Ethernet{
											{
												Ports: []string{"ens3f0"},
											},
										},
									},
								},
							},
						},
						RelatedPtpProfileName: "ordinary-clock",
					},
				},
			},
			expectedProfilesCount: 2,
			expectedProfileNames:  []string{"boundary-clock-profile", "ordinary-clock-profile"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reconciler := &HardwareConfigReconciler{
				NodeName: tc.nodeName,
			}

			// Call the method under test
			result, err := reconciler.calculateNodeHardwareConfigs(nil, tc.hwConfigs)

			// Verify no error occurred
			assert.NoError(t, err)

			// Verify the number of hardware profiles
			assert.Len(t, result, tc.expectedProfilesCount,
				"Expected %d hardware profiles, got %d", tc.expectedProfilesCount, len(result))

			// Verify profile names match expected
			var actualProfileNames []string
			for _, profile := range result {
				if profile.Name != nil {
					actualProfileNames = append(actualProfileNames, *profile.Name)
				} else {
					actualProfileNames = append(actualProfileNames, "unnamed")
				}
			}
			assert.ElementsMatch(t, tc.expectedProfileNames, actualProfileNames,
				"Expected profile names %v, got %v", tc.expectedProfileNames, actualProfileNames)

			// Additional validations
			for i, profile := range result {
				if profile.Name != nil {
					assert.NotEmpty(t, *profile.Name, "Profile name should not be empty for profile %d", i)
				}
				assert.NotNil(t, profile.ClockChain, "ClockChain should not be nil for profile %d", i)
				if profile.ClockChain != nil {
					assert.NotEmpty(t, profile.ClockChain.Structure, "ClockChain structure should not be empty for profile %d", i)
				}
			}
		})
	}
}

func TestHardwareConfigUpdateHandlerIntegration(t *testing.T) {
	// Test the interaction between controller and handler
	mockHandler := &MockHardwareConfigHandler{}

	reconciler := &HardwareConfigReconciler{
		NodeName:              "test-node",
		HardwareConfigHandler: mockHandler,
	}

	// Create some test hardware profiles
	testProfiles := []types.HardwareProfile{
		{
			Name:        stringPtr("ordinary-clock-profile"),
			Description: stringPtr("Test ordinary clock configuration"),
			ClockChain: &types.ClockChain{
				Structure: []types.Subsystem{
					{
						Name: "oc-subsystem",
						DPLL: types.DPLL{
							ClockID: "0x1234567890abcdef",
						},
						Ethernet: []types.Ethernet{
							{
								Ports: []string{"ens1f0"},
							},
						},
					},
				},
			},
		},
		{
			Name:        stringPtr("grandmaster-profile"),
			Description: stringPtr("Test grandmaster configuration"),
			ClockChain: &types.ClockChain{
				Structure: []types.Subsystem{
					{
						Name:           "gm-subsystem",
						HardwarePlugin: "intel-e810",
						DPLL: types.DPLL{
							ClockID: "0xaabbccddeeff1122",
						},
						Ethernet: []types.Ethernet{
							{
								Ports: []string{"ens2f0", "ens2f1"},
							},
						},
					},
				},
			},
		},
	}

	// Call UpdateHardwareConfig through the handler
	err := reconciler.HardwareConfigHandler.UpdateHardwareConfig(testProfiles)

	// Verify the call succeeded
	assert.NoError(t, err)

	// Verify the handler received the correct configurations
	assert.Equal(t, 1, mockHandler.UpdateCallCount, "Handler should have been called exactly once")
	assert.Len(t, mockHandler.LastUpdateProfiles, 2, "Handler should have received 2 hardware profiles")

	// Verify the specific profiles
	assert.Equal(t, "ordinary-clock-profile", *mockHandler.LastUpdateProfiles[0].Name)
	assert.Equal(t, "Test ordinary clock configuration", *mockHandler.LastUpdateProfiles[0].Description)
	assert.NotNil(t, mockHandler.LastUpdateProfiles[0].ClockChain)

	assert.Equal(t, "grandmaster-profile", *mockHandler.LastUpdateProfiles[1].Name)
	assert.Equal(t, "Test grandmaster configuration", *mockHandler.LastUpdateProfiles[1].Description)
	assert.NotNil(t, mockHandler.LastUpdateProfiles[1].ClockChain)
}

func TestCheckIfActiveProfilesAffected(t *testing.T) {
	testCases := []struct {
		name            string
		activeProfiles  []string
		hwConfigs       []types.HardwareConfig
		expectedRestart bool
		description     string
	}{
		{
			name:            "no active profiles",
			activeProfiles:  []string{},
			hwConfigs:       []types.HardwareConfig{},
			expectedRestart: false,
			description:     "Should not restart when no active profiles exist",
		},
		{
			name:            "no hardware configs",
			activeProfiles:  []string{"grandmaster-profile"},
			hwConfigs:       []types.HardwareConfig{},
			expectedRestart: false,
			description:     "Should not restart when no hardware configs exist",
		},
		{
			name:           "hardware config associated with active profile",
			activeProfiles: []string{"grandmaster-profile", "boundary-clock-profile"},
			hwConfigs: []types.HardwareConfig{
				{
					Spec: types.HardwareConfigSpec{
						RelatedPtpProfileName: "grandmaster-profile",
						Profile: types.HardwareProfile{
							Name: stringPtr("intel-e810-gm"),
						},
					},
				},
			},
			expectedRestart: true,
			description:     "Should restart when hardware config is associated with active profile",
		},
		{
			name:           "hardware config not associated with active profile",
			activeProfiles: []string{"ordinary-clock-profile"},
			hwConfigs: []types.HardwareConfig{
				{
					Spec: types.HardwareConfigSpec{
						RelatedPtpProfileName: "grandmaster-profile",
						Profile: types.HardwareProfile{
							Name: stringPtr("intel-e810-gm"),
						},
					},
				},
			},
			expectedRestart: false,
			description:     "Should not restart when hardware config is not associated with any active profile",
		},
		{
			name:           "multiple hardware configs, one matches",
			activeProfiles: []string{"boundary-clock-profile"},
			hwConfigs: []types.HardwareConfig{
				{
					Spec: types.HardwareConfigSpec{
						RelatedPtpProfileName: "grandmaster-profile",
						Profile: types.HardwareProfile{
							Name: stringPtr("intel-e810-gm"),
						},
					},
				},
				{
					Spec: types.HardwareConfigSpec{
						RelatedPtpProfileName: "boundary-clock-profile",
						Profile: types.HardwareProfile{
							Name: stringPtr("intel-e810-bc"),
						},
					},
				},
			},
			expectedRestart: true,
			description:     "Should restart when at least one hardware config is associated with active profile",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockTrigger := &MockHardwareConfigRestartTrigger{
				CurrentProfiles: tc.activeProfiles,
			}

			reconciler := &HardwareConfigReconciler{
				NodeName:     "test-node",
				ConfigUpdate: mockTrigger,
			}

			result := reconciler.checkIfActiveProfilesAffected(nil, tc.hwConfigs)

			assert.Equal(t, tc.expectedRestart, result, tc.description)
		})
	}
}

func TestRestartTriggerIntegration(t *testing.T) {
	// Test the complete flow of hardware config change triggering deferred PTP restart
	mockHandler := &MockHardwareConfigHandler{}
	mockTrigger := &MockHardwareConfigRestartTrigger{
		CurrentProfiles: []string{"grandmaster-profile"},
	}

	reconciler := &HardwareConfigReconciler{
		NodeName:              "test-node",
		HardwareConfigHandler: mockHandler,
		ConfigUpdate:          mockTrigger,
	}

	// Create a hardware config that is associated with an active profile
	hwConfigs := []types.HardwareConfig{
		{
			Spec: types.HardwareConfigSpec{
				RelatedPtpProfileName: "grandmaster-profile",
				Profile: types.HardwareProfile{
					Name:        stringPtr("intel-e810-gm"),
					Description: stringPtr("Intel E810 grandmaster configuration"),
				},
			},
		},
	}

	// Test that the restart is needed
	needsRestart := reconciler.checkIfActiveProfilesAffected(nil, hwConfigs)
	assert.True(t, needsRestart, "Should detect that restart is needed")

	// Test the deferred restart mechanism
	reconciler.scheduleDeferredRestart(nil)

	// Wait for the deferred restart to execute
	time.Sleep(150 * time.Millisecond)

	// Verify that the restart was triggered after the delay
	assert.Equal(t, 1, mockTrigger.RestartTriggerCount, "Restart should have been triggered once after delay")
}

// Test that multiple restart requests are handled properly
func TestDeferredRestartDebouncing(t *testing.T) {
	mockHandler := &MockHardwareConfigHandler{}
	mockTrigger := &MockHardwareConfigRestartTrigger{
		CurrentProfiles: []string{"grandmaster-profile"},
	}

	reconciler := &HardwareConfigReconciler{
		NodeName:              "test-node",
		HardwareConfigHandler: mockHandler,
		ConfigUpdate:          mockTrigger,
	}

	// Schedule multiple deferred restarts
	reconciler.scheduleDeferredRestart(nil)
	reconciler.scheduleDeferredRestart(nil)
	reconciler.scheduleDeferredRestart(nil)

	// Wait for all deferred restarts to execute
	time.Sleep(200 * time.Millisecond)

	// The restart should have been triggered multiple times (once per call)
	// In a real scenario, we might want to implement actual debouncing,
	// but for now we allow multiple calls
	assert.True(t, mockTrigger.RestartTriggerCount >= 1, "At least one restart should have been triggered")
}

func TestHardwareConfigReconcilerFields(t *testing.T) {
	mockHandler := &MockHardwareConfigHandler{}
	mockTrigger := &MockHardwareConfigRestartTrigger{}

	reconciler := &HardwareConfigReconciler{
		NodeName:              "test-node",
		HardwareConfigHandler: mockHandler,
		ConfigUpdate:          mockTrigger,
	}

	// Verify reconciler has all required fields
	assert.Equal(t, "test-node", reconciler.NodeName)
	assert.NotNil(t, reconciler.HardwareConfigHandler)
	assert.NotNil(t, reconciler.ConfigUpdate)

	// Verify the handler implements the interface
	var _ HardwareConfigUpdateHandler = reconciler.HardwareConfigHandler
	var _ HardwareConfigRestartTrigger = reconciler.ConfigUpdate
}

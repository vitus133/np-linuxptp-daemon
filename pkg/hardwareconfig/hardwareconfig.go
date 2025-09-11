package hardwareconfig

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/types"
	ptpv1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"
)

// HardwareConfigUpdateHandler defines the interface for handling hardware configuration updates
type HardwareConfigUpdateHandler interface {
	UpdateHardwareConfig(hwConfigs []types.HardwareConfig) error
}

// HardwareConfigManager manages hardware configurations and their application
type HardwareConfigManager struct {
	hardwareConfigs []types.HardwareConfig
}

// NewHardwareConfigManager creates a new hardware config manager
func NewHardwareConfigManager() *HardwareConfigManager {
	return &HardwareConfigManager{
		hardwareConfigs: make([]types.HardwareConfig, 0),
	}
}

// UpdateHardwareConfig implements HardwareConfigUpdateHandler interface
// This method updates the hardware configuration stored in the manager
func (hcm *HardwareConfigManager) UpdateHardwareConfig(hwConfigs []types.HardwareConfig) error {
	glog.Infof("Received hardware configuration update with %d hardware configs", len(hwConfigs))

	// Store the hardware configs for use during daemon restart
	hcm.hardwareConfigs = make([]types.HardwareConfig, len(hwConfigs))
	copy(hcm.hardwareConfigs, hwConfigs)

	// Log the hardware configurations for debugging
	for i, hwConfig := range hwConfigs {
		profile := hwConfig.Spec.Profile
		profileName := "unnamed"
		if profile.Name != nil {
			profileName = *profile.Name
		}

		glog.Infof("Hardware config %d: %s (Related PTP: %s)", i, profileName, hwConfig.Spec.RelatedPtpProfileName)

		if profile.Description != nil {
			glog.Infof("  Description: %s", *profile.Description)
		}

		if profile.ClockChain != nil {
			glog.Infof("  Clock chain with %d subsystems", len(profile.ClockChain.Structure))

			// Log basic information about each subsystem
			for j, subsystem := range profile.ClockChain.Structure {
				plugin := subsystem.HardwarePlugin
				if plugin == "" {
					plugin = "default"
				}
				glog.Infof("    Subsystem %d: %s (Plugin: %s, Clock ID: %s)",
					j, subsystem.Name, plugin, subsystem.DPLL.ClockID)
			}

			// Log behavior information if present
			if profile.ClockChain.Behavior != nil {
				glog.Infof("  Behavior: %d sources, %d conditions",
					len(profile.ClockChain.Behavior.Sources),
					len(profile.ClockChain.Behavior.Conditions))
			}
		}
	}

	return nil
}

// UpdateHardwareConfigWithNotification updates hardware configs and notifies state detector to rebuild caches
func (hcm *HardwareConfigManager) UpdateHardwareConfigWithNotification(hwConfigs []types.HardwareConfig, psd *PTPStateDetector) error {
	err := hcm.UpdateHardwareConfig(hwConfigs)
	if err != nil {
		return err
	}
	if psd != nil {
		psd.rebuildCaches()
	}
	return nil
}

// HasHardwareConfigForProfile checks if hardware config is available for a PTP profile
func (hcm *HardwareConfigManager) HasHardwareConfigForProfile(nodeProfile *ptpv1.PtpProfile) bool {
	if nodeProfile.Name == nil {
		return false
	}

	for _, hwConfig := range hcm.hardwareConfigs {
		if hwConfig.Spec.RelatedPtpProfileName == *nodeProfile.Name {
			return true
		}
	}
	return false
}

// GetHardwareConfigsForProfile returns hardware configs associated with a PTP profile
func (hcm *HardwareConfigManager) GetHardwareConfigsForProfile(nodeProfile *ptpv1.PtpProfile) []types.HardwareProfile {
	if nodeProfile.Name == nil {
		return nil
	}

	var relevantConfigs []types.HardwareProfile
	for _, hwConfig := range hcm.hardwareConfigs {
		if hwConfig.Spec.RelatedPtpProfileName == *nodeProfile.Name {
			relevantConfigs = append(relevantConfigs, hwConfig.Spec.Profile)
		}
	}
	return relevantConfigs
}

// ApplyHardwareConfigsForProfile applies hardware configurations for a PTP profile
func (hcm *HardwareConfigManager) ApplyHardwareConfigsForProfile(nodeProfile *ptpv1.PtpProfile) error {
	relevantConfigs := hcm.GetHardwareConfigsForProfile(nodeProfile)

	glog.Infof("Applying %d hardware configurations for PTP profile %s",
		len(relevantConfigs), *nodeProfile.Name)

	for _, hwProfile := range relevantConfigs {
		profileName := "unnamed"
		if hwProfile.Name != nil {
			profileName = *hwProfile.Name
		}

		glog.Infof("Applying hardware profile: %s", profileName)

		// TODO: Implement actual hardware configuration application
		// For now, just log that we would apply the configuration
		if hwProfile.ClockChain != nil {
			for _, subsystem := range hwProfile.ClockChain.Structure {
				glog.Infof("  Would configure subsystem: %s (Plugin: %s)",
					subsystem.Name, subsystem.HardwarePlugin)
			}
		}
	}

	// TODO: Remove this error once real hardware config functionality is implemented
	// For now, return an error to indicate that plugins should be called as fallback
	glog.Infof("TODO: Hardware config application not yet implemented, plugins should be called as fallback")
	return fmt.Errorf("hardware config application not implemented, use plugin fallback")
}

// GetHardwareConfigCount returns the number of hardware configs currently managed
func (hcm *HardwareConfigManager) GetHardwareConfigCount() int {
	return len(hcm.hardwareConfigs)
}

// ClearHardwareConfigs clears all hardware configurations
func (hcm *HardwareConfigManager) ClearHardwareConfigs() {
	hcm.hardwareConfigs = make([]types.HardwareConfig, 0)
}

// GetPTPStateDetector returns a PTP state detector for processing PTP events
// This allows external components to use the hardwareconfig-based PTP processing
func (hcm *HardwareConfigManager) GetPTPStateDetector() *PTPStateDetector {
	// Create a new PTPStateDetector with the current hardware configs
	return NewPTPStateDetector(hcm)
}

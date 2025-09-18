package hardwareconfig

import (
	"fmt"
	"os"
	"strings"

	"github.com/golang/glog"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/types"
	ptpv1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"
)

// HardwareConfigUpdateHandler defines the interface for handling hardware configuration updates
//
//nolint:revive // Name is part of established API
type HardwareConfigUpdateHandler interface {
	UpdateHardwareConfig(hwConfigs []types.HardwareConfig) error
}

// HardwareConfigManager manages hardware configurations and their application
//
//nolint:revive // Name is part of established API
type HardwareConfigManager struct {
	hardwareConfigs []types.HardwareConfig
	pinCache        *PinCache
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
	var err error

	// Resolve clock ID aliases in each hardware config before storing them
	for i := range hwConfigs {
		if hwConfigs[i].Spec.Profile.ClockChain != nil {
			if err := hwConfigs[i].Spec.Profile.ClockChain.ResolveClockAliases(); err != nil {
				return fmt.Errorf("failed to resolve clock aliases in hardware config %d: %w", i, err)
			}
		}
	}

	// Store the hardware configs for use during daemon restart
	hcm.hardwareConfigs = make([]types.HardwareConfig, len(hwConfigs))
	copy(hcm.hardwareConfigs, hwConfigs)
	hcm.pinCache, err = GetDpllPins()
	if err != nil {
		return fmt.Errorf("failed to get DPLL pins: %w", err)
	}

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
		psd.buildCaches()
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
// It processes "default" and "init" conditions in order, applying their desired states
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

		if hwProfile.ClockChain != nil {
			// Log subsystem structure
			for _, subsystem := range hwProfile.ClockChain.Structure {
				glog.Infof("  Subsystem: %s (Plugin: %s, Clock ID: %s)",
					subsystem.Name, subsystem.HardwarePlugin, subsystem.DPLL.ClockID)
			}

			// Extract and apply "default" and "init" conditions in order
			if err := hcm.applyDefaultAndInitConditions(hwProfile.ClockChain, profileName); err != nil {
				return fmt.Errorf("failed to apply default/init conditions for profile %s: %w", profileName, err)
			}
		}
	}

	// TODO: Remove this error once real hardware config functionality is implemented
	// For now, return an error to indicate that plugins should be called as fallback
	glog.Infof("TODO: Hardware config application not yet implemented, plugins should be called as fallback")
	return fmt.Errorf("hardware config application not implemented, use plugin fallback")
}

// applyDefaultAndInitConditions extracts and applies "default" and "init" conditions in order
func (hcm *HardwareConfigManager) applyDefaultAndInitConditions(clockChain *types.ClockChain, profileName string) error {
	if clockChain.Behavior == nil {
		glog.Infof("No behavior section found in hardware profile %s", profileName)
		return nil
	}

	// Extract conditions by type
	defaultConditions := hcm.extractConditionsByType(clockChain.Behavior.Conditions, "default")
	initConditions := hcm.extractConditionsByType(clockChain.Behavior.Conditions, "init")

	glog.Infof("Found %d default conditions and %d init conditions in profile %s",
		len(defaultConditions), len(initConditions), profileName)

	// Apply default conditions first
	for i, condition := range defaultConditions {
		glog.Infof("Applying default condition %d: %s", i+1, condition.Name)
		if err := hcm.applyConditionDesiredStates(condition, profileName, clockChain); err != nil {
			return fmt.Errorf("failed to apply default condition '%s': %w", condition.Name, err)
		}
	}

	// Apply init conditions second
	for i, condition := range initConditions {
		glog.Infof("Applying init condition %d: %s", i+1, condition.Name)
		if err := hcm.applyConditionDesiredStates(condition, profileName, clockChain); err != nil {
			return fmt.Errorf("failed to apply init condition '%s': %w", condition.Name, err)
		}
	}

	return nil
}

// extractConditionsByType extracts conditions that have sources with the specified condition type
// For "default" and "init" conditions, sourceName is not relevant as they apply irrespective of sources
// Special handling: conditions with empty sources array are treated as "init" conditions
func (hcm *HardwareConfigManager) extractConditionsByType(conditions []types.Condition, conditionType string) []types.Condition {
	var matchingConditions []types.Condition

	for _, condition := range conditions {
		// Special case: conditions with empty sources are treated as "init" conditions
		if len(condition.Sources) == 0 && conditionType == "init" {
			glog.Infof("Found condition with empty sources, treating as init condition: %s", condition.Name)
			matchingConditions = append(matchingConditions, condition)
			continue
		}

		// Check if any source in this condition matches the desired type
		for _, source := range condition.Sources {
			if source.ConditionType == conditionType {
				matchingConditions = append(matchingConditions, condition)
				break // Found matching type, add condition and move to next
			}
		}
	}

	return matchingConditions
}

// applyConditionDesiredStates applies the desired states for a given condition
func (hcm *HardwareConfigManager) applyConditionDesiredStates(condition types.Condition, profileName string, clockChain *types.ClockChain) error {
	glog.Infof("Applying %d desired states for condition '%s' in profile %s",
		len(condition.DesiredStates), condition.Name, profileName)

	for i, desiredState := range condition.DesiredStates {
		if err := hcm.applyDesiredState(desiredState, condition.Name, profileName, i+1, clockChain); err != nil {
			return fmt.Errorf("failed to apply desired state %d: %w", i+1, err)
		}
	}

	return nil
}

// applyDesiredState applies a single desired state configuration
func (hcm *HardwareConfigManager) applyDesiredState(desiredState types.DesiredState, conditionName, profileName string, stateIndex int, clockChain *types.ClockChain) error {
	glog.Infof("Applying desired state %d for condition '%s' in profile %s:",
		stateIndex, conditionName, profileName)

	// Apply sysFS configuration if specified
	if desiredState.SysFS != nil {
		if err := hcm.applySysFSDesiredState(*desiredState.SysFS, clockChain); err != nil {
			return fmt.Errorf("failed to apply sysFS configuration: %w", err)
		}
	}

	// Apply DPLL configuration if specified
	if desiredState.DPLL != nil {
		if err := hcm.applyDPLLDesiredState(*desiredState.DPLL, conditionName, profileName); err != nil {
			return fmt.Errorf("failed to apply DPLL configuration: %w", err)
		}
	}
	return nil
}

// applyDPLLDesiredState applies DPLL pin configurations
func (hcm *HardwareConfigManager) applyDPLLDesiredState(dpllDesiredState types.DPLLDesiredState, _, _ string) error {
	glog.Infof("  DPLL Configuration - Clock ID: %s, Board Label: %s", dpllDesiredState.ClockID, dpllDesiredState.BoardLabel)

	return nil
}

// applySysFSDesiredState applies a single sysFS-based desired state configuration
func (hcm *HardwareConfigManager) applySysFSDesiredState(sysfSDesiredState types.SysFSDesiredState, clockChain *types.ClockChain) error {
	glog.Infof("    Applying sysFS configuration:")
	glog.Infof("      Path: %s", sysfSDesiredState.Path)
	glog.Infof("      Value: %s", sysfSDesiredState.Value)
	if sysfSDesiredState.Description != "" {
		glog.Infof("      Description: %s", sysfSDesiredState.Description)
	}

	// Resolve interface names from PTP sources if path contains templating
	resolvedPaths, err := hcm.resolveSysFSPath(sysfSDesiredState, clockChain)
	if err != nil {
		return fmt.Errorf("failed to resolve interface names in path: %w", err)
	}

	// Apply the configuration to each resolved path
	for _, resolvedPath := range resolvedPaths {
		glog.Infof("      Writing '%s' to '%s'", sysfSDesiredState.Value, resolvedPath)
		if writeErr := hcm.writeSysFSValue(resolvedPath, sysfSDesiredState.Value); writeErr != nil {
			return fmt.Errorf("failed to write sysFS value to %s: %w", resolvedPath, writeErr)
		}
	}

	return nil
}

// resolveSysFSPath resolves interface name templating in sysFS paths
func (hcm *HardwareConfigManager) resolveSysFSPath(sysfSDesiredState types.SysFSDesiredState, clockChain *types.ClockChain) ([]string, error) {
	path := sysfSDesiredState.Path

	// If path doesn't contain {interface} placeholder, return as-is
	if !strings.Contains(path, "{interface}") {
		return []string{path}, nil
	}

	// Get interface names from PTP sources
	interfaceName, err := hcm.getInterfaceNameFromSources(sysfSDesiredState.SourceName, clockChain)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface names: %w", err)
	}

	if interfaceName == nil {
		return nil, fmt.Errorf("no interface names found for path templating")
	}

	resolvedPath := strings.ReplaceAll(path, "{interface}", *interfaceName)
	resolvedPaths := []string{resolvedPath}

	return resolvedPaths, nil
}

func (hcm *HardwareConfigManager) resolveSysFSPtpDevice(interfacePath string) ([]string, error) {
	// If path doesn't contain "ptp*" placeholder, return as-is
	if !strings.Contains(interfacePath, "ptp*") {
		return []string{interfacePath}, nil
	}
	deviceDir := strings.Split(interfacePath, "ptp*")[0]
	ptpDevices, err := os.ReadDir(deviceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read ptp devices directory %s: %v", deviceDir, err)
	}
	// We loop through ptp devices to find which one has the full path specified  in the sysfs.path
	// If there are several, we return a list of all the matching full paths
	atLeastOneMatch := false
	resolvedPaths := []string{}
	for _, ptpDevice := range ptpDevices {
		fullPath := strings.ReplaceAll(interfacePath, "ptp*", ptpDevice.Name())
		info, statErr := os.Stat(fullPath)
		if statErr != nil {
			glog.Infof("can't stat %s: %v", fullPath, statErr)
			continue
		}
		if info.Mode()&0200 == 0 {
			glog.Infof("file %s is not writable", fullPath)
			continue
		}
		resolvedPaths = append(resolvedPaths, fullPath)
		atLeastOneMatch = true
	}
	if !atLeastOneMatch {
		return nil, fmt.Errorf("no writable files found for path %s", interfacePath)
	}
	return resolvedPaths, nil
}

// getInterfaceNameFromSources extracts the default interface name from the structure section
// based on the clock ID of the specified source. The default interface is ethernet.ports[0]
// of the corresponding subsystem in the structure section.
func (hcm *HardwareConfigManager) getInterfaceNameFromSources(sourceName string, clockChain *types.ClockChain) (*string, error) {
	if clockChain.Behavior == nil {
		return nil, fmt.Errorf("no behavior section found in clock chain")
	}
	upstreamPort := ""
	// Find the corresponding subsystem in the structure section using the resolved clock ID
	if clockChain.Structure == nil {
		return nil, fmt.Errorf("no structure section found in clock chain")
	}
	for _, source := range clockChain.Behavior.Sources {
		if source.Name == sourceName {
			upstreamPort = source.PTPTimeReceivers[0]
			break
		}
	}
	for _, subsystem := range clockChain.Structure {
		if len(subsystem.Ethernet) > 0 && len(subsystem.Ethernet[0].Ports) > 0 {
			for _, eth := range subsystem.Ethernet {
				for _, port := range eth.Ports {
					if port == upstreamPort {
						return &eth.Ports[0], nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("no default port found for port %s", sourceName)
}

// writeSysFSValue writes a value to a sysFS path
//
//nolint:unparam // TODO implementation always returns nil for now
func (hcm *HardwareConfigManager) writeSysFSValue(path, value string) error {
	// TODO: Implement actual sysFS writing
	// This would involve:
	// 1. Checking if the sysFS path exists
	// 2. Opening the file for writing
	// 3. Writing the value to the file
	// 4. Proper error handling for permissions, file not found, etc.

	glog.Infof("        TODO: Write '%s' to sysFS path '%s'", value, path)
	return nil
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

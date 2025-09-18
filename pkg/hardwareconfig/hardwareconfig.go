package hardwareconfig

import (
	"fmt"
	"strings"

	"github.com/golang/glog"
	dpll "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/dpll-netlink"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/types"
	ptpv1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"
)

// HardwareConfigUpdateHandler defines the interface for handling hardware configuration updates
//
//nolint:revive // Name is part of established API
type HardwareConfigUpdateHandler interface {
	UpdateHardwareConfig(hwConfigs []types.HardwareConfig) error
}

// SysFSCommand represents a resolved sysFS command ready for execution
type SysFSCommand struct {
	Path        string // Resolved path (with interface names substituted)
	Value       string // Value to write
	Description string // Optional description for logging
}

type enrichedHardwareConfig struct {
	types.HardwareConfig
	dpllPinCommands map[string][]dpll.PinParentDeviceCtl
	sysFSCommands   map[string][]SysFSCommand // condition name -> resolved sysFS commands
}

// HardwareConfigManager manages hardware configurations and their application
//
//nolint:revive // Name is part of established API
type HardwareConfigManager struct {
	hardwareConfigs []enrichedHardwareConfig
	pinCache        *PinCache
}

// NewHardwareConfigManager creates a new hardware config manager
func NewHardwareConfigManager() *HardwareConfigManager {
	return &HardwareConfigManager{
		hardwareConfigs: make([]enrichedHardwareConfig, 0),
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

	// Get DPLL pins for processing
	hcm.pinCache, err = GetDpllPins()
	if err != nil {
		return fmt.Errorf("failed to get DPLL pins: %w", err)
	}

	// Store the hardware configs as enriched configs for use during daemon restart
	hcm.hardwareConfigs = make([]enrichedHardwareConfig, len(hwConfigs))
	for i, hwConfig := range hwConfigs {
		hcm.hardwareConfigs[i] = enrichedHardwareConfig{
			HardwareConfig: hwConfig,
		}
		dpllCommands, sysFSCommands, err := hcm.resolveClockChainBehavior(hwConfig)
		if err != nil {
			return fmt.Errorf("failed to resolve clock chain behavior for hardware config %s: %w", hwConfig.Name, err)
		}
		hcm.hardwareConfigs[i].dpllPinCommands = dpllCommands
		hcm.hardwareConfigs[i].sysFSCommands = sysFSCommands

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
	if nodeProfile.Name == nil {
		return fmt.Errorf("PTP profile has no name")
	}

	// Find enriched hardware configs for this profile
	var relevantConfigs []enrichedHardwareConfig
	for _, hwConfig := range hcm.hardwareConfigs {
		if hwConfig.Spec.RelatedPtpProfileName == *nodeProfile.Name {
			relevantConfigs = append(relevantConfigs, hwConfig)
		}
	}

	glog.Infof("Applying %d hardware configurations for PTP profile %s",
		len(relevantConfigs), *nodeProfile.Name)

	for _, enrichedConfig := range relevantConfigs {
		profileName := "unnamed"
		if enrichedConfig.Spec.Profile.Name != nil {
			profileName = *enrichedConfig.Spec.Profile.Name
		}

		glog.Infof("Applying hardware profile: %s", profileName)

		if enrichedConfig.Spec.Profile.ClockChain != nil {
			// Log subsystem structure
			for _, subsystem := range enrichedConfig.Spec.Profile.ClockChain.Structure {
				glog.Infof("  Subsystem: %s (Plugin: %s, Clock ID: %s)",
					subsystem.Name, subsystem.HardwarePlugin, subsystem.DPLL.ClockID)
			}

			// Extract and apply "default" and "init" conditions in order
			if err := hcm.applyDefaultAndInitConditions(enrichedConfig.Spec.Profile.ClockChain, profileName, &enrichedConfig); err != nil {
				return fmt.Errorf("failed to apply default/init conditions for profile %s: %w", profileName, err)
			}
		}
	}

	// TODO: Remove this error once real hardware config functionality is implemented
	// For now, return an error to indicate that plugins should be called as fallback
	glog.Infof("TODO: Hardware config application not yet implemented, plugins should be called as fallback")
	return fmt.Errorf("hardware config application not implemented, use plugin fallback")
}

func (hcm *HardwareConfigManager) resolveClockChainBehavior(hwConfig types.HardwareConfig) (map[string][]dpll.PinParentDeviceCtl, map[string][]SysFSCommand, error) {
	clockChain := hwConfig.Spec.Profile.ClockChain
	if clockChain == nil {
		// Return empty maps if there's no clock chain
		return make(map[string][]dpll.PinParentDeviceCtl), make(map[string][]SysFSCommand), nil
	}
	conditions := hcm.extractConditionByType(clockChain)
	pinCommandsPerCondition := make(map[string][]dpll.PinParentDeviceCtl)
	sysFSCommandsPerCondition := make(map[string][]SysFSCommand)

	for conditionName, condition := range conditions {
		// Resolve DPLL pin commands
		pinCommands, err := hcm.resolveDpllPinCommands(condition)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve DPLL pin commands for condition %s: %w", condition.Name, err)
		}
		pinCommandsPerCondition[conditionName] = pinCommands

		// Resolve sysFS commands
		sysFSCommands, err := hcm.resolveSysFSCommands(condition, clockChain)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve sysFS commands for condition %s: %w", condition.Name, err)
		}
		sysFSCommandsPerCondition[conditionName] = sysFSCommands
	}
	return pinCommandsPerCondition, sysFSCommandsPerCondition, nil
}

func (hcm *HardwareConfigManager) resolveDpllPinCommands(condition types.Condition) ([]dpll.PinParentDeviceCtl, error) {
	pinCommands := []dpll.PinParentDeviceCtl{}
	for _, desiredState := range condition.DesiredStates {
		if desiredState.DPLL != nil {
			pinCommand, err := hcm.createPinCommandForDPLLDesiredState(*desiredState.DPLL)
			if err != nil {
				return nil, fmt.Errorf("failed to create pin command for DPLL desired state: %w", err)
			}
			pinCommands = append(pinCommands, pinCommand)
		}
	}
	return pinCommands, nil
}

func (hcm *HardwareConfigManager) resolveSysFSCommands(condition types.Condition, clockChain *types.ClockChain) ([]SysFSCommand, error) {
	sysFSCommands := []SysFSCommand{}
	for _, desiredState := range condition.DesiredStates {
		if desiredState.SysFS != nil {
			// Resolve the sysFS paths (handle interface templating)
			resolvedPaths, err := hcm.resolveSysFSPath(*desiredState.SysFS, clockChain)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve sysFS path: %w", err)
			}

			// Create a command for each resolved path
			for _, resolvedPath := range resolvedPaths {
				sysFSCommands = append(sysFSCommands, SysFSCommand{
					Path:        resolvedPath,
					Value:       desiredState.SysFS.Value,
					Description: desiredState.SysFS.Description,
				})
			}
		}
	}
	return sysFSCommands, nil
}

func (hcm *HardwareConfigManager) extractConditionByType(clockChain *types.ClockChain) map[string]types.Condition {
	conditions := make(map[string]types.Condition)

	if clockChain.Behavior == nil || len(clockChain.Behavior.Conditions) == 0 {
		return conditions
	}

	for _, condition := range clockChain.Behavior.Conditions {
		if len(condition.Sources) == 0 {
			// Treat conditions with empty sources as "init" conditions
			conditions["init"] = condition
			continue
		}
		switch condition.Sources[0].ConditionType {
		case "default":
			conditions["default"] = condition
		case "init":
			conditions["init"] = condition
		case "locked":
			conditions["locked"] = condition
		case "lost":
			conditions["lost"] = condition
		}
	}
	return conditions
}

func (hcm *HardwareConfigManager) createPinCommandForDPLLDesiredState(dpllDesiredState types.DPLLDesiredState) (dpll.PinParentDeviceCtl, error) {
	// Find the pin in the cache
	pin, found := hcm.pinCache.GetPin(dpllDesiredState.ClockIDParsed, dpllDesiredState.BoardLabel)
	if !found {
		return dpll.PinParentDeviceCtl{}, fmt.Errorf("DPLL pin not found in cache")
	}

	// Create the pin command
	pinCommand := dpll.PinParentDeviceCtl{
		ID:           pin.ID,
		PinParentCtl: make([]dpll.PinControl, 0),
	}

	// Add pin controls for each parent device
	for _, parentDevice := range pin.ParentDevice {
		pc := dpll.PinControl{
			PinParentID: parentDevice.ParentID,
		}

		// Set priority or state based on direction and desired state
		if parentDevice.Direction == dpll.PinDirectionInput {
			if dpllDesiredState.EEC != nil && dpllDesiredState.EEC.Priority != nil {
				priority := uint32(*dpllDesiredState.EEC.Priority)
				pc.Prio = &priority
			}
			if dpllDesiredState.PPS != nil && dpllDesiredState.PPS.Priority != nil {
				priority := uint32(*dpllDesiredState.PPS.Priority)
				pc.Prio = &priority
			}
		} else {
			// Output pin
			if dpllDesiredState.EEC != nil && dpllDesiredState.EEC.State != "" {
				state, err := GetPinStateUint32(dpllDesiredState.EEC.State)
				if err != nil {
					return dpll.PinParentDeviceCtl{}, fmt.Errorf("invalid EEC state: %w", err)
				}
				pc.State = &state
			}
			if dpllDesiredState.PPS != nil && dpllDesiredState.PPS.State != "" {
				state, err := GetPinStateUint32(dpllDesiredState.PPS.State)
				if err != nil {
					return dpll.PinParentDeviceCtl{}, fmt.Errorf("invalid PPS state: %w", err)
				}
				pc.State = &state
			}
		}

		pinCommand.PinParentCtl = append(pinCommand.PinParentCtl, pc)
	}

	return pinCommand, nil
}

// applyDefaultAndInitConditions extracts and applies "default" and "init" conditions in order
func (hcm *HardwareConfigManager) applyDefaultAndInitConditions(clockChain *types.ClockChain, profileName string, enrichedConfig *enrichedHardwareConfig) error {
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
		if err := hcm.applyConditionDesiredStates(condition, profileName, clockChain, enrichedConfig); err != nil {
			return fmt.Errorf("failed to apply default condition '%s': %w", condition.Name, err)
		}
	}

	// Apply init conditions second
	for i, condition := range initConditions {
		glog.Infof("Applying init condition %d: %s", i+1, condition.Name)
		if err := hcm.applyConditionDesiredStates(condition, profileName, clockChain, enrichedConfig); err != nil {
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
func (hcm *HardwareConfigManager) applyConditionDesiredStates(condition types.Condition, profileName string, clockChain *types.ClockChain, enrichedConfig *enrichedHardwareConfig) error {
	glog.Infof("Applying %d desired states for condition '%s' in profile %s",
		len(condition.DesiredStates), condition.Name, profileName)

	// Apply cached sysFS commands for this condition
	if sysFSCommands, exists := enrichedConfig.sysFSCommands[condition.Name]; exists && len(sysFSCommands) > 0 {
		if err := hcm.applyCachedSysFSCommands(sysFSCommands, condition.Name, profileName); err != nil {
			return fmt.Errorf("failed to apply cached sysFS commands: %w", err)
		}
	}

	// Apply individual desired states (for DPLL and other non-sysFS configurations)
	for i, desiredState := range condition.DesiredStates {
		if err := hcm.applyDesiredState(desiredState, condition.Name, profileName, i+1, clockChain); err != nil {
			return fmt.Errorf("failed to apply desired state %d: %w", i+1, err)
		}
	}

	return nil
}

// applyCachedSysFSCommands applies pre-resolved sysFS commands for a condition
func (hcm *HardwareConfigManager) applyCachedSysFSCommands(commands []SysFSCommand, conditionName, profileName string) error {
	glog.Infof("  Applying %d cached sysFS commands for condition '%s' in profile %s",
		len(commands), conditionName, profileName)

	for i, cmd := range commands {
		glog.Infof("    SysFS command %d:", i+1)
		glog.Infof("      Path: %s", cmd.Path)
		glog.Infof("      Value: %s", cmd.Value)
		if cmd.Description != "" {
			glog.Infof("      Description: %s", cmd.Description)
		}

		if err := hcm.writeSysFSValue(cmd.Path, cmd.Value); err != nil {
			return fmt.Errorf("failed to write sysFS value '%s' to path '%s': %w", cmd.Value, cmd.Path, err)
		}
	}

	return nil
}

// applyDesiredState applies a single desired state configuration
func (hcm *HardwareConfigManager) applyDesiredState(desiredState types.DesiredState, conditionName, profileName string, stateIndex int, clockChain *types.ClockChain) error {
	glog.Infof("Applying desired state %d for condition '%s' in profile %s:",
		stateIndex, conditionName, profileName)

	// Note: SysFS configurations are now applied via cached commands in applyCachedSysFSCommands
	// Individual sysFS desired states are no longer applied here to avoid duplicate resolution

	// Apply DPLL configuration if specified
	if desiredState.DPLL != nil {
		// if err := hcm.applyDPLLDesiredState(*desiredState.DPLL); err != nil {
		// 	return fmt.Errorf("failed to apply DPLL configuration: %w", err)
		// }
	}
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

	// Also resolve ptp* placeholders if present
	if strings.Contains(resolvedPath, "ptp*") {
		return hcm.resolveSysFSPtpDevice(resolvedPath)
	}

	return []string{resolvedPath}, nil
}

func (hcm *HardwareConfigManager) resolveSysFSPtpDevice(interfacePath string) ([]string, error) {
	return ptpDeviceResolver(interfacePath)
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
	hcm.hardwareConfigs = make([]enrichedHardwareConfig, 0)
}

// GetPTPStateDetector returns a PTP state detector for processing PTP events
// This allows external components to use the hardwareconfig-based PTP processing
func (hcm *HardwareConfigManager) GetPTPStateDetector() *PTPStateDetector {
	// Create a new PTPStateDetector with the current hardware configs
	return NewPTPStateDetector(hcm)
}

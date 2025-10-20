package hardwareconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	dpll "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/dpll-netlink"

	// loader is part of this package (vendor_loader.go)
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/types"
	ptpv1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"
)

// Condition type constants
const (
	ConditionTypeDefault = "default"
	ConditionTypeInit    = "init"
	ConditionTypeLocked  = "locked"
	ConditionTypeLost    = "lost"
)

func collectConnectorUsage(subsystem types.Subsystem) (map[string]struct{}, map[string]struct{}) {
	inputs := make(map[string]struct{})
	outputs := make(map[string]struct{})

	add := func(connector string, target map[string]struct{}) {
		if connector == "" {
			return
		}
		target[connector] = struct{}{}
	}

	for _, cfg := range subsystem.DPLL.PhaseInputs {
		add(cfg.Connector, inputs)
	}
	for _, cfg := range subsystem.DPLL.FrequencyInputs {
		add(cfg.Connector, inputs)
	}
	for _, cfg := range subsystem.DPLL.PhaseOutputs {
		add(cfg.Connector, outputs)
	}
	for _, cfg := range subsystem.DPLL.FrequencyOutputs {
		add(cfg.Connector, outputs)
	}

	return inputs, outputs
}

func firstInterface(subsystem types.Subsystem) string {
	if len(subsystem.Ethernet) == 0 {
		return ""
	}
	if len(subsystem.Ethernet[0].Ports) == 0 {
		return ""
	}
	return subsystem.Ethernet[0].Ports[0]
}

func (hcm *HardwareConfigManager) translateConnectorCommands(commands *ConnectorCommands, defaultInterface, subsystemName string, connectorsInput, connectorsOutput map[string]struct{}) ([]SysFSCommand, error) {
	if commands == nil {
		return nil, nil
	}
	if defaultInterface == "" {
		glog.Infof("No Ethernet ports defined for subsystem %s; skipping connectorCommands translation", subsystemName)
		return nil, nil
	}

	render := func(cmds []ConnectorCommand) ([]SysFSCommand, error) {
		out := make([]SysFSCommand, 0, len(cmds))
		for _, c := range cmds {
			if !strings.EqualFold(c.Type, "FSWrite") {
				glog.Infof("Unsupported connector command type %s, skipping", c.Type)
				continue
			}
			path := strings.ReplaceAll(c.Path, "{interface}", defaultInterface)
			var paths []string
			var err error
			if strings.Contains(path, "ptp*") {
				paths, err = hcm.resolveSysFSPtpDevice(path)
				if err != nil {
					return nil, fmt.Errorf("resolve ptp* for %s: %w", path, err)
				}
			} else {
				paths = []string{path}
			}
			for _, rp := range paths {
				out = append(out, SysFSCommand{Path: rp, Value: c.Value, Description: c.Description})
			}
		}
		return out, nil
	}

	sysfs := make([]SysFSCommand, 0)

	apply := func(conn string, actionMap map[string]ConnectorAction, usage string) error {
		if actionMap == nil {
			glog.Infof("No %s commands defined for connector %s", usage, conn)
			return nil
		}
		action, ok := actionMap[conn]
		if !ok {
			glog.Infof("Connector %s used as %s but no vendor commands provided", conn, usage)
			return nil
		}
		rendered, err := render(action.Commands)
		if err != nil {
			return err
		}
		sysfs = append(sysfs, rendered...)
		return nil
	}

	for conn := range connectorsInput {
		if err := apply(conn, commands.Inputs, "input"); err != nil {
			return nil, fmt.Errorf("connector %s inputs: %w", conn, err)
		}
	}
	for conn := range connectorsOutput {
		if err := apply(conn, commands.Outputs, "output"); err != nil {
			return nil, fmt.Errorf("connector %s outputs: %w", conn, err)
		}
	}

	if commands.Disable != nil {
		defined := make(map[string]struct{})
		for name := range commands.Inputs {
			defined[name] = struct{}{}
		}
		for name := range commands.Outputs {
			defined[name] = struct{}{}
		}
		for name := range commands.Disable {
			defined[name] = struct{}{}
		}

		used := make(map[string]struct{})
		for name := range connectorsInput {
			used[name] = struct{}{}
		}
		for name := range connectorsOutput {
			used[name] = struct{}{}
		}

		for conn := range defined {
			if _, ok := used[conn]; ok {
				continue
			}
			action, exists := commands.Disable[conn]
			if !exists {
				glog.Infof("Connector %s not referenced but disable commands missing", conn)
				continue
			}
			rendered, err := render(action.Commands)
			if err != nil {
				return nil, fmt.Errorf("connector %s disable: %w", conn, err)
			}
			sysfs = append(sysfs, rendered...)
		}
	}

	return sysfs, nil
}

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
	// Static defaults derived from the clock chain structure (hardware-specific)
	structurePinCommands   []dpll.PinParentDeviceCtl
	structureSysFSCommands []SysFSCommand
}

// HardwareConfigManager manages hardware configurations and their application
//
//nolint:revive // Name is part of established API
type HardwareConfigManager struct {
	hardwareConfigs []enrichedHardwareConfig
	pinCache        *PinCache
	pinApplier      func([]dpll.PinParentDeviceCtl) error
	sysfsWriter     func(string, string) error
	mu              sync.RWMutex
	cond            *sync.Cond
	ready           bool
}

// NewHardwareConfigManager creates a new hardware config manager
func NewHardwareConfigManager() *HardwareConfigManager {
	hcm := &HardwareConfigManager{
		hardwareConfigs: make([]enrichedHardwareConfig, 0),
		pinApplier:      func(cmds []dpll.PinParentDeviceCtl) error { return BatchPinSet(&cmds) },
		sysfsWriter: func(path, value string) error {
			glog.Infof("Writing sysfs value to %s: %s", path, value)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return fmt.Errorf("create dir for %s: %w", path, err)
			}
			return os.WriteFile(path, []byte(value), 0o644)
		},
	}
	hcm.cond = sync.NewCond(&hcm.mu)
	return hcm
}

// UpdateHardwareConfig implements HardwareConfigUpdateHandler interface
// This method updates the hardware configuration stored in the manager
func (hcm *HardwareConfigManager) UpdateHardwareConfig(hwConfigs []types.HardwareConfig) error {
	glog.Infof("Received hardware configuration update with %d hardware configs", len(hwConfigs))

	// Handle empty configs case - mark as ready immediately
	if len(hwConfigs) == 0 {
		hcm.setHardwareConfigs([]enrichedHardwareConfig{})
		return nil
	}

	var err error

	// Resolve clock ID aliases in each hardware config before storing them
	for i := range hwConfigs {
		if hwConfigs[i].Spec.Profile.ClockChain != nil {
			if aliasErr := hwConfigs[i].Spec.Profile.ClockChain.ResolveClockAliases(); aliasErr != nil {
				return fmt.Errorf("failed to resolve clock aliases in hardware config %d: %w", i, aliasErr)
			}
		}
	}

	// Get DPLL pins for processing
	hcm.pinCache, err = GetDpllPins()
	if err != nil {
		return fmt.Errorf("failed to get DPLL pins: %w", err)
	}
	if hcm.pinCache != nil {
		glog.Infof("Pin cache initialized: %d total pins", hcm.pinCache.Count())
	}

	prepared := make([]enrichedHardwareConfig, len(hwConfigs))
	for i, hwConfig := range hwConfigs {
		prepared[i] = enrichedHardwareConfig{HardwareConfig: hwConfig}

		glog.Infof("Resolving hardware config '%s' (%d/%d)", hwConfig.Name, i+1, len(hwConfigs))

		dpllCommands, sysFSCommands, behaviorErr := hcm.resolveClockChainBehavior(hwConfig)
		if behaviorErr != nil {
			return fmt.Errorf("failed to resolve clock chain behavior for hardware config %s: %w", hwConfig.Name, behaviorErr)
		}
		glog.Infof("  behavior: %d conditions with DPLL commands, %d conditions with sysfs commands", len(dpllCommands), len(sysFSCommands))
		prepared[i].dpllPinCommands = dpllCommands
		prepared[i].sysFSCommands = sysFSCommands

		structPins, structSysfs, structErr := hcm.resolveClockChainStructure(hwConfig)
		if structErr != nil {
			return fmt.Errorf("failed to resolve clock chain structure for hardware config %s: %w", hwConfig.Name, structErr)
		}
		glog.Infof("  structure: %d DPLL commands, %d sysfs commands", len(structPins), len(structSysfs))
		prepared[i].structurePinCommands = structPins
		prepared[i].structureSysFSCommands = structSysfs
	}

	hcm.setHardwareConfigs(prepared)
	return nil
}

// CloneHardwareConfigs returns a deep copy of the current hardware configurations
func (hcm *HardwareConfigManager) CloneHardwareConfigs() []types.HardwareConfig {
	hcm.mu.RLock()
	defer hcm.mu.RUnlock()
	out := make([]types.HardwareConfig, len(hcm.hardwareConfigs))
	for i, cfg := range hcm.hardwareConfigs {
		out[i] = cfg.HardwareConfig
	}
	return out
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

		if err := hcm.applyStructureDefaults(&enrichedConfig, profileName); err != nil {
			return err
		}
		if err := hcm.applyBehaviorConditions(&enrichedConfig, profileName); err != nil {
			return err
		}
	}

	// NOTE: Structure application currently resolves and caches commands, but execution relies on future netlink/sysfs writers.
	// Until full support lands, we simply cache the resolved data and return success so the daemon remains stable.
	return nil
}

func (hcm *HardwareConfigManager) resolveClockChainBehavior(hwConfig types.HardwareConfig) (map[string][]dpll.PinParentDeviceCtl, map[string][]SysFSCommand, error) {
	clockChain := hwConfig.Spec.Profile.ClockChain
	if clockChain == nil {
		glog.Infof("Hardware config %s has no clock chain", hwConfig.Name)
		return make(map[string][]dpll.PinParentDeviceCtl), make(map[string][]SysFSCommand), nil
	}
	conditions := hcm.extractConditionByType(clockChain)
	glog.Infof("Hardware config %s behavior: %d conditions", hwConfig.Name, len(conditions))
	pinCommandsPerCondition := make(map[string][]dpll.PinParentDeviceCtl)
	sysFSCommandsPerCondition := make(map[string][]SysFSCommand)

	for conditionName, condition := range conditions {
		glog.Infof("  Resolving condition '%s' with %d desired states", condition.Name, len(condition.DesiredStates))

		pinCommands, err := hcm.resolveDpllPinCommands(condition)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve DPLL pin commands for condition %s: %w", condition.Name, err)
		}
		glog.Infof("    Condition '%s': resolved %d DPLL commands", condition.Name, len(pinCommands))
		pinCommandsPerCondition[conditionName] = pinCommands

		sysFSCommands, err := hcm.resolveSysFSCommands(condition, clockChain)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve sysFS commands for condition %s: %w", condition.Name, err)
		}
		glog.Infof("    Condition '%s': resolved %d sysfs commands", condition.Name, len(sysFSCommands))
		sysFSCommandsPerCondition[conditionName] = sysFSCommands
	}
	return pinCommandsPerCondition, sysFSCommandsPerCondition, nil
}

// resolveClockChainStructure inspects the structure section and produces static, hardware-specific
// defaults that should be applied regardless of runtime behavior, such as:
// - eSync and refSync configuration (via translation to the DPLL commands)
// - pin phase adjustments (factory/internal and internal/external from config)
// - default pin priorities resulting from factory defaults
// - sysfs commands when a pin is associated with a connector
//
// This function delegates to a hardware-specific definition based on Subsystem.HardwareSpecificDefinitions.
// Example: "intel/e810" would map to pkg/hardwareconfig/hardware-specific/intel/e810
// where YAML definitions convert static declarations into concrete commands.
func (hcm *HardwareConfigManager) resolveClockChainStructure(hwConfig types.HardwareConfig) ([]dpll.PinParentDeviceCtl, []SysFSCommand, error) {
	cc := hwConfig.Spec.Profile.ClockChain
	if cc == nil || len(cc.Structure) == 0 {
		glog.Infof("Hardware config %s has no structure section", hwConfig.Name)
		return nil, nil, nil
	}

	allPins := make([]dpll.PinParentDeviceCtl, 0)
	allSysfs := make([]SysFSCommand, 0)

	for _, subsystem := range cc.Structure {
		hwDefPath := strings.TrimSpace(subsystem.HardwareSpecificDefinitions)
		glog.Infof("  Subsystem %s: hardware definition='%s'", subsystem.Name, hwDefPath)
		if hwDefPath == "" {
			glog.Infof("  Subsystem %s has no hardware-specific definition; skipping", subsystem.Name)
			continue
		}

		pins, sysfs, err := hcm.resolveSubsystemStructure(hwDefPath, subsystem, cc)
		if err != nil {
			return nil, nil, fmt.Errorf("hardware-specific '%s' failed for subsystem %s: %w", hwDefPath, subsystem.Name, err)
		}
		glog.Infof("    Subsystem %s: resolved %d structure DPLL commands, %d sysfs commands", subsystem.Name, len(pins), len(sysfs))
		allPins = append(allPins, pins...)
		allSysfs = append(allSysfs, sysfs...)
	}

	return allPins, allSysfs, nil
}

// resolveSubsystemStructure dispatches to a hardware-specific definition implementation.
// Skeleton only: wire vendor-specific translators here.
func (hcm *HardwareConfigManager) resolveSubsystemStructure(hwDefPath string, subsystem types.Subsystem, clockChain *types.ClockChain) ([]dpll.PinParentDeviceCtl, []SysFSCommand, error) {
	// Load YAML defaults from pkg/hardwareconfig/hardware-specific/<hwDefPath>/defaults.yaml
	spec, err := LoadHardwareDefaults(hwDefPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load hardware defaults for '%s': %w", hwDefPath, err)
	}
	if spec == nil {
		glog.Infof("No hardware defaults found for '%s' (subsystem %s) - skipping", hwDefPath, subsystem.Name)
		return nil, nil, nil
	}

	pins := make([]dpll.PinParentDeviceCtl, 0)
	sysfs := make([]SysFSCommand, 0)

	// Translate pin default priorities/states (apply unconditionally)
	for label, overrides := range spec.PinDefaults {
		var eecPrio, ppsPrio *uint32
		if overrides.EEC != nil && overrides.EEC.Priority != nil {
			v := uint32(*overrides.EEC.Priority)
			eecPrio = &v
		}
		if overrides.PPS != nil && overrides.PPS.Priority != nil {
			v := uint32(*overrides.PPS.Priority)
			ppsPrio = &v
		}
		if cmd, ok := hcm.buildPinCommandFromDefaults(subsystem, label, overrides, eecPrio, ppsPrio); ok {
			pins = append(pins, cmd)
		}
	}

	// Process eSync/frequency configuration for all pins in the subsystem
	esyncPins, err := hcm.buildESyncPinCommands(subsystem, clockChain, spec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build eSync pin commands: %w", err)
	}
	pins = append(pins, esyncPins...)

	// Translate connectorCommands to SysFS actions based on connectors referenced by pins
	inputs, outputs := collectConnectorUsage(subsystem)
	defaultInterface := firstInterface(subsystem)
	extraSysfs, err := hcm.translateConnectorCommands(spec.ConnectorCommands, defaultInterface, subsystem.Name, inputs, outputs)
	if err != nil {
		return nil, nil, err
	}
	sysfs = append(sysfs, extraSysfs...)

	return pins, sysfs, nil
}

// buildESyncPinCommands processes all pins in the subsystem and builds frequency/eSync commands
func (hcm *HardwareConfigManager) buildESyncPinCommands(subsystem types.Subsystem, clockChain *types.ClockChain, hwSpec *HardwareDefaults) ([]dpll.PinParentDeviceCtl, error) {
	if hcm.pinCache == nil {
		return nil, nil
	}

	commands := make([]dpll.PinParentDeviceCtl, 0)
	clockID := subsystem.DPLL.ClockIDParsed

	// Process all pin types (inputs and outputs)
	pinGroups := []struct {
		pins    map[string]types.PinConfig
		isInput bool
		name    string
	}{
		{subsystem.DPLL.PhaseInputs, true, "phase inputs"},
		{subsystem.DPLL.PhaseOutputs, false, "phase outputs"},
		{subsystem.DPLL.FrequencyInputs, true, "frequency inputs"},
		{subsystem.DPLL.FrequencyOutputs, false, "frequency outputs"},
	}

	for _, group := range pinGroups {
		for boardLabel, pinCfg := range group.pins {
			cmds := hcm.buildPinFrequencyCommands(clockID, boardLabel, pinCfg, clockChain, hwSpec, group.isInput)
			commands = append(commands, cmds...)
		}
	}

	return commands, nil
}

// buildPinFrequencyCommands builds DPLL commands to set pin frequency (with optional eSync)
// Returns a sequence of commands based on vendor-specific definitions
func (hcm *HardwareConfigManager) buildPinFrequencyCommands(clockID uint64, boardLabel string, pinCfg types.PinConfig, clockChain *types.ClockChain, hwSpec *HardwareDefaults, isInput bool) []dpll.PinParentDeviceCtl {
	pin, found := hcm.pinCache.GetPin(clockID, boardLabel)
	if !found {
		glog.V(2).Infof("Pin %s not found for clock %#x (eSync/frequency config)", boardLabel, clockID)
		return nil
	}

	// Resolve frequency, eSync, and duty cycle configuration
	frequency, esyncFreq, dutyCycle, hasConfig := hcm.resolvePinFrequency(pinCfg, clockChain)
	if !hasConfig {
		return nil
	}

	// If only frequency is set (no eSync), return a single command
	if esyncFreq == 0 {
		if frequency > 0 {
			cmd := dpll.PinParentDeviceCtl{ID: pin.ID, Frequency: &frequency}
			glog.Infof("Pin %s (id=%d, clock=%#x): frequency=%d Hz", boardLabel, pin.ID, clockID, frequency)
			return []dpll.PinParentDeviceCtl{cmd}
		}
		return nil
	}

	// eSync is configured - use vendor-specific command sequence
	glog.Infof("Pin %s (id=%d, clock=%#x): eSync frequency=%d Hz, duty cycle=%d%%, transfer frequency=%d Hz",
		boardLabel, pin.ID, clockID, esyncFreq, dutyCycle, frequency)

	// Get vendor-specific command sequence
	if hwSpec == nil || hwSpec.PinEsyncCommands == nil {
		// No vendor-specific sequence - fallback to single command
		glog.Warningf("No vendor-specific eSync sequence defined, using fallback for pin %s", boardLabel)
		cmd := dpll.PinParentDeviceCtl{
			ID:             pin.ID,
			Frequency:      &frequency,
			EsyncFrequency: &esyncFreq,
		}
		return []dpll.PinParentDeviceCtl{cmd}
	}

	// Select appropriate command sequence (input vs output)
	var cmdSequence []PinESyncCommand
	if isInput {
		cmdSequence = hwSpec.PinEsyncCommands.Inputs
	} else {
		cmdSequence = hwSpec.PinEsyncCommands.Outputs
	}

	if len(cmdSequence) == 0 {
		glog.Warningf("Empty eSync command sequence for pin %s (input=%v), using fallback", boardLabel, isInput)
		cmd := dpll.PinParentDeviceCtl{
			ID:             pin.ID,
			Frequency:      &frequency,
			EsyncFrequency: &esyncFreq,
		}
		return []dpll.PinParentDeviceCtl{cmd}
	}

	// Build command sequence
	commands := make([]dpll.PinParentDeviceCtl, 0, len(cmdSequence))
	for _, cmdDef := range cmdSequence {
		if cmdDef.Type != "DPLLWrite" {
			glog.Warningf("Unsupported eSync command type '%s' for pin %s, skipping", cmdDef.Type, boardLabel)
			continue
		}

		cmd := dpll.PinParentDeviceCtl{ID: pin.ID}

		// Set argument-based fields
		for _, arg := range cmdDef.Arguments {
			switch arg {
			case "frequency":
				cmd.Frequency = &frequency
			case "eSyncFrequency":
				cmd.EsyncFrequency = &esyncFreq
			default:
				glog.Warningf("Unknown argument '%s' in eSync command for pin %s", arg, boardLabel)
			}
		}

		// Set parent device states
		if len(cmdDef.PinParentDevices) > 0 {
			cmd.PinParentCtl = make([]dpll.PinControl, 0, len(cmdDef.PinParentDevices))
			for _, parentCfg := range cmdDef.PinParentDevices {
				// Find matching parent device in pin cache
				for _, parent := range pin.ParentDevice {
					// Match by device index: 0=EEC, 1=PPS
					deviceName := ""
					if parent.Direction == dpll.PinDirectionOutput {
						if len(cmd.PinParentCtl) == 0 {
							deviceName = "EEC"
						} else {
							deviceName = "PPS"
						}
					}

					if strings.EqualFold(deviceName, parentCfg.ParentDevice) {
						state, err := GetPinStateUint32(parentCfg.State)
						if err != nil {
							glog.Warningf("Invalid state '%s' for parent %s: %v", parentCfg.State, parentCfg.ParentDevice, err)
							continue
						}
						pc := dpll.PinControl{
							PinParentID: parent.ParentID,
							State:       &state,
						}
						cmd.PinParentCtl = append(cmd.PinParentCtl, pc)
					}
				}
			}
		}

		commands = append(commands, cmd)
		argStr := strings.Join(cmdDef.Arguments, ", ")
		if argStr == "" {
			argStr = "none"
		}
		glog.Infof("  eSync cmd[%d] for pin %s: %s (args=[%s], parents=%d)",
			len(commands), boardLabel, cmdDef.Description, argStr, len(cmd.PinParentCtl))
	}

	return commands
}

// resolvePinFrequency resolves the pin frequency configuration from PinConfig
// Returns: (transferFrequency, esyncFrequency, dutyCyclePct, hasConfig)
func (hcm *HardwareConfigManager) resolvePinFrequency(pinCfg types.PinConfig, clockChain *types.ClockChain) (uint64, uint64, int64, bool) {
	// If eSyncConfigName is set, resolve from commonDefinitions
	if pinCfg.ESyncConfigName != "" {
		if clockChain == nil || clockChain.CommonDefinitions == nil {
			glog.Warningf("eSync config '%s' referenced but no commonDefinitions", pinCfg.ESyncConfigName)
			return 0, 0, 0, false
		}

		for _, esyncDef := range clockChain.CommonDefinitions.ESyncDefinitions {
			if esyncDef.Name == pinCfg.ESyncConfigName {
				transferFreq := uint64(esyncDef.ESyncConfig.TransferFrequency)
				esyncFreq := uint64(esyncDef.ESyncConfig.EmbeddedSyncFrequency)
				dutyCycle := esyncDef.ESyncConfig.DutyCyclePct

				// Apply defaults
				if esyncFreq == 0 {
					esyncFreq = 1 // Default to 1Hz if not specified
				}
				if dutyCycle == 0 {
					dutyCycle = 25 // Default to 25% if not specified
				}

				glog.Infof("Resolved eSync config '%s': transfer=%d Hz, esync=%d Hz, duty=%d%%",
					esyncDef.Name, transferFreq, esyncFreq, dutyCycle)
				return transferFreq, esyncFreq, dutyCycle, true
			}
		}
		glog.Warningf("eSync config '%s' not found in commonDefinitions", pinCfg.ESyncConfigName)
		return 0, 0, 0, false
	}

	// If frequency is directly specified, use it (no eSync, no duty cycle)
	if pinCfg.Frequency != nil && *pinCfg.Frequency > 0 {
		return uint64(*pinCfg.Frequency), 0, 0, true
	}

	// No frequency configuration
	return 0, 0, 0, false
}

// buildPinPriorityCommand searches the pin cache by clock ID and board label and creates a priority command.
func (hcm *HardwareConfigManager) buildPinPriorityCommand(clockID uint64, boardLabel string, eecPrio, ppsPrio *uint32) (dpll.PinParentDeviceCtl, bool) {
	if hcm.pinCache == nil {
		return dpll.PinParentDeviceCtl{}, false
	}
	pin, found := hcm.pinCache.GetPin(clockID, boardLabel)
	if !found {
		return dpll.PinParentDeviceCtl{}, false
	}
	cmd := dpll.PinParentDeviceCtl{ID: pin.ID, PinParentCtl: make([]dpll.PinControl, 0)}
	for idx, parent := range pin.ParentDevice {
		pc := dpll.PinControl{PinParentID: parent.ParentID}
		if parent.Direction == dpll.PinDirectionInput {
			// Map device index 0->EEC, 1->PPS as in legacy implementation
			if idx == 0 && eecPrio != nil {
				pc.Prio = eecPrio
			} else if idx == 1 && ppsPrio != nil {
				pc.Prio = ppsPrio
			}
		}
		cmd.PinParentCtl = append(cmd.PinParentCtl, pc)
	}
	return cmd, true
}

func (hcm *HardwareConfigManager) buildPinCommandFromDefaults(subsystem types.Subsystem, label string, overrides *PinDefault, eecPrio, ppsPrio *uint32) (dpll.PinParentDeviceCtl, bool) {
	clockID := subsystem.DPLL.ClockIDParsed
	cmd, found := hcm.buildPinPriorityCommand(clockID, label, eecPrio, ppsPrio)
	if !found {
		glog.Warningf("hardware defaults: pin %s not found for clock %x", label, clockID)
		return dpll.PinParentDeviceCtl{}, false
	}

	// Apply state overrides if provided
	if overrides != nil {
		pin, ok := hcm.pinCache.GetPin(clockID, label)
		if ok {
			for idx := range cmd.PinParentCtl {
				parent := cmd.PinParentCtl[idx]
				if idx < len(pin.ParentDevice) && pin.ParentDevice[idx].Direction == dpll.PinDirectionOutput {
					if overrides.EEC != nil && overrides.EEC.State != "" {
						if stateVal, err := GetPinStateUint32(overrides.EEC.State); err == nil {
							parent.State = &stateVal
						}
					}
					if overrides.PPS != nil && overrides.PPS.State != "" {
						if stateVal, err := GetPinStateUint32(overrides.PPS.State); err == nil {
							parent.State = &stateVal
						}
					}
					cmd.PinParentCtl[idx] = parent
				}
			}
		}
	}

	return cmd, true
}

func (hcm *HardwareConfigManager) resolveDpllPinCommands(condition types.Condition) ([]dpll.PinParentDeviceCtl, error) {
	pinCommands := []dpll.PinParentDeviceCtl{}
	for idx, desiredState := range condition.DesiredStates {
		if desiredState.DPLL != nil {
			glog.Infof("      DesiredState[%d]: DPLL boardLabel=%s clockID=%s", idx, desiredState.DPLL.BoardLabel, desiredState.DPLL.ClockID)
			pinCommand, err := hcm.createPinCommandForDPLLDesiredState(*desiredState.DPLL)
			if err != nil {
				return nil, fmt.Errorf("failed to create pin command for DPLL desired state: %w", err)
			}
			pinCommands = append(pinCommands, pinCommand)
		} else {
			glog.Infof("      DesiredState[%d]: no DPLL section", idx)
		}
	}
	return pinCommands, nil
}

func (hcm *HardwareConfigManager) resolveSysFSCommands(condition types.Condition, clockChain *types.ClockChain) ([]SysFSCommand, error) {
	sysFSCommands := []SysFSCommand{}
	for idx, desiredState := range condition.DesiredStates {
		if desiredState.SysFS != nil {
			glog.Infof("      DesiredState[%d]: sysfs path=%s value=%s sourceName=%s", idx, desiredState.SysFS.Path, desiredState.SysFS.Value, desiredState.SysFS.SourceName)
			resolvedPaths, err := hcm.resolveSysFSPath(*desiredState.SysFS, clockChain)
			if err != nil {
				glog.Errorf("      DesiredState[%d]: failed to resolve sysFS path: %v", idx, err)
				return nil, fmt.Errorf("failed to resolve sysFS path: %w", err)
			}
			glog.Infof("        Resolved to %d paths", len(resolvedPaths))
			for _, resolvedPath := range resolvedPaths {
				sysFSCommands = append(sysFSCommands, SysFSCommand{
					Path:        resolvedPath,
					Value:       desiredState.SysFS.Value,
					Description: desiredState.SysFS.Description,
				})
			}
		} else {
			glog.Infof("      DesiredState[%d]: SysFS is nil (DPLL=%v)", idx, desiredState.DPLL != nil)
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
			conditions[ConditionTypeInit] = condition
			continue
		}
		switch condition.Sources[0].ConditionType {
		case ConditionTypeDefault:
			conditions[ConditionTypeDefault] = condition
		case ConditionTypeInit:
			conditions[ConditionTypeInit] = condition
		case ConditionTypeLocked:
			conditions[ConditionTypeLocked] = condition
		case ConditionTypeLost:
			conditions[ConditionTypeLost] = condition
		}
	}
	return conditions
}

func (hcm *HardwareConfigManager) createPinCommandForDPLLDesiredState(dpllDesiredState types.DPLLDesiredState) (dpll.PinParentDeviceCtl, error) {
	pin, found := hcm.pinCache.GetPin(dpllDesiredState.ClockIDParsed, dpllDesiredState.BoardLabel)
	if !found {
		return dpll.PinParentDeviceCtl{}, fmt.Errorf("DPLL pin not found in cache (clock=%#x label=%s)", dpllDesiredState.ClockIDParsed, dpllDesiredState.BoardLabel)
	}

	pinCommand := dpll.PinParentDeviceCtl{
		ID:           pin.ID,
		PinParentCtl: make([]dpll.PinControl, 0),
	}

	for _, parentDevice := range pin.ParentDevice {
		pc := dpll.PinControl{
			PinParentID: parentDevice.ParentID,
		}

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
	defaultConditions := hcm.extractConditionsByType(clockChain.Behavior.Conditions, ConditionTypeDefault)
	initConditions := hcm.extractConditionsByType(clockChain.Behavior.Conditions, ConditionTypeInit)

	glog.Infof("Found %d default conditions and %d init conditions in profile %s",
		len(defaultConditions), len(initConditions), profileName)

	// Apply default conditions first
	for i, condition := range defaultConditions {
		glog.Infof("Applying default condition %d: %s", i+1, condition.Name)
		if err := hcm.applyConditionDesiredStatesByType(condition, ConditionTypeDefault, profileName, enrichedConfig); err != nil {
			return fmt.Errorf("failed to apply default condition '%s': %w", condition.Name, err)
		}
	}

	// Apply init conditions second
	for i, condition := range initConditions {
		glog.Infof("Applying init condition %d: %s", i+1, condition.Name)
		if err := hcm.applyConditionDesiredStatesByType(condition, ConditionTypeInit, profileName, enrichedConfig); err != nil {
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
		if len(condition.Sources) == 0 && conditionType == ConditionTypeInit {
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

// applyConditionDesiredStatesByType applies cached commands for a condition using the condition type as the lookup key
func (hcm *HardwareConfigManager) applyConditionDesiredStatesByType(condition types.Condition, conditionType, profileName string, enrichedConfig *enrichedHardwareConfig) error {
	glog.Infof("Applying %d desired states for condition '%s' (type: %s) in profile %s", len(condition.DesiredStates), condition.Name, conditionType, profileName)

	sysFSCommands := enrichedConfig.sysFSCommands[conditionType]
	glog.Infof("  Condition '%s': cached sysfs commands=%d", condition.Name, len(sysFSCommands))
	if len(sysFSCommands) > 0 {
		if err := hcm.applyCachedSysFSCommands(condition.Name, profileName, sysFSCommands); err != nil {
			return fmt.Errorf("failed to apply cached sysFS commands: %w", err)
		}
	}

	pinCommands := enrichedConfig.dpllPinCommands[conditionType]
	glog.Infof("  Condition '%s': cached DPLL commands=%d", condition.Name, len(pinCommands))
	if len(pinCommands) > 0 {
		if err := hcm.applyDpllPinCommands(profileName, condition.Name, pinCommands); err != nil {
			return fmt.Errorf("failed to apply cached DPLL commands for condition '%s': %w", condition.Name, err)
		}
	}

	return nil
}

// applyStructureDefaults extracts and applies static, hardware-specific defaults for a given hardware config
func (hcm *HardwareConfigManager) applyStructureDefaults(enrichedConfig *enrichedHardwareConfig, profileName string) error {
	if enrichedConfig.Spec.Profile.ClockChain == nil {
		return nil
	}

	if len(enrichedConfig.structureSysFSCommands) > 0 {
		if err := hcm.applyCachedSysFSCommands("structure-defaults", profileName, enrichedConfig.structureSysFSCommands); err != nil {
			return fmt.Errorf("failed to apply structure sysFS defaults: %w", err)
		}
	}

	if len(enrichedConfig.structurePinCommands) > 0 {
		if err := hcm.applyDpllPinCommands(profileName, "structure-defaults", enrichedConfig.structurePinCommands); err != nil {
			return fmt.Errorf("failed to apply structure DPLL defaults: %w", err)
		}
	}

	for _, subsystem := range enrichedConfig.Spec.Profile.ClockChain.Structure {
		glog.Infof("  Subsystem: %s (Hardware: %s, Clock ID: %s)",
			subsystem.Name, subsystem.HardwareSpecificDefinitions, subsystem.DPLL.ClockID)
	}

	return nil
}

func (hcm *HardwareConfigManager) applyBehaviorConditions(enrichedConfig *enrichedHardwareConfig, profileName string) error {
	if enrichedConfig.Spec.Profile.ClockChain == nil {
		return nil
	}
	return hcm.applyDefaultAndInitConditions(enrichedConfig.Spec.Profile.ClockChain, profileName, enrichedConfig)
}

func (hcm *HardwareConfigManager) applyCachedSysFSCommands(conditionName, profileName string, commands []SysFSCommand) error {
	glog.Infof("  Applying %d sysFS commands for '%s' in profile %s", len(commands), conditionName, profileName)

	for i, cmd := range commands {
		glog.Infof("    sysfs[%d]: path=%s value=%s desc=%s", i+1, cmd.Path, cmd.Value, cmd.Description)
		if err := hcm.writeSysFSValue(cmd.Path, cmd.Value); err != nil {
			return fmt.Errorf("failed to write sysfs value '%s' to '%s': %w", cmd.Value, cmd.Path, err)
		}
	}

	return nil
}

func (hcm *HardwareConfigManager) applyDpllPinCommands(profileName, context string, commands []dpll.PinParentDeviceCtl) error {
	if len(commands) == 0 {
		glog.Infof("  No DPLL pin commands for %s in profile %s", context, profileName)
		return nil
	}

	glog.Infof("  Applying %d DPLL pin commands for %s in profile %s", len(commands), context, profileName)
	for i, c := range commands {
		glog.Infof("    pin[%d]: id=%d parents=%d", i+1, c.ID, len(c.PinParentCtl))
	}

	if err := hcm.pinApplier(commands); err != nil {
		return fmt.Errorf("dpll pin apply (%s): %w", context, err)
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
// If sourceName is empty, it uses the first available PTP source.
func (hcm *HardwareConfigManager) getInterfaceNameFromSources(sourceName string, clockChain *types.ClockChain) (*string, error) {
	if clockChain.Behavior == nil {
		return nil, fmt.Errorf("no behavior section found in clock chain")
	}
	upstreamPort := ""
	// Find the corresponding subsystem in the structure section using the resolved clock ID
	if clockChain.Structure == nil {
		return nil, fmt.Errorf("no structure section found in clock chain")
	}

	// If sourceName is empty, use the first available PTP source
	if sourceName == "" {
		for _, source := range clockChain.Behavior.Sources {
			if source.SourceType == "ptpTimeReceiver" && len(source.PTPTimeReceivers) > 0 {
				upstreamPort = source.PTPTimeReceivers[0]
				break
			}
		}
		if upstreamPort == "" {
			return nil, fmt.Errorf("no PTP sources with ptpTimeReceivers found")
		}
	} else {
		// Find the named source
		for _, source := range clockChain.Behavior.Sources {
			if source.Name == sourceName {
				if len(source.PTPTimeReceivers) == 0 {
					return nil, fmt.Errorf("source %s has no ptpTimeReceivers", sourceName)
				}
				upstreamPort = source.PTPTimeReceivers[0]
				break
			}
		}
		if upstreamPort == "" {
			return nil, fmt.Errorf("source %s not found", sourceName)
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

	return nil, fmt.Errorf("no default port found for port %s", upstreamPort)
}

// writeSysFSValue writes a value to a sysFS path
func (hcm *HardwareConfigManager) writeSysFSValue(path, value string) error {
	return hcm.sysfsWriter(path, value)
}

func (hcm *HardwareConfigManager) overrideExecutors(pin func([]dpll.PinParentDeviceCtl) error, sysfs func(string, string) error) {
	if pin != nil {
		hcm.pinApplier = pin
	}
	if sysfs != nil {
		hcm.sysfsWriter = sysfs
	}
}

func (hcm *HardwareConfigManager) resetExecutors() {
	hcm.pinApplier = func(cmds []dpll.PinParentDeviceCtl) error { return BatchPinSet(&cmds) }
	hcm.sysfsWriter = func(path, value string) error { return os.WriteFile(path, []byte(value), 0o644) }
}

// ApplyConditionForProfile applies cached commands for a specific condition (e.g., "locked", "lost") for a PTP profile
func (hcm *HardwareConfigManager) ApplyConditionForProfile(nodeProfile *ptpv1.PtpProfile, conditionType string) error {
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

	if len(relevantConfigs) == 0 {
		glog.Infof("No hardware configurations found for PTP profile %s condition %s", *nodeProfile.Name, conditionType)
		return nil
	}

	glog.Infof("Applying condition '%s' for %d hardware configurations for PTP profile %s",
		conditionType, len(relevantConfigs), *nodeProfile.Name)

	for _, enrichedConfig := range relevantConfigs {
		profileName := "unnamed"
		if enrichedConfig.Spec.Profile.Name != nil {
			profileName = *enrichedConfig.Spec.Profile.Name
		}

		// Apply cached sysFS commands for this condition
		sysFSCommands := enrichedConfig.sysFSCommands[conditionType]
		glog.Infof("  Profile '%s' condition '%s': cached sysfs commands=%d", profileName, conditionType, len(sysFSCommands))
		if len(sysFSCommands) > 0 {
			if err := hcm.applyCachedSysFSCommands(conditionType, profileName, sysFSCommands); err != nil {
				return fmt.Errorf("failed to apply cached sysFS commands for condition '%s': %w", conditionType, err)
			}
		}

		// Apply cached DPLL commands for this condition
		pinCommands := enrichedConfig.dpllPinCommands[conditionType]
		glog.Infof("  Profile '%s' condition '%s': cached DPLL commands=%d", profileName, conditionType, len(pinCommands))
		if len(pinCommands) > 0 {
			if err := hcm.applyDpllPinCommands(profileName, conditionType, pinCommands); err != nil {
				return fmt.Errorf("failed to apply cached DPLL commands for condition '%s': %w", conditionType, err)
			}
		}
	}

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

func (hcm *HardwareConfigManager) setHardwareConfigs(hwConfigs []enrichedHardwareConfig) {
	hcm.mu.Lock()
	defer hcm.mu.Unlock()
	hcm.hardwareConfigs = hwConfigs
	if !hcm.ready {
		hcm.ready = true
		if hcm.cond != nil {
			hcm.cond.Broadcast()
		}
	}
}

// WaitForHardwareConfigs waits for hardware configurations to be ready within the specified timeout
func (hcm *HardwareConfigManager) WaitForHardwareConfigs(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	hcm.mu.Lock()
	defer hcm.mu.Unlock()
	for !hcm.ready {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		if hcm.cond == nil {
			return hcm.ready
		}
		hcm.cond.Wait()
	}
	return true
}

// HasReadyHardwareConfigs returns true if hardware configurations are ready
func (hcm *HardwareConfigManager) HasReadyHardwareConfigs() bool {
	hcm.mu.RLock()
	defer hcm.mu.RUnlock()
	return hcm.ready
}

// HasHardwareConfigs returns true if any hardware configurations are loaded
func (hcm *HardwareConfigManager) HasHardwareConfigs() bool {
	hcm.mu.RLock()
	defer hcm.mu.RUnlock()
	return len(hcm.hardwareConfigs) > 0
}

// ReadyHardwareConfigForProfile returns true if hardware configurations are ready for the specified profile
func (hcm *HardwareConfigManager) ReadyHardwareConfigForProfile(name string) bool {
	hcm.mu.RLock()
	defer hcm.mu.RUnlock()
	if !hcm.ready {
		return false
	}
	for _, hw := range hcm.hardwareConfigs {
		if hw.Spec.RelatedPtpProfileName == name {
			return true
		}
	}
	return false
}

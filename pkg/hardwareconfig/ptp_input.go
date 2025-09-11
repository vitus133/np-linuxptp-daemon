package hardwareconfig

import (
	"regexp"
	"strings"

	"github.com/golang/glog"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/types"
)

// PTPStateDetector monitors PTP state changes based on hardware config behavior rules
type PTPStateDetector struct {
	hcm *HardwareConfigManager

	// Performance optimizations - cached lookups
	portToSources  map[string][]string // port -> list of source names that monitor it
	monitoredPorts map[string]bool     // set of all monitored ports
	lockedRegex    *regexp.Regexp      // compiled regex for locked transitions
	lostRegex      *regexp.Regexp      // compiled regex for lost transitions

	// Ultra-fast direct regex for extracting interface and event from PTP4L state change logs
	// This bypasses the generic parser entirely for maximum performance
	stateChangeRegex *regexp.Regexp // extracts port_name and event from state change logs
}

// NewPTPStateDetector creates a new PTP state detector
func NewPTPStateDetector(hcm *HardwareConfigManager) *PTPStateDetector {
	psd := &PTPStateDetector{
		hcm: hcm,
	}

	// Initialize caches and compile regexes for performance
	psd.buildCachesAndRegexes()

	// Create ultra-fast regex for direct PTP4L state change parsing
	// This regex extracts the port name and event from PTP4L state change logs
	// Pattern: ptp4l[timestamp]: [config] port id (port_name): event_text
	psd.stateChangeRegex = regexp.MustCompile(`^ptp4l\[\d+\.?\d*\]:\s+\[.*?\]\s+port\s+\d+(?:\s+\(([\d\w]+)\))?:\s+(.+)$`)

	return psd
}

// extractPTP4LStateChangeDirect extracts port name and event from PTP4L log line using direct regex
// This bypasses the generic parser for maximum performance
func (psd *PTPStateDetector) extractPTP4LStateChangeDirect(logLine string) (portName string, event string, isStateChange bool) {
	// Use direct regex matching - much faster than generic parser
	matches := psd.stateChangeRegex.FindStringSubmatch(logLine)
	if len(matches) < 3 {
		return "", "", false
	}

	portName = matches[1] // captured port name (e.g., "ens4f1")
	event = matches[2]    // captured event text (e.g., "UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED")

	return portName, event, true
}

// buildCachesAndRegexes builds performance caches and compiles regexes for fast lookups
func (psd *PTPStateDetector) buildCachesAndRegexes() {
	// Initialize maps
	psd.portToSources = make(map[string][]string)
	psd.monitoredPorts = make(map[string]bool)

	// Build caches from hardware configs
	for _, hwConfig := range psd.hcm.hardwareConfigs {
		if hwConfig.Spec.Profile.ClockChain != nil && hwConfig.Spec.Profile.ClockChain.Behavior != nil {
			for _, source := range hwConfig.Spec.Profile.ClockChain.Behavior.Sources {
				if source.SourceType == "ptpTimeReceiver" {
					for _, portName := range source.PTPTimeReceivers {
						// Add to monitored ports set
						psd.monitoredPorts[portName] = true

						// Add to port-to-sources mapping
						psd.portToSources[portName] = append(psd.portToSources[portName], source.Name)
					}
				}
			}
		}
	}

	// Compile regexes for state transition detection
	// Locked conditions: "to slave" transition
	psd.lockedRegex = regexp.MustCompile(`(?i)to slave`)

	// Lost conditions: various slave state losses
	psd.lostRegex = regexp.MustCompile(`(?i)(slave to|fault_detected|announce_receipt_timeout|sync_receipt_timeout|slave.*(?:fault|timeout|disconnected))`)
}

// rebuildCaches rebuilds the performance caches when hardware configs change
func (psd *PTPStateDetector) rebuildCaches() {
	psd.buildCachesAndRegexes()
}

// StateChangeHandler is a function called when a state change condition is detected
type StateChangeHandler func(sourceName string, conditionType string, portName string)

// ProcessPTP4LLog processes a ptp4l log line and detects state changes (ultra-optimized version)
// This bypasses the generic parser entirely for maximum performance
func (psd *PTPStateDetector) ProcessPTP4LLog(logLine string, handler StateChangeHandler) {
	glog.Infof("Processing PTP4L log: %s", logLine)

	// Ultra-fast direct regex extraction - bypasses entire parser overhead
	portName, event, isStateChange := psd.extractPTP4LStateChangeDirect(logLine)
	if !isStateChange {
		// Not a state change log line, skip
		return
	}

	glog.Infof("Direct regex extracted: port=%s, event=%s", portName, event)

	// Check if this port is monitored by any hardware config (O(1) lookup)
	if portName == "" {
		glog.Infof("No interface name in PTP event")
		return
	}

	// Fast O(1) check if port is monitored
	if !psd.monitoredPorts[portName] {
		// Port not monitored, skip processing
		return
	}

	// Get sources that monitor this port (O(1) lookup)
	sources, exists := psd.portToSources[portName]
	if !exists || len(sources) == 0 {
		return
	}

	// Detect condition type using compiled regexes (much faster than string.Contains)
	conditionType := psd.determineConditionTypeOptimized(event)
	if conditionType == "" {
		return
	}

	// Call handler for each source that monitors this port
	for _, sourceName := range sources {
		glog.Infof("Detected %s condition for port %s in source %s", conditionType, portName, sourceName)
		if handler != nil {
			handler(sourceName, conditionType, portName)
		}
	}
}

// determineConditionTypeOptimized uses compiled regexes for fast state transition detection
func (psd *PTPStateDetector) determineConditionTypeOptimized(event string) string {
	eventLower := strings.ToLower(event)

	// Check for locked conditions using compiled regex
	if psd.lockedRegex.MatchString(eventLower) {
		// Ensure it's not a "slave to slave" transition
		if !strings.Contains(eventLower, "slave to slave") {
			return "locked"
		}
	}

	// Check for lost conditions using compiled regex
	if psd.lostRegex.MatchString(eventLower) {
		// Exclude "slave to slave" transitions from lost conditions
		if strings.Contains(eventLower, "slave to slave") {
			return ""
		}
		// Don't consider MASTER to MASTER transitions as lost even with timeout
		if strings.Contains(eventLower, "master to master") {
			return ""
		}
		return "lost"
	}

	return "" // No condition detected
}

// GetMonitoredPorts returns all ports that are being monitored by hardware configs (optimized)
func (psd *PTPStateDetector) GetMonitoredPorts() []string {
	// Return cached result for O(1) performance
	ports := make([]string, 0, len(psd.monitoredPorts))
	for port := range psd.monitoredPorts {
		ports = append(ports, port)
	}
	return ports
}

// GetBehaviorRules returns all behavior rules from hardware configs
func (psd *PTPStateDetector) GetBehaviorRules() []types.Condition {
	var allConditions []types.Condition

	for _, hwConfig := range psd.hcm.hardwareConfigs {
		if hwConfig.Spec.Profile.ClockChain != nil && hwConfig.Spec.Profile.ClockChain.Behavior != nil {
			allConditions = append(allConditions, hwConfig.Spec.Profile.ClockChain.Behavior.Conditions...)
		}
	}

	return allConditions
}

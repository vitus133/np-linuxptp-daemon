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
	// Universal pattern handles both formats:
	// 1. [ptp4l.config:level] port id (port_name): event_text
	// 2. ptp4l[timestamp]: [ptp4l.config:level] port id (port_name): event_text
	psd.stateChangeRegex = regexp.MustCompile(`^(?:ptp4l\[[^\]]+\]:\s+)?\[ptp4l[^\]]*\]\s+port\s+\d+\s*\(([^)]+)\):\s+(.+)$`)
	glog.Infof("stateChangeRegex: %v", psd.stateChangeRegex)

	return psd
}

// DetectStateChange processes a PTP4L log line and returns state change information
// Returns "locked", "lost", or "" (empty string for no relevant state change)
// Only returns a result if the interface is in the monitored sources list
// TODO: replace by pmc  state monitor
func (psd *PTPStateDetector) DetectStateChange(logLine string) string {
	// Step 1: Simple string-based parsing to avoid regex issues
	// Look for PTP4L log pattern: "] port N (interface): event"

	// Find the port pattern
	portIndex := strings.Index(logLine, "] port ")
	if portIndex == -1 {
		return "" // Not a PTP4L state change log line
	}

	// Find the interface name in parentheses after "port N"
	parenStart := strings.Index(logLine[portIndex:], "(")
	if parenStart == -1 {
		return "" // No interface name found
	}
	parenStart += portIndex

	parenEnd := strings.Index(logLine[parenStart:], ")")
	if parenEnd == -1 {
		return "" // No closing parenthesis found
	}
	parenEnd += parenStart

	// Extract port name
	portName := logLine[parenStart+1 : parenEnd]
	if portName == "" {
		return "" // Empty port name
	}

	// Find the event part after ": "
	colonIndex := strings.Index(logLine[parenEnd:], ": ")
	if colonIndex == -1 {
		return "" // No event separator found
	}
	colonIndex += parenEnd

	event := logLine[colonIndex+2:] // Skip ": "
	if event == "" {
		return "" // Empty event
	}

	// Step 2: Fast O(1) check if port is monitored (single map lookup)
	if !psd.monitoredPorts[portName] {
		return "" // Port not in monitored sources, skip
	}

	// Step 3: Simple string-based condition detection
	eventLower := strings.ToLower(event)

	// Check for locked conditions: "to slave on master_clock_selected"
	if strings.Contains(eventLower, "to slave") && strings.Contains(eventLower, "master_clock_selected") {
		return "locked"
	}

	// Check for lost conditions: various failure patterns
	if strings.Contains(eventLower, "slave to") ||
		strings.Contains(eventLower, "fault") ||
		strings.Contains(eventLower, "timeout") {
		return "lost"
	}

	return "" // No relevant condition detected
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

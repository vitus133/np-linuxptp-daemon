package daemon

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	v1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"

	"github.com/golang/glog"

	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/alias"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/event"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/ipc"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/parser"
	parserconstants "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/parser/constants"
)

func convertParserRoleToMetricsRole(role parserconstants.PTPPortRole) ptpPortRole {
	switch role {
	case parserconstants.PortRoleSlave:
		return SLAVE
	case parserconstants.PortRoleMaster:
		return MASTER
	case parserconstants.PortRolePassive:
		return PASSIVE
	case parserconstants.PortRoleFaulty:
		return FAULTY
	case parserconstants.PortRoleListening:
		return LISTENING
	default:
		return UNKNOWN
	}
}

func convertParserClockStateEventPTPState(clockState parserconstants.ClockState) event.PTPState {
	switch clockState {
	case parserconstants.ClockStateFreeRun:
		return event.PTP_FREERUN
	case parserconstants.ClockStateLocked:
		return event.PTP_LOCKED
	case parserconstants.ClockStateHoldover:
		return event.PTP_HOLDOVER
	}
	return event.PTP_NOTSET
}

func getParser(processName string) parser.MetricsExtractor {
	switch processName {
	case ptp4lProcessName:
		return parser.NewPTP4LExtractor()
	case phc2sysProcessName:
		return parser.NewPhc2SysExtractor()
	case ts2phcProcessName:
		return parser.NewTS2PHCExtractor()
	default:
		glog.Errorf("No parser available for process: %s", processName)
		return nil
	}
}

// processWithParser uses the new parser-based approach for processes with parsers
func processWithParser(process *ptpProcess, output string) {
	// Extract metrics and events using the parser
	metrics, ptpEvent, err := process.logParser.Extract(output)
	if err != nil {
		glog.Errorf("Failed to extract metrics from %s output: %v", process.name, err)
		return
	}

	process.hasCollectedMetrics = true
	// Process metrics if available
	if metrics != nil {
		process.offset = metrics.Offset
		processParsedMetrics(process, metrics)
	}

	// Process PTP events if available
	if ptpEvent != nil {
		processParsedEvent(process, ptpEvent)
	}
}

func processParsedMetrics(process *ptpProcess, ptpMetrics *parser.Metrics) {
	// Convert interface from possible clock id
	iface := process.ifaces.GetPhcID2IFace(ptpMetrics.Iface)
	if iface != clockRealTime {
		iface = alias.GetAlias(iface)
	}

	// Update PTP metrics using the parsed data
	updatePTPMetrics(ptpMetrics.Source, process.name, iface, ptpMetrics.Offset, ptpMetrics.MaxOffset, ptpMetrics.FreqAdj, ptpMetrics.Delay)

	// Update clock state metrics if available
	if ptpMetrics.ClockState != "" {
		updateClockStateMetrics(process.name, iface, string(ptpMetrics.ClockState))
	}

	configName := strings.Replace(strings.Replace(process.messageTag, "]", "", 1), "[", "", 1)
	if configName != "" {
		configName = strings.Split(configName, MessageTagSuffixSeperator)[0]
	}

	// Handle master offset source tracking
	if ptpMetrics.Source == "master" && configName != "" {
		masterOffsetSource.set(configName, process.name)
	}

	// if state is HOLDOVER do not update the state
	state := convertParserClockStateEventPTPState(ptpMetrics.ClockState)

	// transition to FREERUN if offset is outside configured thresholds
	if shouldFreeRun(state, ptpMetrics.Offset, process.ptpClockThreshold) {
		state = event.PTP_FREERUN
	}

	switch process.name {
	case ptp4lProcessName:
		if ptpMetrics.Iface != "" && configName != "" {
			masterOffsetIface.set(configName, ptpMetrics.Iface)
		}
		if ptpMetrics.Source == "master" && process.dn != nil {
			process.dn.HandleDelayedPhc2sysStartup(process.name, ptpMetrics.Offset, process.nodeProfile.Name)
		}
		process.sendPtp4lOffsetEvent()
	case ts2phcProcessName:
		if process.dn != nil {
			process.dn.HandleDelayedPhc2sysStartup(process.name, ptpMetrics.Offset, process.nodeProfile.Name)
		}
		// Send event for ts2phc
		eventSource := process.ifaces.GetEventSource(process.ifaces.GetPhcID2IFace(ptpMetrics.Iface))
		values := map[event.ValueType]interface{}{
			event.OFFSET: int64(ptpMetrics.Offset),
		}
		if eventSource == event.GNSS {
			values[event.NMEA_STATUS] = int64(1)
		}
		select {
		case process.eventCh <- event.Event{
			Source:     event.TS2PHC,
			CfgName:    configName,
			IFace:      ptpMetrics.Iface, // use real interface name in event/log
			ClockType:  process.clockType,
			Time:       time.Now().UnixMilli(),
			WriteToLog: eventSource == event.GNSS,
			Reset:      false,
			Data: &event.PTPData{
				State:  state,
				Values: values,
			},
		}:
		default:
		}
	case phc2sysProcessName:
		if ptpMetrics.Iface != clockRealTime || ptpMetrics.ClockState == "" {
			return
		}
		if ptpMetrics.Source == "sys" {
			// CLOCK_REALTIME is the source, not the sink: it is not PTP-disciplined.
			process.tBCAttributes.sysOffsetInSyncCount = 0
			process.tBCAttributes.sysOffsetOutOfSyncCount = 0
			if process.tBCAttributes.sysOffsetState != event.PTP_FREERUN {
				process.tBCAttributes.sysOffsetState = event.PTP_FREERUN
				process.publishOSClockState(event.PTP_FREERUN, ptpMetrics.Offset)
			}
			return
		}
		if ptpMetrics.Source != "phc" {
			return
		}
		if osClockState, changed := process.updateSysOffsetState(ptpMetrics.Offset); changed {
			process.publishOSClockState(osClockState, ptpMetrics.Offset)
		}
	}
}

func (p *ptpProcess) publishOSClockState(state event.PTPState, offset float64) {
	if p.dn == nil || p.dn.ipcCache == nil || p.nodeProfile.Name == nil {
		return
	}
	p.dn.ipcCache.Send(ipc.Message{
		Type:    ipc.TypeOSClockState,
		Profile: *p.nodeProfile.Name,
		IFace:   clockRealTime,
		Values:  ipc.StateValue{State: ipcState(state), Offset: int64(offset)},
	})
}

func (p *ptpProcess) configureSysOffsetFilter(settings map[string]string, defaultThreshold int64) error {
	p.tBCAttributes.sysOffsetSamples = defaultSysOffsetSamples
	p.tBCAttributes.sysOffsetInSyncThreshold = float64(defaultThreshold)
	p.tBCAttributes.sysOffsetOutOfSyncThreshold = float64(defaultThreshold)
	p.tBCAttributes.sysOffsetInSyncConfigured = true
	p.tBCAttributes.sysOffsetOutOfSyncConfigured = true
	if value, ok := settings[sysOffsetSamplesKey]; ok {
		samples, err := strconv.Atoi(value)
		if err != nil || samples <= 0 {
			return fmt.Errorf("invalid %s %q: must be a positive integer", sysOffsetSamplesKey, value)
		}
		p.tBCAttributes.sysOffsetSamples = samples
	}
	if value, ok := settings[sysOffsetInSyncThresholdKey]; ok {
		threshold, err := strconv.ParseFloat(value, 64)
		if err != nil || threshold < 0 {
			return fmt.Errorf("invalid %s %q: must be a non-negative number", sysOffsetInSyncThresholdKey, value)
		}
		p.tBCAttributes.sysOffsetInSyncThreshold = threshold
		p.tBCAttributes.sysOffsetInSyncConfigured = true
	}
	if value, ok := settings[sysOffsetOutOfSyncThresholdKey]; ok {
		threshold, err := strconv.ParseFloat(value, 64)
		if err != nil || threshold < 0 {
			return fmt.Errorf("invalid %s %q: must be a non-negative number", sysOffsetOutOfSyncThresholdKey, value)
		}
		p.tBCAttributes.sysOffsetOutOfSyncThreshold = threshold
		p.tBCAttributes.sysOffsetOutOfSyncConfigured = true
	}
	return nil
}

func (p *ptpProcess) updateSysOffsetState(offset float64) (event.PTPState, bool) {
	t := &p.tBCAttributes
	if !t.sysOffsetInSyncConfigured && !t.sysOffsetOutOfSyncConfigured {
		return event.PTP_NOTSET, false
	}

	absOffset := math.Abs(offset)
	if t.sysOffsetInSyncConfigured && absOffset <= t.sysOffsetInSyncThreshold {
		t.sysOffsetInSyncCount++
		t.sysOffsetOutOfSyncCount = 0
		if t.sysOffsetInSyncCount >= t.sysOffsetSamples && t.sysOffsetState != event.PTP_LOCKED {
			t.sysOffsetState = event.PTP_LOCKED
			return t.sysOffsetState, true
		}
		return t.sysOffsetState, false
	}
	if t.sysOffsetOutOfSyncConfigured && absOffset > t.sysOffsetOutOfSyncThreshold {
		t.sysOffsetOutOfSyncCount++
		t.sysOffsetInSyncCount = 0
		if t.sysOffsetOutOfSyncCount >= t.sysOffsetSamples && t.sysOffsetState != event.PTP_FREERUN {
			t.sysOffsetState = event.PTP_FREERUN
			return t.sysOffsetState, true
		}
		return t.sysOffsetState, false
	}
	t.sysOffsetInSyncCount = 0
	t.sysOffsetOutOfSyncCount = 0
	return t.sysOffsetState, false
}

func ipcState(state event.PTPState) string {
	if state == event.PTP_LOCKED {
		return ipc.StateLocked
	}
	return ipc.StateFreerun
}

// processParsedEvent handles PTP events extracted by the parser
func processParsedEvent(process *ptpProcess, ptpEvent *parser.PTPEvent) {
	if process.name != ptp4lProcessName {
		return
	}

	// Update interface role metrics
	if ptpEvent.PortID > 0 && len(process.ifaces) >= ptpEvent.PortID-1 {
		configName := strings.Replace(strings.Replace(process.messageTag, "]", "", 1), "[", "", 1)
		configName = strings.Split(configName, MessageTagSuffixSeperator)[0]

		interfaceName := process.ifaces[ptpEvent.PortID-1].Name
		role := convertParserRoleToMetricsRole(ptpEvent.Role)
		UpdateInterfaceRoleMetrics(process.name, interfaceName, role)
		process.handler.SetPortRole(configName, interfaceName, ptpEvent)

		if configName == "" {
			return
		}

		// Handle role-specific logic
		switch ptpEvent.Role {
		case parserconstants.PortRoleSlave:
			masterOffsetIface.set(configName, interfaceName)
			slaveIface.set(configName, interfaceName)
		case parserconstants.PortRoleFaulty:
			isFaulty := slaveIface.isFaulty(configName, interfaceName)
			sourceIsPtp4l := masterOffsetSource.get(configName) == ptp4lProcessName
			if isFaulty && sourceIsPtp4l {
				// Set fault metrics and clear slave & master offset interfaces
				updatePTPMetrics(master, process.name, masterOffsetIface.get(configName).alias, faultyOffset, faultyOffset, 0, 0)
				updatePTPMetrics(phc, phc2sysProcessName, clockRealTime, faultyOffset, faultyOffset, 0, 0)
				updateClockStateMetrics(process.name, masterOffsetIface.get(configName).alias, FREERUN)
				masterOffsetIface.set(configName, "")
				slaveIface.set(configName, "")
			}
		}
	}
}

// shouldFreeRun returns true if we’re not already in HOLDOVER or FREERUN
// and the current offset breaches maxOffsetThreshold: abs(offset) >= maxOffsetThreshold.
func shouldFreeRun(
	currentState event.PTPState,
	rawOffset float64,
	th *v1.PtpClockThreshold,
) bool {
	if currentState == event.PTP_HOLDOVER || currentState == event.PTP_FREERUN {
		return false
	}

	return math.Abs(rawOffset) >= float64(th.MaxOffsetThreshold)
}

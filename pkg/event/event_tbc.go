package event

import (
	"fmt"
	"math"
	"time"

	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/pmc"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/protocol"

	fbprotocol "github.com/facebook/time/ptp/protocol"
	"github.com/golang/glog"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/leap"
)

const (
	// LeadingSource is a key for passing the leading source
	LeadingSource ValueType = "LeadingSource"
	// InSyncConditionThreshold is a key for passing the in-sync condition threshold
	InSyncConditionThreshold ValueType = "in-sync-th"
	// InSyncConditionTimes is a key for passing the in-sync condition counter maximum
	InSyncConditionTimes ValueType = "in-sync-times"
	// ToFreeRunThreshold is a key for passing the threshold for the to-free-run condition
	ToFreeRunThreshold ValueType = "free-run_th"
	// ControlledPortsConfig is a key for passing the controlled ports config file name
	// to the controlling instance,
	ControlledPortsConfig ValueType = "controlled-ports-config"
	// ParentDataSet is a key for passing the ParentDS
	ParentDataSet ValueType = "parent-ds"
	// CurrentDataSet is a key for passing the CurrentDS
	CurrentDataSet ValueType = "current-ds"
	// ClockIDKey is a key for passing the clock ID
	ClockIDKey ValueType = "clock-id"
	//TimePropertiesDataSet is a key for passing the TimePropertiesDS
	TimePropertiesDataSet ValueType = "time-props"
	// MaxInSpecOffset is the key for passing the MaxInSpecOffset
	MaxInSpecOffset ValueType = "max-in-spec"
	// FaultyPhaseOffset is a value assigned to the phase offset when free-running
	FaultyPhaseOffset int64 = 99999999999
)

// LeadingClockParams ... leading clock parameters includes state
// and configuration of the system leading clock. There is only
// one leading clock in the system. The leading clock is the clock that
// receives phase, frequency and ToD synchronization from an external source.
// Currently used for T-BC only
type LeadingClockParams struct {
	upstreamTimeProperties        *protocol.TimePropertiesDS
	upstreamParentDataSet         *protocol.ParentDataSet
	upstreamCurrentDSStepsRemoved uint16
	downstreamTimeProperties      *protocol.TimePropertiesDS
	downstreamParentDataSet       *protocol.ParentDataSet
	leadingInterface              string
	controlledPortsConfig         string
	inSyncConditionThreshold      int
	inSyncConditionTimes          int
	toFreeRunThreshold            int
	MaxInSpecOffset               uint64
	lastInSpec                    bool
	inSyncThresholdCounter        int
	clockID                       string
}

func (e *EventHandler) updateBCState(event EventChannel) clockSyncState {
	cfgName := event.CfgName
	dpllState := PTP_NOTSET
	ts2phcState := PTP_FREERUN
	// For internal data announces, only update the downstream data on class change
	// For External GM data announces in the locked state, update whenever any of the
	// information elements change
	updateDownstreamData := false

	syncSrcLost := e.isSourceLost(cfgName)
	leadingInterface := e.getLeadingInterfaceBC()
	if leadingInterface == LEADING_INTERFACE_UNKNOWN {
		glog.Infof("Leading interface is not yet identified, clock state reporting delayed.")
		return clockSyncState{leadingIFace: leadingInterface}
	}

	if _, ok := e.clkSyncState[cfgName]; !ok {
		glog.Info("initializing e.clkSyncState for ", cfgName)
		e.clkSyncState[cfgName] = &clockSyncState{
			state:         PTP_FREERUN,
			clockClass:    protocol.ClockClassUninitialized,
			clockAccuracy: fbprotocol.ClockAccuracyUnknown,
			sourceLost:    syncSrcLost,
			leadingIFace:  leadingInterface,
		}
	}
	// glog.Infof("cfgName %s syncSourceLost %t, leadingIface %s e.clkSyncState %++v", cfgName, syncSrcLost, leadingInterface, e.clkSyncState)
	e.clkSyncState[cfgName].sourceLost = syncSrcLost
	e.clkSyncState[cfgName].leadingIFace = leadingInterface
	if data, ok := e.data[cfgName]; ok {
		for _, d := range data {
			switch d.ProcessName {
			case DPLL:
				dpllState = d.State
			case TS2PHCProcessName:
				ts2phcState = d.State
			case PTP4lProcessName:
			}
		}
	} else {
		glog.Info("initializing default e.clkSyncState for ", cfgName)
		e.clkSyncState[cfgName].state = PTP_FREERUN
		e.clkSyncState[cfgName].clockClass = protocol.ClockClassFreerun
		e.clkSyncState[cfgName].clockAccuracy = fbprotocol.ClockAccuracyUnknown
		e.clkSyncState[cfgName].lastLoggedTime = time.Now().Unix()
		e.clkSyncState[cfgName].leadingIFace = leadingInterface
		e.clkSyncState[cfgName].clkLog = fmt.Sprintf("%s[%d]:[%s] %s T-BC-STATUS %s\n", BC, e.clkSyncState[cfgName].lastLoggedTime, cfgName, leadingInterface, e.clkSyncState[cfgName].state)
		return *e.clkSyncState[cfgName]
	}
	glog.Info("current BC state: ", e.clkSyncState[cfgName].state)
	switch e.clkSyncState[cfgName].state {
	case PTP_NOTSET, PTP_FREERUN:
		if e.inSyncCondition(cfgName) && !e.isSourceLostBC(cfgName) {
			e.clkSyncState[cfgName].state = PTP_LOCKED
			glog.Info("BC FSM: FREERUN to LOCKED")
			updateDownstreamData = true
		}
	case PTP_LOCKED:
		if e.freeRunCondition(cfgName) {
			e.clkSyncState[cfgName].state = PTP_FREERUN
			e.clkSyncState[cfgName].clockClass = protocol.ClockClassFreerun
			glog.Info("BC FSM: LOCKED to FREERUN")
			updateDownstreamData = true
		} else if e.isSourceLostBC(cfgName) {
			e.clkSyncState[cfgName].state = PTP_HOLDOVER
			e.clkSyncState[cfgName].clockClass = fbprotocol.ClockClass(135)
			glog.Info("BC FSM: LOCKED to HOLDOVER")
			e.LeadingClockData.lastInSpec = true
			updateDownstreamData = true
		} else {
			// upstream data changed? If changed, update downstream data
			if e.LeadingClockData.upstreamParentDataSet != nil && e.LeadingClockData.upstreamTimeProperties != nil &&
				e.LeadingClockData.downstreamParentDataSet != nil && e.LeadingClockData.downstreamTimeProperties != nil {
				if *e.LeadingClockData.upstreamParentDataSet != *e.LeadingClockData.downstreamParentDataSet ||
					*e.LeadingClockData.upstreamTimeProperties != *e.LeadingClockData.downstreamTimeProperties {
					e.LeadingClockData.downstreamParentDataSet = e.LeadingClockData.upstreamParentDataSet
					e.LeadingClockData.downstreamTimeProperties = e.LeadingClockData.upstreamTimeProperties
					updateDownstreamData = true
				}
			}
		}
	case PTP_HOLDOVER:
		if e.inSyncCondition(cfgName) && !e.isSourceLostBC(cfgName) {
			e.clkSyncState[cfgName].state = PTP_LOCKED
			glog.Info("BC FSM: HOLDOVER to LOCKED")
			updateDownstreamData = true
		} else if e.freeRunCondition(cfgName) {
			e.clkSyncState[cfgName].state = PTP_FREERUN
			e.clkSyncState[cfgName].clockClass = protocol.ClockClassFreerun
			glog.Info("BC FSM: HOLDOVER to FREERUN")
			updateDownstreamData = true
		} else {
			if event.IFace == leadingInterface {
				inSpec := e.inSpecCondition(cfgName)
				if e.LeadingClockData.lastInSpec != inSpec {
					e.LeadingClockData.lastInSpec = inSpec
					if !inSpec {
						if e.clkSyncState[cfgName].clockClass != fbprotocol.ClockClass(165) {
							e.clkSyncState[cfgName].clockClass = fbprotocol.ClockClass(165)
							glog.Info("BC FSM: HOLDOVER sub-state Out Of Spec")
							updateDownstreamData = true
						}
					} else {
						if e.clkSyncState[cfgName].clockClass != fbprotocol.ClockClass(135) {
							e.clkSyncState[cfgName].clockClass = fbprotocol.ClockClass(135)
							glog.Info("BC FSM: HOLDOVER sub-state In Spec")
							updateDownstreamData = true
						}
					}
				}
			}
		}
	}
	e.clkSyncState[cfgName].leadingIFace = leadingInterface
	e.clkSyncState[cfgName].clockAccuracy = fbprotocol.ClockAccuracyUnknown

	gSycState := e.clkSyncState[cfgName]
	rclockSyncState := clockSyncState{
		state:         gSycState.state,
		clockClass:    gSycState.clockClass,
		clockAccuracy: gSycState.clockAccuracy,
		sourceLost:    gSycState.sourceLost,
		leadingIFace:  gSycState.leadingIFace,
	}

	if gSycState.state == PTP_FREERUN {
		e.clkSyncState[cfgName].clockOffset = FaultyPhaseOffset
	} else {
		e.clkSyncState[cfgName].clockOffset = e.getLargestOffset(cfgName)
	}

	if updateDownstreamData {
		if gSycState.state == PTP_LOCKED {
			if e.LeadingClockData.upstreamParentDataSet != nil && e.LeadingClockData.upstreamTimeProperties != nil {
				go e.downstreamAnnounceIWF(e.LeadingClockData.upstreamCurrentDSStepsRemoved,
					*e.LeadingClockData.upstreamParentDataSet, *e.LeadingClockData.upstreamTimeProperties, cfgName)
			}
		} else {
			go e.announceLocalData(cfgName)
		}
	}
	// this will reduce log noise and prints 1 per sec
	logTime := time.Now().Unix()
	if e.clkSyncState[cfgName].lastLoggedTime != logTime {
		clkLog := fmt.Sprintf("%s[%d]:[%s] %s offset %d T-BC-STATUS %s\n",
			BC, logTime, cfgName, gSycState.leadingIFace, e.clkSyncState[cfgName].clockOffset, gSycState.state)
		e.clkSyncState[cfgName].lastLoggedTime = logTime
		e.clkSyncState[cfgName].clkLog = clkLog
		rclockSyncState.clkLog = clkLog
		glog.Infof("dpll State %s, tsphc state %s, BC state %s, BC offset %d",
			dpllState, ts2phcState, e.clkSyncState[cfgName].state, e.clkSyncState[cfgName].clockOffset)
	}
	return rclockSyncState
}

// Implements Rec. ITU-T G.8275 (2024) Amd. 1 (08/2024)
// Table VIII.3 − T-BC-/ T-BC-P/ T-BC-A Announce message contents
// for free-run (acquiring), holdover within / out of the specification
func (e *EventHandler) announceLocalData(cfgName string) {
	glog.Info("in announceLocalData")

	egp := protocol.ExternalGrandmasterProperties{
		GrandmasterIdentity: e.LeadingClockData.clockID,
		StepsRemoved:        0,
	}
	glog.Infof("EGP %++v", egp)
	go pmc.RunPMCExpSetExternalGMPropertiesNP(e.LeadingClockData.controlledPortsConfig, egp)
	fmt.Printf("ptp4l %d %s CLOCK_CLASS_CHANGE %d\n", time.Now().Unix(), cfgName, e.clkSyncState[cfgName].clockClass)

	gs := protocol.GrandmasterSettings{
		ClockQuality: fbprotocol.ClockQuality{
			ClockClass:              e.clkSyncState[cfgName].clockClass,
			ClockAccuracy:           fbprotocol.ClockAccuracyUnknown,
			OffsetScaledLogVariance: 0xffff,
		},
		TimePropertiesDS: protocol.TimePropertiesDS{
			TimeSource: fbprotocol.TimeSourceInternalOscillator,
		},
	}
	switch e.clkSyncState[cfgName].clockClass {
	case protocol.ClockClassFreerun:
		gs.TimePropertiesDS.CurrentUtcOffsetValid = false
		gs.TimePropertiesDS.Leap59 = false
		gs.TimePropertiesDS.Leap61 = false
		gs.TimePropertiesDS.PtpTimescale = true
		gs.TimePropertiesDS.TimeTraceable = false
		// TODO: get the real freq traceability status when implemented
		gs.TimePropertiesDS.FrequencyTraceable = false
		gs.TimePropertiesDS.CurrentUtcOffset = int32(leap.GetUtcOffset())
	case fbprotocol.ClockClass(165), fbprotocol.ClockClass(135):
		if e.LeadingClockData.upstreamTimeProperties == nil {
			glog.Info("Pending upstream clock data acquisition, skip updates")
			return
		}
		gs.TimePropertiesDS.CurrentUtcOffsetValid = e.LeadingClockData.upstreamTimeProperties.CurrentUtcOffsetValid
		gs.TimePropertiesDS.Leap59 = e.LeadingClockData.upstreamTimeProperties.Leap59
		gs.TimePropertiesDS.Leap61 = e.LeadingClockData.upstreamTimeProperties.Leap61
		gs.TimePropertiesDS.PtpTimescale = true
		if e.clkSyncState[cfgName].clockClass == fbprotocol.ClockClass(135) {
			gs.TimePropertiesDS.TimeTraceable = true
		} else {
			gs.TimePropertiesDS.TimeTraceable = false
		}
		// TODO: get the real freq traceability status when implemented
		gs.TimePropertiesDS.FrequencyTraceable = false
		gs.TimePropertiesDS.CurrentUtcOffset = e.LeadingClockData.upstreamTimeProperties.CurrentUtcOffset

	default:
	}
	// pmcCmd := fmt.Sprintf("pmc -u -b 0 -f /var/run/%s", cfgName)

	go pmc.RunPMCExpSetGMSettings(e.LeadingClockData.controlledPortsConfig, gs)
}

func (e *EventHandler) downstreamAnnounceIWF(stepsRemoved uint16, pds protocol.ParentDataSet, tp protocol.TimePropertiesDS, cfgName string) {
	gs := protocol.GrandmasterSettings{
		ClockQuality: fbprotocol.ClockQuality{
			ClockClass:              fbprotocol.ClockClass(pds.GrandmasterClockClass),
			ClockAccuracy:           fbprotocol.ClockAccuracy(pds.GrandmasterClockAccuracy),
			OffsetScaledLogVariance: pds.ObservedParentOffsetScaledLogVariance,
		},
		TimePropertiesDS: tp,
	}
	es := protocol.ExternalGrandmasterProperties{
		GrandmasterIdentity: pds.GrandmasterIdentity,
		// stepsRemoved at this point is already incremented, representing the current clock position
		StepsRemoved: stepsRemoved,
	}
	fmt.Printf("ptp4l %d %s CLOCK_CLASS_CHANGE %d\n", time.Now().Unix(), cfgName, gs.ClockQuality.ClockClass)
	if err := pmc.RunPMCExpSetExternalGMPropertiesNP(e.LeadingClockData.controlledPortsConfig, es); err != nil {
		glog.Error(err)
	}
	if err := pmc.RunPMCExpSetGMSettings(e.LeadingClockData.controlledPortsConfig, gs); err != nil {
		glog.Error(err)
	}
	glog.Infof("%++v", es)
}

func (e *EventHandler) inSyncCondition(cfgName string) bool {
	if e.LeadingClockData.inSyncConditionThreshold == 0 {
		glog.Info("Leading clock in-sync condition is pending initialization")
		return false
	}
	worstDpllOffset := e.getLargestOffset(cfgName)
	if math.Abs(float64(worstDpllOffset)) < float64(e.LeadingClockData.inSyncConditionThreshold) {
		e.LeadingClockData.inSyncThresholdCounter++
		if e.LeadingClockData.inSyncThresholdCounter >= e.LeadingClockData.inSyncConditionTimes {
			return true
		}
	} else {
		e.LeadingClockData.inSyncThresholdCounter = 0
	}

	glog.Info("sync condition not reached: offset ", worstDpllOffset, " count ",
		e.LeadingClockData.inSyncThresholdCounter, " out of ", e.LeadingClockData.inSyncConditionTimes)
	return false
}

func (e *EventHandler) isSourceLostBC(cfgName string) bool {
	ptpLost := true
	dpllLost := false
	dpllLostIface := ""
	if data, ok := e.data[cfgName]; ok {
		for _, d := range data {
			if d.ProcessName == PTP4l {
				for _, dd := range d.Details {
					if dd.State == PTP_LOCKED {
						ptpLost = false
					}
				}
			}
			if d.ProcessName == DPLL {
				for _, dd := range d.Details {
					if dd.State != PTP_LOCKED {
						dpllLost = true
						dpllLostIface = dd.IFace
						break
					}
				}
			}
		}
	}
	glog.Infof("Source %s: ptpLost %t, dpllLost %t %s",
		func() string {
			if dpllLost || ptpLost {
				return "LOST"
			}
			return "NOT LOST"
		}(), ptpLost, dpllLost, dpllLostIface)
	return ptpLost || dpllLost
}

func (e *EventHandler) getLargestOffset(cfgName string) int64 {
	worstOffset := FaultyPhaseOffset
	if data, ok := e.data[cfgName]; ok {
		for _, d := range data {
			if d.ProcessName == DPLL {
				for _, dd := range d.Details {
					if math.Abs(float64(dd.Offset)) > math.Abs(float64(worstOffset)) || worstOffset == FaultyPhaseOffset {
						worstOffset = dd.Offset
					}
				}
			}
		}
	}
	glog.Info("Largest DPLL offset ", worstOffset)
	return worstOffset
}

func (e *EventHandler) freeRunCondition(cfgName string) bool {
	if e.LeadingClockData.toFreeRunThreshold == 0 {
		glog.Info("Leading clock free-run condition is pending initialization")
		return true
	}
	if data, ok := e.data[cfgName]; ok {
		for _, d := range data {
			if d.ProcessName == DPLL {
				for _, dd := range d.Details {
					if dd.IFace == e.clkSyncState[cfgName].leadingIFace {
						if math.Abs(float64(dd.Offset)) > float64(e.LeadingClockData.toFreeRunThreshold) {
							glog.Infof("free-run condition on DPLL ", dd.IFace)
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func (e *EventHandler) inSpecCondition(cfgName string) bool {
	if e.LeadingClockData.MaxInSpecOffset == 0 {
		glog.Info("Leading clock in-spec condition is pending initialization")
		return false
	}
	if data, ok := e.data[cfgName]; ok {
		for _, d := range data {
			if d.ProcessName == DPLL {
				for _, dd := range d.Details {
					if dd.IFace == e.clkSyncState[cfgName].leadingIFace {
						if math.Abs(float64(dd.Offset)) > float64(e.LeadingClockData.MaxInSpecOffset) {
							glog.Infof("out-of-spec condition on DPLL ", dd.IFace)
							return false
						}
					}
				}
			}
		}
	}
	return true
}

func (e *EventHandler) getLeadingInterfaceBC() string {
	if e.LeadingClockData.leadingInterface != "" {
		return e.LeadingClockData.leadingInterface
	}
	return LEADING_INTERFACE_UNKNOWN
}

func (e *EventHandler) convergeConfig(event EventChannel) EventChannel {
	if event.ProcessName == PTP4lProcessName {
		iface := event.IFace
		for cfg, dd := range e.data {
			for _, item := range dd {
				if item.ProcessName != DPLL {
					continue
				}
				for _, dp := range item.Details {
					if dp.IFace == iface {
						// We want to process ptp4l having a separate config with ts2phc and dpll events having ts2phc config
						// so in the rare occurrence of ptp4l state change we modify the event.CfgName
						event.CfgName = cfg
					}
				}
			}
		}
	}
	e.updateLeadingClockData(event)
	return event
}

func (e *EventHandler) updateLeadingClockData(event EventChannel) {
	switch event.ProcessName {
	case PTP4lProcessName:
		glog.Infof("%++v", event)
		tp, found := event.Values[TimePropertiesDataSet].(*protocol.TimePropertiesDS)
		if found && tp != nil {
			e.LeadingClockData.upstreamTimeProperties = tp
		}
		cpc, found := event.Values[ControlledPortsConfig].(string)
		if found {
			e.LeadingClockData.controlledPortsConfig = cpc
		}
		pds, found := event.Values[ParentDataSet].(*protocol.ParentDataSet)
		if found && pds != nil {
			e.LeadingClockData.upstreamParentDataSet = pds
		}
		cds, found := event.Values[CurrentDataSet].(*protocol.CurrentDS)
		if found && cds != nil {
			e.LeadingClockData.upstreamCurrentDSStepsRemoved = cds.StepsRemoved
		}
		id, found := event.Values[ClockIDKey].(string)
		if found {
			e.LeadingClockData.clockID = id
		}
	case DPLL:
		ls, found := event.Values[LeadingSource].(bool)
		if found && ls {
			e.LeadingClockData.leadingInterface = event.IFace
		}
		inSyncTh, found := event.Values[InSyncConditionThreshold].(uint64)
		if found {
			e.LeadingClockData.inSyncConditionThreshold = int(inSyncTh)
		}
		inSyncTimes, found := event.Values[InSyncConditionTimes].(uint64)
		if found {
			e.LeadingClockData.inSyncConditionTimes = int(inSyncTimes)
		}
		toFreeRunTh, found := event.Values[ToFreeRunThreshold].(uint64)
		if found {
			e.LeadingClockData.toFreeRunThreshold = int(toFreeRunTh)
		}
		maxInSpec, found := event.Values[MaxInSpecOffset].(uint64)
		if found {
			e.LeadingClockData.MaxInSpecOffset = maxInSpec
		}
	}
}

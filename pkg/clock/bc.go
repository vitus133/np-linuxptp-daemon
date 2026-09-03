package clock

import (
	"time"

	fbprotocol "github.com/facebook/time/ptp/protocol"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/event"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/ipc"
	parserconstants "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/parser/constants"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/utils"
)

// defaultBCClockHoldOverTimeout is the amount of time a BC/OC clock holds
// HOLDOVER after its upstream source is lost before dropping to FREERUN.
const defaultBCClockHoldOverTimeout = 5 * time.Second

// BCClock is a simple Boundary Clock instance (no DPLL/ts2phc). It also backs
// the Ordinary Clock (OC) role, which is a single slave-port time receiver and
// shares the same state machine; the clockType field records which role it serves.
type BCClock struct {
	cfgName          string
	clockType        event.ClockType
	sendIPC          func(ipc.Message)
	iface            string
	data             []*event.Data
	syncState        event.PTPState
	clockClass       fbprotocol.ClockClass
	overallSyncState event.PTPState
	osClockState     event.PTPState
	// holdOverTimeout is how long to stay in HOLDOVER after the upstream
	// source is lost before falling back to FREERUN. Zero disables the
	// mini-holdover (immediate FREERUN).
	holdOverTimeout time.Duration
	// holdoverStart is when HOLDOVER was entered. A zero value means the
	// clock is not currently in HOLDOVER.
	holdoverStart time.Time
	// portRole is the latest parsed ptp4l port role (from PTPData.Values).
	// It is one of the upstream source-loss triggers: a transition away from
	// SLAVE indicates the upstream adjacency is lost. haveRole is true once a
	// role has been observed; until then role-based loss is ignored so a fresh
	// clock (zero-value portRole) is not spuriously held over.
	portRole parserconstants.PTPPortRole
	haveRole bool
}

// SetHoldOverTimeout sets how long the BC/OC stays in HOLDOVER after losing
// its upstream source before falling back to FREERUN.
func (c *BCClock) SetHoldOverTimeout(seconds int64) {
	c.holdOverTimeout = time.Duration(seconds) * time.Second
}

// ClockType returns the clock type for this clock (BC or OC).
func (c *BCClock) ClockType() event.ClockType {
	if c.clockType == event.ClockUnset {
		return event.BC
	}
	return c.clockType
}

// ClockClass returns the current clock class.
func (c *BCClock) ClockClass() fbprotocol.ClockClass { return c.clockClass }

// ConfigName returns the configuration name.
func (c *BCClock) ConfigName() string { return c.cfgName }

func (c *BCClock) getData(processName event.EventSource) *event.Data {
	for _, d := range c.data {
		if d.ProcessName == processName {
			return d
		}
	}
	d := &event.Data{ProcessName: processName, State: event.PTP_UNKNOWN, Window: *utils.NewWindow(event.WindowSize)}
	c.data = append(c.data, d)
	return d
}

// AddEvent processes an event and updates clock state.
func (c *BCClock) AddEvent(ev event.Event) SyncState {
	switch ev.Source {
	case event.PMC:
		if ds, ok := ev.Data.(*event.ParentDSData); ok {
			clockClass := fbprotocol.ClockClass(ds.ParentDataSet.GrandmasterClockClass)
			c.updateClockClass(clockClass)
		}
		return SyncState{State: c.syncState, LeadingIFace: event.LEADING_INTERFACE_UNKNOWN}
	default:
		d := c.getData(ev.Source)

		ptp, ok := ev.Data.(*event.PTPData)
		if !ok || ptp == nil {
			return SyncState{State: c.syncState, LeadingIFace: event.LEADING_INTERFACE_UNKNOWN}
		}

		if c.iface == "" && ev.IFace != "" {
			c.iface = ev.IFace
		}

		// A port-role event is a side-channel: it updates the last known
		// upstream port role (one of the source-loss triggers) but carries no
		// servo State, so it must not run through the servo Data window. The
		// offset/state events below are the ones that maintain d.State.
		roleOnly := false
		if role, ok := ptp.Values[event.PortRole]; ok {
			if r, ok := role.(int64); ok {
				c.portRole = parserconstants.PTPPortRole(r)
				c.haveRole = true
			}
			roleOnly = true
		}

		if !roleOnly {
			d.AddEvent(ev)
			d.UpdateState()
		}

		prev := c.syncState
		c.applyMiniHoldover(c.sourceLost(d.State))

		if c.syncState != prev {
			c.sendIPC(ipc.Message{
				Type:    ipc.TypePTPState,
				Profile: c.cfgName,
				IFace:   ev.IFace,
				Values:  ipc.StateValue{State: event.PtpStateToIPCState(c.syncState)},
			})
		}

		emitOverallSyncStateIfChanged(c.sendIPC, &c.overallSyncState, c.syncState, c.osClockState, c.cfgName)

		return SyncState{State: c.syncState, LeadingIFace: event.LEADING_INTERFACE_UNKNOWN}
	}
}

// SystemClockUpdate updates the OS clock state.
func (c *BCClock) SystemClockUpdate(osClockState event.PTPState) {
	c.osClockState = osClockState
	emitOverallSyncStateIfChanged(c.sendIPC, &c.overallSyncState, c.syncState, c.osClockState, c.cfgName)
}

// sourceLost reports whether the upstream PTP source is lost, combining the
// servo state and the last known port role. The source is considered lost if
// either signal indicates it: the servo degraded below LOCKED, or the upstream
// port is no longer SLAVE (e.g. FAULTY, MASTER/PASSIVE/LISTENING, or self
// elected as grand master). A port role of UNKNOWN (not yet observed) is not
// treated as lost so a freshly started clock is not spuriously held over.
func (c *BCClock) sourceLost(servo event.PTPState) bool {
	if servo != event.PTP_LOCKED {
		return true
	}
	if c.haveRole && c.portRole != parserconstants.PortRoleSlave {
		return true
	}
	return false
}

// applyMiniHoldover runs the BC/OC mini-holdover FSM. When the upstream PTP
// source is lost, the clock first reports HOLDOVER for holdOverTimeout and only
// then falls back to FREERUN. If the source is re-acquired during holdover, the
// clock returns to LOCKED immediately. A never-synced FREERUN stays FREERUN
// (there is nothing to hold over).
func (c *BCClock) applyMiniHoldover(sourceLost bool) {
	now := time.Now()
	if !sourceLost {
		// Source present: clear any in-progress holdover and lock.
		c.holdoverStart = time.Time{}
		c.syncState = event.PTP_LOCKED
		return
	}
	// Source lost.
	if c.holdoverStart.IsZero() {
		// Not currently in holdover. Enter it only if we previously had a
		// synchronized source; a fresh FREERUN (never locked) has nothing
		// to hold over and stays FREERUN.
		if c.syncState == event.PTP_LOCKED {
			c.holdoverStart = now
			c.syncState = event.PTP_HOLDOVER
		} else {
			c.syncState = event.PTP_FREERUN
		}
	} else if now.Sub(c.holdoverStart) >= c.holdOverTimeout {
		c.holdoverStart = time.Time{}
		c.syncState = event.PTP_FREERUN
	} else {
		c.syncState = event.PTP_HOLDOVER
	}
}

// Reset resets the clock state.
func (c *BCClock) Reset() {
	c.syncState = event.PTP_FREERUN
	c.overallSyncState = event.PTP_FREERUN
	c.clockClass = 0
	c.data = nil
	c.iface = ""
	c.holdoverStart = time.Time{}
	c.portRole = parserconstants.PortRoleUnknown
	c.haveRole = false
}

func (c *BCClock) updateClockClass(clockClass fbprotocol.ClockClass) {
	if clockClass == c.clockClass {
		return
	}
	c.clockClass = clockClass
	c.sendIPC(ipc.Message{
		Type:    ipc.TypeClockClass,
		Profile: c.cfgName,
		IFace:   c.iface,
		Values:  ipc.ClockClassValue{ClockClass: uint8(clockClass)},
	})
}

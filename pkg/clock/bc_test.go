package clock

import (
	"testing"
	"time"

	fbprotocol "github.com/facebook/time/ptp/protocol"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/event"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/ipc"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/parser/constants"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestBCClock() (*BCClock, *ipcRecorder) {
	rio := &ipcRecorder{}
	return &BCClock{
		cfgName:          testPTP4lCfg,
		sendIPC:          rio.send,
		syncState:        event.PTP_NOTSET,
		overallSyncState: event.PTP_NOTSET,
		osClockState:     event.PTP_NOTSET,
		holdOverTimeout:  defaultBCClockHoldOverTimeout,
	}, rio
}

func TestBCClock_AddEvent_StateTransitions(t *testing.T) {
	t.Run("NOTSET to LOCKED emits ptp_state IPC", func(t *testing.T) {
		bc, rio := newTestBCClock()
		cs := bc.AddEvent(event.Event{
			IFace: testEns7f0,
			Data:  &event.PTPData{State: event.PTP_LOCKED},
		})
		assert.Equal(t, event.PTP_LOCKED, cs.State)
		require.Len(t, rio.messages, 1)
		assert.Equal(t, ipc.TypePTPState, rio.messages[0].Type)
		assert.Equal(t, testPTP4lCfg, rio.messages[0].Profile)
		assert.Equal(t, testEns7f0, rio.messages[0].IFace)
		assert.Equal(t, ipc.StateValue{State: ipc.StateLocked}, rio.messages[0].Values)
	})

	t.Run("LOCKED to FREERUN enters HOLDOVER via mini-holdover", func(t *testing.T) {
		bc, rio := newTestBCClock()
		bc.syncState = event.PTP_LOCKED
		cs := bc.AddEvent(event.Event{
			IFace: testEns7f0,
			Data:  &event.PTPData{State: event.PTP_FREERUN},
		})
		assert.Equal(t, event.PTP_HOLDOVER, cs.State)
		assert.False(t, bc.holdoverStart.IsZero())
		require.Len(t, rio.messages, 1)
		assert.Equal(t, ipc.StateHoldover, rio.messages[0].Values.(ipc.StateValue).State)
	})

	t.Run("duplicate state does not emit ptp_state IPC", func(t *testing.T) {
		bc, rio := newTestBCClock()
		bc.syncState = event.PTP_LOCKED
		cs := bc.AddEvent(event.Event{
			IFace: testEns7f0,
			Data:  &event.PTPData{State: event.PTP_LOCKED},
		})
		assert.Equal(t, event.PTP_LOCKED, cs.State)
		assert.Empty(t, rio.messages)
	})

	t.Run("nil PTPData returns current state unchanged", func(t *testing.T) {
		bc, rio := newTestBCClock()
		bc.syncState = event.PTP_FREERUN
		cs := bc.AddEvent(event.Event{Data: nil})
		assert.Equal(t, event.PTP_FREERUN, cs.State)
		assert.Empty(t, rio.messages)
	})
}

func TestBCClock_UpdateOSClockState(t *testing.T) {
	t.Run("worst of LOCKED and FREERUN is FREERUN", func(t *testing.T) {
		bc, rio := newTestBCClock()
		bc.syncState = event.PTP_LOCKED
		bc.overallSyncState = event.PTP_LOCKED
		bc.SystemClockUpdate(event.PTP_FREERUN)
		assert.Equal(t, event.PTP_FREERUN, bc.overallSyncState)
		assert.Equal(t, event.PTP_FREERUN, bc.osClockState)
		require.Len(t, rio.messages, 1)
		assert.Equal(t, ipc.TypeSyncState, rio.messages[0].Type)
		assert.Equal(t, ipc.SyncStateValue{State: ipc.StateFreerun}, rio.messages[0].Values)
	})

	t.Run("worst of LOCKED and LOCKED is LOCKED", func(t *testing.T) {
		bc, rio := newTestBCClock()
		bc.syncState = event.PTP_LOCKED
		bc.overallSyncState = event.PTP_LOCKED
		bc.SystemClockUpdate(event.PTP_LOCKED)
		assert.Equal(t, event.PTP_LOCKED, bc.overallSyncState)
		assert.Empty(t, rio.messages)
	})

	t.Run("worst of HOLDOVER and LOCKED is HOLDOVER", func(t *testing.T) {
		bc, rio := newTestBCClock()
		bc.syncState = event.PTP_HOLDOVER
		bc.overallSyncState = event.PTP_NOTSET
		bc.SystemClockUpdate(event.PTP_LOCKED)
		assert.Equal(t, event.PTP_HOLDOVER, bc.overallSyncState)
		require.Len(t, rio.messages, 1)
		assert.Equal(t, ipc.TypeSyncState, rio.messages[0].Type)
	})

	t.Run("no change does not emit IPC", func(t *testing.T) {
		bc, rio := newTestBCClock()
		bc.syncState = event.PTP_FREERUN
		bc.overallSyncState = event.PTP_FREERUN
		bc.SystemClockUpdate(event.PTP_LOCKED)
		assert.Equal(t, event.PTP_FREERUN, bc.overallSyncState)
		assert.Empty(t, rio.messages)
	})
}

func TestBCClock_UpdateClockClass(t *testing.T) {
	t.Run("change emits clock_class IPC with iface", func(t *testing.T) {
		bc, rio := newTestBCClock()
		bc.AddEvent(event.Event{IFace: testEns7f0, Data: &event.PTPData{State: event.PTP_LOCKED}})
		rio.messages = nil // clear ptp_state IPC from addEvent
		bc.updateClockClass(fbprotocol.ClockClass6)
		require.Len(t, rio.messages, 1)
		assert.Equal(t, ipc.TypeClockClass, rio.messages[0].Type)
		assert.Equal(t, testPTP4lCfg, rio.messages[0].Profile)
		assert.Equal(t, testEns7f0, rio.messages[0].IFace)
		assert.Equal(t, ipc.ClockClassValue{ClockClass: 6}, rio.messages[0].Values)
	})

	t.Run("same class does not emit IPC", func(t *testing.T) {
		bc, rio := newTestBCClock()
		bc.clockClass = fbprotocol.ClockClass6
		bc.updateClockClass(fbprotocol.ClockClass6)
		assert.Empty(t, rio.messages)
	})

	t.Run("class change updates stored value", func(t *testing.T) {
		bc, _ := newTestBCClock()
		bc.updateClockClass(fbprotocol.ClockClass7)
		assert.Equal(t, fbprotocol.ClockClass7, bc.clockClass)
		bc.updateClockClass(fbprotocol.ClockClass6)
		assert.Equal(t, fbprotocol.ClockClass6, bc.clockClass)
	})
}

func TestBCClock_Interface(t *testing.T) {
	bc, _ := newTestBCClock()
	assert.Equal(t, event.BC, bc.ClockType())
	assert.Equal(t, testPTP4lCfg, bc.ConfigName())
}

func TestBCClock_ClockType(t *testing.T) {
	t.Run("unset defaults to BC", func(t *testing.T) {
		bc, _ := newTestBCClock()
		assert.Equal(t, event.BC, bc.ClockType())
	})

	t.Run("OC role is reported as OC", func(t *testing.T) {
		bc, _ := newTestBCClock()
		bc.clockType = event.OC
		assert.Equal(t, event.OC, bc.ClockType())
	})

	t.Run("OC clock processes events like BC", func(t *testing.T) {
		bc, rio := newTestBCClock()
		bc.clockType = event.OC
		cs := bc.AddEvent(event.Event{
			IFace: testEns7f0,
			Data:  &event.PTPData{State: event.PTP_LOCKED},
		})
		assert.Equal(t, event.PTP_LOCKED, cs.State)
		require.Len(t, rio.messages, 1)
		assert.Equal(t, ipc.TypePTPState, rio.messages[0].Type)
	})
}

func TestBCClock_ParentDSUpdate(t *testing.T) {
	t.Run("updates clock class and emits", func(t *testing.T) {
		rio := &ipcRecorder{}
		bc := &BCClock{cfgName: testPTP4lCfg, sendIPC: rio.send}

		parentDS := protocol.ParentDataSet{
			GrandmasterClockClass: 6,
		}
		bc.AddEvent(event.Event{Source: event.PMC, Data: &event.ParentDSData{ParentDataSet: parentDS}})

		assert.Equal(t, fbprotocol.ClockClass(6), bc.clockClass)
		require.Len(t, rio.messages, 1)
		assert.Equal(t, ipc.TypeClockClass, rio.messages[0].Type)
		assert.Equal(t, ipc.ClockClassValue{ClockClass: 6}, rio.messages[0].Values)
	})

	t.Run("unchanged class does not send IPC", func(t *testing.T) {
		rio := &ipcRecorder{}
		bc := &BCClock{cfgName: testPTP4lCfg, sendIPC: rio.send, clockClass: fbprotocol.ClockClass(6)}

		parentDS := protocol.ParentDataSet{
			GrandmasterClockClass: 6,
		}
		bc.AddEvent(event.Event{Source: event.PMC, Data: &event.ParentDSData{ParentDataSet: parentDS}})

		assert.Empty(t, rio.messages, "updateClockClass should no-op on unchanged class")
	})
}

func TestBCClock_MiniHoldover(t *testing.T) {
	t.Run("never-synced FREERUN stays FREERUN", func(t *testing.T) {
		bc, _ := newTestBCClock()
		bc.syncState = event.PTP_FREERUN
		cs := bc.AddEvent(event.Event{IFace: testEns7f0, Data: &event.PTPData{State: event.PTP_FREERUN}})
		assert.Equal(t, event.PTP_FREERUN, cs.State)
		assert.True(t, bc.holdoverStart.IsZero())
	})

	t.Run("re-acquiring LOCKED during holdover returns to LOCKED", func(t *testing.T) {
		bc, rio := newTestBCClock()
		bc.syncState = event.PTP_LOCKED
		bc.AddEvent(event.Event{IFace: testEns7f0, Data: &event.PTPData{State: event.PTP_FREERUN}})
		assert.Equal(t, event.PTP_HOLDOVER, bc.syncState)

		cs := bc.AddEvent(event.Event{IFace: testEns7f0, Data: &event.PTPData{State: event.PTP_LOCKED}})
		assert.Equal(t, event.PTP_LOCKED, cs.State)
		assert.True(t, bc.holdoverStart.IsZero())
		// LOCKED->HOLDOVER and HOLDOVER->LOCKED are two transitions.
		require.Len(t, rio.messages, 2)
		assert.Equal(t, ipc.StateHoldover, rio.messages[0].Values.(ipc.StateValue).State)
		assert.Equal(t, ipc.StateLocked, rio.messages[1].Values.(ipc.StateValue).State)
	})

	t.Run("stays HOLDOVER within timeout, then FREERUN after expiry", func(t *testing.T) {
		bc, _ := newTestBCClock()
		bc.holdOverTimeout = 10 * time.Second
		bc.syncState = event.PTP_LOCKED

		bc.holdoverStart = time.Now().Add(-2 * time.Second)
		cs := bc.AddEvent(event.Event{IFace: testEns7f0, Data: &event.PTPData{State: event.PTP_FREERUN}})
		assert.Equal(t, event.PTP_HOLDOVER, cs.State, "should stay HOLDOVER before timeout")

		bc.holdoverStart = time.Now().Add(-11 * time.Second)
		cs = bc.AddEvent(event.Event{IFace: testEns7f0, Data: &event.PTPData{State: event.PTP_FREERUN}})
		assert.Equal(t, event.PTP_FREERUN, cs.State, "should fall back to FREERUN after timeout")
		assert.True(t, bc.holdoverStart.IsZero())
	})

	t.Run("SetHoldOverTimeout configures the holdover window", func(t *testing.T) {
		bc, _ := newTestBCClock()
		bc.SetHoldOverTimeout(3)
		assert.Equal(t, 3*time.Second, bc.holdOverTimeout)
	})

	t.Run("Reset clears holdover state", func(t *testing.T) {
		bc, _ := newTestBCClock()
		bc.syncState = event.PTP_LOCKED
		bc.AddEvent(event.Event{IFace: testEns7f0, Data: &event.PTPData{State: event.PTP_FREERUN}})
		assert.False(t, bc.holdoverStart.IsZero())

		bc.Reset()
		assert.True(t, bc.holdoverStart.IsZero())
		assert.Equal(t, event.PTP_FREERUN, bc.syncState)
	})
}

func roleEvent(role constants.PTPPortRole) event.Event {
	return event.Event{
		IFace: testEns7f0,
		Data: &event.PTPData{
			Values: map[event.ValueType]interface{}{event.PortRole: int64(role)},
		},
	}
}

func TestBCClock_MiniHoldover_RoleTrigger(t *testing.T) {
	t.Run("role loss while servo LOCKED enters HOLDOVER and recovers on SLAVE", func(t *testing.T) {
		bc, rio := newTestBCClock()
		// servo offset event drives LOCKED
		bc.AddEvent(event.Event{IFace: testEns7f0, Data: &event.PTPData{State: event.PTP_LOCKED}})
		require.Equal(t, event.PTP_LOCKED, bc.syncState)

		// upstream drops SLAVE (self-elected MASTER) -> HOLDOVER, not FREERUN
		rio.messages = nil
		cs := bc.AddEvent(roleEvent(constants.PortRoleMaster))
		assert.Equal(t, event.PTP_HOLDOVER, cs.State)
		assert.False(t, bc.holdoverStart.IsZero())
		assert.Equal(t, ipc.StateHoldover, rio.messages[0].Values.(ipc.StateValue).State)

		// re-acquire SLAVE while servo still LOCKED -> back to LOCKED
		cs = bc.AddEvent(roleEvent(constants.PortRoleSlave))
		assert.Equal(t, event.PTP_LOCKED, cs.State)
		assert.True(t, bc.holdoverStart.IsZero())
	})

	t.Run("loss roles MASTER/FAULTY/PASSIVE/LISTENING all hold over", func(t *testing.T) {
		for _, role := range []constants.PTPPortRole{
			constants.PortRoleMaster,
			constants.PortRoleFaulty,
			constants.PortRolePassive,
			constants.PortRoleListening,
		} {
			bc, _ := newTestBCClock()
			bc.AddEvent(event.Event{IFace: testEns7f0, Data: &event.PTPData{State: event.PTP_LOCKED}})
			require.Equal(t, event.PTP_LOCKED, bc.syncState)
			cs := bc.AddEvent(roleEvent(role))
			assert.Equal(t, event.PTP_HOLDOVER, cs.State, "role %d should trigger holdover", role)
		}
	})

	t.Run("no role observed does not spuriously hold over (haveRole false)", func(t *testing.T) {
		bc, _ := newTestBCClock()
		bc.syncState = event.PTP_LOCKED
		// zero-value portRole is Passive(0) but haveRole is false -> ignored
		cs := bc.AddEvent(event.Event{IFace: testEns7f0, Data: &event.PTPData{State: event.PTP_LOCKED}})
		assert.Equal(t, event.PTP_LOCKED, cs.State)
		assert.True(t, bc.holdoverStart.IsZero())
	})

	t.Run("servo loss still dominates when role is SLAVE", func(t *testing.T) {
		bc, _ := newTestBCClock()
		bc.AddEvent(event.Event{IFace: testEns7f0, Data: &event.PTPData{State: event.PTP_LOCKED}})
		require.Equal(t, event.PTP_LOCKED, bc.syncState)
		bc.AddEvent(roleEvent(constants.PortRoleSlave))
		require.Equal(t, event.PTP_LOCKED, bc.syncState)

		// servo degrades to FREERUN even though role is SLAVE -> HOLDOVER
		cs := bc.AddEvent(event.Event{IFace: testEns7f0, Data: &event.PTPData{State: event.PTP_FREERUN}})
		assert.Equal(t, event.PTP_HOLDOVER, cs.State)
	})

	t.Run("Reset clears observed role state", func(t *testing.T) {
		bc, _ := newTestBCClock()
		bc.syncState = event.PTP_LOCKED
		bc.AddEvent(roleEvent(constants.PortRoleFaulty))
		require.Equal(t, event.PTP_HOLDOVER, bc.syncState)
		require.True(t, bc.haveRole)

		bc.Reset()
		assert.False(t, bc.haveRole)
		assert.Equal(t, constants.PortRoleUnknown, bc.portRole)
		assert.Equal(t, event.PTP_FREERUN, bc.syncState)
	})
}

func TestBCClock_SetHoldOverTimeoutInterface(t *testing.T) {
	t.Run("implements Clock interface", func(t *testing.T) {
		var _ Clock = (*BCClock)(nil)
		bc := &BCClock{}
		bc.SetHoldOverTimeout(5)
		assert.Equal(t, 5*time.Second, bc.holdOverTimeout)
	})
}

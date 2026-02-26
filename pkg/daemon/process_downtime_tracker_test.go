package daemon

import (
	"testing"
	"time"

	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/event"
	"github.com/stretchr/testify/assert"
	ptpv1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"
)

func intPtr(v int) *int { return &v }

func newTestTracker() (*ProcessDowntimeTracker, chan event.EventChannel) {
	ch := make(chan event.EventChannel, 20)
	tracker := NewProcessDowntimeTracker()
	return tracker, ch
}

func registerPtp4l(tracker *ProcessDowntimeTracker, ch chan event.EventChannel, thresholdSec int) {
	tracker.Register(ptp4lProcessName, "ptp4l.0.config", &ptpv1.ProcessDowntimeThresholds{
		Ptp4l: intPtr(thresholdSec),
	}, ch)
}

func drainDowntimeEvents(ch chan event.EventChannel) []event.ProcessDownInfo {
	var events []event.ProcessDownInfo
	for {
		select {
		case e := <-ch:
			if e.ProcessDown != nil {
				events = append(events, *e.ProcessDown)
			}
		default:
			return events
		}
	}
}

func TestPhase1EmittedOnProcessDown(t *testing.T) {
	t.Parallel()
	tracker, ch := newTestTracker()
	registerPtp4l(tracker, ch, 5)

	tracker.OnProcessDown(ptp4lProcessName, "ptp4l.0.config")

	events := drainDowntimeEvents(ch)
	if !assert.Len(t, events, 1) {
		return
	}
	assert.False(t, events[0].Exceeded)
}

func TestPhase2EmittedOnCumulativeExceeded(t *testing.T) {
	t.Parallel()
	tracker, ch := newTestTracker()
	registerPtp4l(tracker, ch, 5)

	key := stateKey(ptp4lProcessName, "ptp4l.0.config")

	// First down/up cycle: 3s downtime.
	tracker.OnProcessDown(ptp4lProcessName, "ptp4l.0.config")
	drainDowntimeEvents(ch)

	tracker.mu.Lock()
	s := tracker.states[key]
	s.downTimestamp = time.Now().Add(-3 * time.Second)
	if s.expiryTimer != nil {
		s.expiryTimer.Stop()
		s.expiryTimer = nil
	}
	tracker.mu.Unlock()

	tracker.OnProcessUp(ptp4lProcessName, "ptp4l.0.config")
	drainDowntimeEvents(ch)

	assert.False(t, tracker.HasExceeded(ptp4lProcessName, "ptp4l.0.config"))

	// Second down/up cycle: 3s downtime (total ~6s > 5s).
	tracker.OnProcessDown(ptp4lProcessName, "ptp4l.0.config")
	drainDowntimeEvents(ch)

	tracker.mu.Lock()
	s = tracker.states[key]
	s.downTimestamp = time.Now().Add(-3 * time.Second)
	if s.expiryTimer != nil {
		s.expiryTimer.Stop()
		s.expiryTimer = nil
	}
	tracker.mu.Unlock()

	tracker.OnProcessUp(ptp4lProcessName, "ptp4l.0.config")

	events := drainDowntimeEvents(ch)
	var phase2 *event.ProcessDownInfo
	for i := range events {
		if events[i].Exceeded {
			phase2 = &events[i]
			break
		}
	}
	if !assert.NotNil(t, phase2, "expected Phase 2 event") {
		return
	}
	assert.True(t, phase2.Exceeded)
	assert.True(t, tracker.HasExceeded(ptp4lProcessName, "ptp4l.0.config"))
}

func TestStabilityReset(t *testing.T) {
	t.Parallel()
	tracker, ch := newTestTracker()
	registerPtp4l(tracker, ch, 5)

	key := stateKey(ptp4lProcessName, "ptp4l.0.config")

	// First cycle: 2s down.
	tracker.OnProcessDown(ptp4lProcessName, "ptp4l.0.config")
	tracker.mu.Lock()
	s := tracker.states[key]
	s.downTimestamp = time.Now().Add(-2 * time.Second)
	if s.expiryTimer != nil {
		s.expiryTimer.Stop()
		s.expiryTimer = nil
	}
	tracker.mu.Unlock()

	tracker.OnProcessUp(ptp4lProcessName, "ptp4l.0.config")
	drainDowntimeEvents(ch)

	// Simulate that the process stayed up for 6s (>= 5s threshold) and
	// then went down for 2s.
	now := time.Now()
	tracker.OnProcessDown(ptp4lProcessName, "ptp4l.0.config")
	drainDowntimeEvents(ch)

	tracker.mu.Lock()
	s = tracker.states[key]
	s.upTimestamp = now.Add(-8 * time.Second) // came up 8s ago
	s.downTimestamp = now.Add(-2 * time.Second) // went down 2s ago (was up for 6s)
	if s.expiryTimer != nil {
		s.expiryTimer.Stop()
		s.expiryTimer = nil
	}
	tracker.mu.Unlock()

	tracker.OnProcessUp(ptp4lProcessName, "ptp4l.0.config")

	assert.False(t, tracker.HasExceeded(ptp4lProcessName, "ptp4l.0.config"))

	tracker.mu.Lock()
	assert.Equal(t, 2*time.Second, s.cumulativeDowntime.Round(time.Second))
	tracker.mu.Unlock()
}

func TestExpiryTimerFiresPhase2(t *testing.T) {
	t.Parallel()
	tracker, ch := newTestTracker()
	registerPtp4l(tracker, ch, 1) // 1 second threshold

	tracker.OnProcessDown(ptp4lProcessName, "ptp4l.0.config")

	events := drainDowntimeEvents(ch)
	if !assert.Len(t, events, 1) {
		return
	}
	assert.False(t, events[0].Exceeded)

	time.Sleep(1500 * time.Millisecond)

	events = drainDowntimeEvents(ch)
	var phase2 *event.ProcessDownInfo
	for i := range events {
		if events[i].Exceeded {
			phase2 = &events[i]
			break
		}
	}
	if !assert.NotNil(t, phase2, "expected Phase 2 from expiry timer") {
		return
	}
	assert.True(t, tracker.HasExceeded(ptp4lProcessName, "ptp4l.0.config"))
}

func TestExpiryTimerCancelledOnProcessUp(t *testing.T) {
	t.Parallel()
	tracker, ch := newTestTracker()
	registerPtp4l(tracker, ch, 2) // 2 second threshold

	tracker.OnProcessDown(ptp4lProcessName, "ptp4l.0.config")
	drainDowntimeEvents(ch)

	time.Sleep(200 * time.Millisecond)
	tracker.OnProcessUp(ptp4lProcessName, "ptp4l.0.config")
	drainDowntimeEvents(ch)

	time.Sleep(2500 * time.Millisecond)

	events := drainDowntimeEvents(ch)
	for _, e := range events {
		assert.False(t, e.Exceeded, "Phase 2 should not fire after process came back within threshold")
	}
	assert.False(t, tracker.HasExceeded(ptp4lProcessName, "ptp4l.0.config"))
}

func TestShouldSuppress(t *testing.T) {
	t.Parallel()
	tracker, ch := newTestTracker()
	registerPtp4l(tracker, ch, 5)

	assert.False(t, tracker.ShouldSuppress(ptp4lProcessName, "ptp4l.0.config"))

	tracker.OnProcessDown(ptp4lProcessName, "ptp4l.0.config")
	drainDowntimeEvents(ch)

	assert.True(t, tracker.ShouldSuppress(ptp4lProcessName, "ptp4l.0.config"))

	tracker.OnProcessUp(ptp4lProcessName, "ptp4l.0.config")

	assert.False(t, tracker.ShouldSuppress(ptp4lProcessName, "ptp4l.0.config"))
}

func TestReset(t *testing.T) {
	t.Parallel()
	tracker, ch := newTestTracker()
	registerPtp4l(tracker, ch, 5)

	tracker.OnProcessDown(ptp4lProcessName, "ptp4l.0.config")
	drainDowntimeEvents(ch)

	tracker.Reset(ptp4lProcessName, "ptp4l.0.config")

	assert.False(t, tracker.HasExceeded(ptp4lProcessName, "ptp4l.0.config"))
	assert.False(t, tracker.IsCurrentlyDown(ptp4lProcessName, "ptp4l.0.config"))
	assert.False(t, tracker.ShouldSuppress(ptp4lProcessName, "ptp4l.0.config"))
}

func TestDefaultThresholds(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 5*time.Second, defaultThreshold(ptp4lProcessName))
	assert.Equal(t, 5*time.Second, defaultThreshold(phc2sysProcessName))
	assert.Equal(t, 5*time.Second, defaultThreshold(ts2phcProcessName))
	assert.Equal(t, 5*time.Second, defaultThreshold(syncEProcessName))
	assert.Equal(t, 5*time.Second, defaultThreshold(chronydProcessName))
	assert.Equal(t, 1*time.Second, defaultThreshold(GPSD_PROCESSNAME))
	assert.Equal(t, 1*time.Second, defaultThreshold(GPSPIPE_PROCESSNAME))
	assert.Equal(t, time.Duration(-1), defaultThreshold("unknown"))
}

func TestLookupThresholdNilUsesDefaults(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 5*time.Second, lookupThreshold(ptp4lProcessName, nil))
	assert.Equal(t, 1*time.Second, lookupThreshold(GPSD_PROCESSNAME, nil))
}

func TestLookupThresholdOverride(t *testing.T) {
	t.Parallel()

	thresholds := &ptpv1.ProcessDowntimeThresholds{
		Ptp4l: intPtr(10),
	}
	assert.Equal(t, 10*time.Second, lookupThreshold(ptp4lProcessName, thresholds))
	assert.Equal(t, 5*time.Second, lookupThreshold(phc2sysProcessName, thresholds))
}

func TestFlappingAccumulatesDowntime(t *testing.T) {
	t.Parallel()
	tracker, ch := newTestTracker()
	registerPtp4l(tracker, ch, 5)

	key := stateKey(ptp4lProcessName, "ptp4l.0.config")

	for i := 0; i < 3; i++ {
		tracker.mu.Lock()
		s := tracker.states[key]
		s.downTimestamp = time.Now().Add(-2 * time.Second)
		if s.expiryTimer != nil {
			s.expiryTimer.Stop()
			s.expiryTimer = nil
		}
		tracker.mu.Unlock()

		tracker.OnProcessUp(ptp4lProcessName, "ptp4l.0.config")

		if i < 2 {
			tracker.mu.Lock()
			s = tracker.states[key]
			s.upTimestamp = time.Now()
			tracker.mu.Unlock()
		}
	}

	assert.True(t, tracker.HasExceeded(ptp4lProcessName, "ptp4l.0.config"))

	events := drainDowntimeEvents(ch)
	var found bool
	for _, e := range events {
		if e.Exceeded {
			found = true
			break
		}
	}
	assert.True(t, found, "expected at least one Phase 2 event from flapping")
}

func TestNoEventsForUnregisteredProcess(t *testing.T) {
	t.Parallel()
	tracker, ch := newTestTracker()

	tracker.OnProcessDown("unknown-process", "unknown.config")
	tracker.OnProcessUp("unknown-process", "unknown.config")

	events := drainDowntimeEvents(ch)
	assert.Empty(t, events)
}

func TestAlreadyExceededDoesNotDoubleEmitPhase2(t *testing.T) {
	t.Parallel()
	tracker, ch := newTestTracker()
	registerPtp4l(tracker, ch, 1)

	key := stateKey(ptp4lProcessName, "ptp4l.0.config")

	tracker.mu.Lock()
	s := tracker.states[key]
	s.downTimestamp = time.Now().Add(-3 * time.Second)
	tracker.mu.Unlock()

	tracker.OnProcessUp(ptp4lProcessName, "ptp4l.0.config")
	drainDowntimeEvents(ch)

	tracker.OnProcessDown(ptp4lProcessName, "ptp4l.0.config")

	events := drainDowntimeEvents(ch)
	assert.Empty(t, events)
}

func TestEventChannelFields(t *testing.T) {
	t.Parallel()
	tracker, ch := newTestTracker()
	registerPtp4l(tracker, ch, 5)

	tracker.OnProcessDown(ptp4lProcessName, "ptp4l.0.config")

	select {
	case evt := <-ch:
		assert.Equal(t, event.EventSource(ptp4lProcessName), evt.ProcessName)
		assert.Equal(t, "ptp4l.0.config", evt.CfgName)
		assert.NotNil(t, evt.ProcessDown)
		assert.False(t, evt.ProcessDown.Exceeded)
		assert.NotZero(t, evt.Time)
	default:
		t.Fatal("expected an event on the channel")
	}
}

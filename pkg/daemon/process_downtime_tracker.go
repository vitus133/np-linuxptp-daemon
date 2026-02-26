package daemon

import (
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/event"
	ptpv1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"
)

// processState tracks the downtime state for a single (processName, configName) pair.
type processState struct {
	threshold          time.Duration
	cumulativeDowntime time.Duration
	downTimestamp      time.Time // zero when process is UP
	upTimestamp        time.Time // zero when process is DOWN or never started
	exceeded           bool
	expiryTimer        *time.Timer
	eventCh            chan<- event.EventChannel // per-process event channel
}

// ProcessDowntimeTracker tracks cumulative downtime across restart cycles for
// managed processes. It emits two-phase events on each process's eventCh:
//
//   - Phase 1 (Exceeded=false): emitted immediately when a process goes down.
//   - Phase 2 (Exceeded=true): emitted when cumulative downtime crosses the threshold.
//
// Cumulative downtime resets when the process has been continuously UP for at
// least the threshold duration (checked lazily on the next DOWN).
type ProcessDowntimeTracker struct {
	mu     sync.Mutex
	states map[string]*processState // key: processName + "/" + configName
}

// NewProcessDowntimeTracker creates a new tracker.
func NewProcessDowntimeTracker() *ProcessDowntimeTracker {
	return &ProcessDowntimeTracker{
		states: make(map[string]*processState),
	}
}

// Register initialises tracking for a process using the threshold from the
// profile. eventCh is the channel on which EventChannel messages will be sent.
// It is safe to call multiple times; subsequent calls update the threshold and
// eventCh without resetting accumulated state.
func (t *ProcessDowntimeTracker) Register(processName, configName string, thresholds *ptpv1.ProcessDowntimeThresholds, eventCh chan<- event.EventChannel) {
	threshold := lookupThreshold(processName, thresholds)
	if threshold < 0 {
		return
	}

	key := stateKey(processName, configName)

	t.mu.Lock()
	defer t.mu.Unlock()

	if s, ok := t.states[key]; !ok {
		t.states[key] = &processState{
			threshold: threshold,
			eventCh:   eventCh,
		}
	} else {
		s.threshold = threshold
		s.eventCh = eventCh
	}
}

// OnProcessDown records the moment a process exited. It emits a Phase 1 event
// (Exceeded=false) and starts an expiry timer that will fire Phase 2 if the
// cumulative downtime crosses the threshold while the process is still down.
func (t *ProcessDowntimeTracker) OnProcessDown(processName, configName string) {
	key := stateKey(processName, configName)
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.states[key]
	if !ok {
		return
	}

	s.downTimestamp = now

	if s.exceeded {
		return
	}

	// Phase 1
	t.emitLocked(s, processName, configName, false, s.cumulativeDowntime)

	remaining := s.threshold - s.cumulativeDowntime
	if remaining <= 0 {
		s.exceeded = true
		t.emitLocked(s, processName, configName, true, s.cumulativeDowntime)
		return
	}

	s.expiryTimer = time.AfterFunc(remaining, func() {
		t.onExpiryTimer(processName, configName)
	})
}

// OnProcessUp records that a process has restarted. It accumulates the
// downtime from the last DOWN, cancels the expiry timer if it hasn't fired,
// and checks whether cumulative downtime now exceeds the threshold.
func (t *ProcessDowntimeTracker) OnProcessUp(processName, configName string) {
	key := stateKey(processName, configName)
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.states[key]
	if !ok || s.downTimestamp.IsZero() {
		return
	}

	if s.expiryTimer != nil {
		s.expiryTimer.Stop()
		s.expiryTimer = nil
	}

	thisCycleDowntime := now.Sub(s.downTimestamp)

	// Stability reset: if the process was UP long enough before this DOWN,
	// the previous stability earned a clean slate.
	if !s.upTimestamp.IsZero() {
		upDuration := s.downTimestamp.Sub(s.upTimestamp)
		if upDuration >= s.threshold {
			glog.Infof("process downtime tracker: stability reset for %s/%s (was up %v >= threshold %v)",
				processName, configName, upDuration, s.threshold)
			s.cumulativeDowntime = 0
			s.exceeded = false
		}
	}

	s.cumulativeDowntime += thisCycleDowntime
	s.downTimestamp = time.Time{}
	s.upTimestamp = now

	glog.Infof("process downtime tracker: %s/%s up after %v, cumulative %v (threshold %v)",
		processName, configName, thisCycleDowntime, s.cumulativeDowntime, s.threshold)

	if !s.exceeded && s.cumulativeDowntime > s.threshold {
		s.exceeded = true
		t.emitLocked(s, processName, configName, true, s.cumulativeDowntime)
	}
}

// HasExceeded returns true if cumulative downtime for the process has crossed
// its threshold.
func (t *ProcessDowntimeTracker) HasExceeded(processName, configName string) bool {
	key := stateKey(processName, configName)

	t.mu.Lock()
	defer t.mu.Unlock()

	if s, ok := t.states[key]; ok {
		return s.exceeded
	}
	return false
}

// IsCurrentlyDown returns true if the process is currently in a DOWN state.
func (t *ProcessDowntimeTracker) IsCurrentlyDown(processName, configName string) bool {
	key := stateKey(processName, configName)

	t.mu.Lock()
	defer t.mu.Unlock()

	if s, ok := t.states[key]; ok {
		return !s.downTimestamp.IsZero()
	}
	return false
}

// ShouldSuppress returns true if the process is within its permitted downtime
// window (Phase 1 fired, Phase 2 has not).
func (t *ProcessDowntimeTracker) ShouldSuppress(processName, configName string) bool {
	key := stateKey(processName, configName)

	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.states[key]
	if !ok {
		return false
	}
	return !s.downTimestamp.IsZero() && !s.exceeded
}

// Reset clears all tracking state for a process. Use on intentional stop or
// profile reconfiguration.
func (t *ProcessDowntimeTracker) Reset(processName, configName string) {
	key := stateKey(processName, configName)

	t.mu.Lock()
	defer t.mu.Unlock()

	if s, ok := t.states[key]; ok {
		if s.expiryTimer != nil {
			s.expiryTimer.Stop()
		}
		delete(t.states, key)
	}
}

// onExpiryTimer is called by the timer goroutine when the permitted downtime
// window expires while the process is still down.
func (t *ProcessDowntimeTracker) onExpiryTimer(processName, configName string) {
	key := stateKey(processName, configName)

	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.states[key]
	if !ok || s.exceeded {
		return
	}

	if s.downTimestamp.IsZero() {
		return
	}

	s.cumulativeDowntime += time.Since(s.downTimestamp)
	s.exceeded = true

	glog.Infof("process downtime tracker: threshold exceeded for %s/%s (cumulative %v, threshold %v)",
		processName, configName, s.cumulativeDowntime, s.threshold)

	t.emitLocked(s, processName, configName, true, s.cumulativeDowntime)
}

// emitLocked sends a process downtime event on the process's eventCh.
// Caller must hold t.mu.
func (t *ProcessDowntimeTracker) emitLocked(s *processState, processName, configName string, exceeded bool, cumulative time.Duration) {
	if s.eventCh == nil {
		return
	}
	select {
	case s.eventCh <- event.EventChannel{
		ProcessName: event.EventSource(processName),
		CfgName:     configName,
		Time:        time.Now().UnixMilli(),
		ProcessDown: &event.ProcessDownInfo{
			Exceeded:           exceeded,
			CumulativeDowntime: cumulative,
		},
	}:
	default:
		glog.Warningf("process downtime tracker: event channel full, dropping event for %s/%s exceeded=%v",
			processName, configName, exceeded)
	}
}

func stateKey(processName, configName string) string {
	return processName + "/" + configName
}

// lookupThreshold returns the threshold duration for a process name from the
// API thresholds struct. Returns -1 if the process is not recognised or
// thresholds is nil.
func lookupThreshold(processName string, thresholds *ptpv1.ProcessDowntimeThresholds) time.Duration {
	if thresholds == nil {
		return defaultThreshold(processName)
	}
	var ptr *int
	switch processName {
	case ptp4lProcessName:
		ptr = thresholds.Ptp4l
	case phc2sysProcessName:
		ptr = thresholds.Phc2sys
	case ts2phcProcessName:
		ptr = thresholds.Ts2phc
	case syncEProcessName:
		ptr = thresholds.Synce4l
	case chronydProcessName:
		ptr = thresholds.Chronyd
	case GPSD_PROCESSNAME:
		ptr = thresholds.Gpsd
	case GPSPIPE_PROCESSNAME:
		ptr = thresholds.Gpspipe
	default:
		return -1
	}
	if ptr == nil {
		return defaultThreshold(processName)
	}
	return time.Duration(*ptr) * time.Second
}

func defaultThreshold(processName string) time.Duration {
	switch processName {
	case GPSD_PROCESSNAME, GPSPIPE_PROCESSNAME:
		return 1 * time.Second
	case ptp4lProcessName, phc2sysProcessName, ts2phcProcessName,
		syncEProcessName, chronydProcessName:
		return 5 * time.Second
	default:
		return -1
	}
}

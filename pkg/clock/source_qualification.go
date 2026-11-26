package clock

import (
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/golang/glog"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/event"
	parserconstants "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/parser/constants"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/utils"
)

var sourceGeneration atomic.Uint64

const maxPendingSourceActions = 100

type sourceInputAction struct {
	generation uint64
	ready      bool
}

// SourceInputActions serializes input actions without blocking the clock loop.
type SourceInputActions struct {
	mu               sync.Mutex
	closed           bool
	generation       uint64
	configName       string
	profileName      string
	apply            func(bool) error
	desired          bool
	desiredKnown     bool
	pendingActions   chan sourceInputAction
	workerDone       chan struct{}
	activeGeneration uint64
	activeDone       chan struct{}
}

func (w *SourceInputActions) reset(generation uint64, clearAction bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.generation = generation
	w.desiredKnown = false
	w.pendingActions = make(chan sourceInputAction, maxPendingSourceActions)
	if clearAction {
		w.apply = nil
		w.profileName = ""
	}
}

func (w *SourceInputActions) configure(generation uint64, configName, profileName string, apply func(bool) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.generation != generation {
		return fmt.Errorf("source qualification changed for %s", configName)
	}
	if apply == nil {
		return fmt.Errorf("source input action is required for %s", configName)
	}
	w.configName, w.profileName, w.apply = configName, profileName, apply
	return nil
}

func (w *SourceInputActions) observe(result event.SourceQualification) {
	w.mu.Lock()
	if w.closed || w.apply == nil || result.Generation != w.generation {
		w.mu.Unlock()
		return
	}
	inputChanged := !w.desiredKnown || w.desired != result.Ready
	overflowed := false
	if inputChanged {
		w.desired, w.desiredKnown = result.Ready, true
		select {
		case w.pendingActions <- sourceInputAction{generation: result.Generation, ready: result.Ready}:
			if w.workerDone == nil {
				w.workerDone = make(chan struct{})
				go w.run(w.workerDone)
			}
		default:
			overflowed = true
		}
	}
	configName, profileName := w.configName, w.profileName
	w.mu.Unlock()
	if result.Changed {
		glog.Infof("PTPSourceQualified profile=%s config=%s source=%s port=%s qualified=%t reason=%q samples=%d",
			profileName, configName, result.SourceType, result.IFace, result.Qualified, result.Reason, result.Samples)
	}
	if overflowed {
		glog.Errorf("SOURCE INPUT ACTION QUEUE FULL for %s: DROPPING action ready=%t", configName, result.Ready)
	}
}

func (w *SourceInputActions) run(done chan struct{}) {
	for {
		w.mu.Lock()
		var action sourceInputAction
		select {
		case action = <-w.pendingActions:
		default:
			w.workerDone = nil
			close(done)
			w.mu.Unlock()
			return
		}
		if action.generation != w.generation || w.apply == nil || (w.closed && action.ready) {
			w.mu.Unlock()
			continue
		}
		apply, profileName := w.apply, w.profileName
		actionDone := make(chan struct{})
		w.activeGeneration, w.activeDone = action.generation, actionDone
		w.mu.Unlock()
		if err := apply(action.ready); err != nil {
			glog.Errorf("PTPSourceQualified hardware apply profile=%s ready=%t: %v", profileName, action.ready, err)
		}
		w.mu.Lock()
		w.activeGeneration, w.activeDone = 0, nil
		close(actionDone)
		w.mu.Unlock()
	}
}

// Done returns the current worker's completion channel, or nil when idle.
func (w *SourceInputActions) Done() <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.workerDone
}

// Close cancels pending enables and waits for any in-flight action and pending loss.
func (w *SourceInputActions) Close() {
	w.close(0, false)
}

// CloseGeneration retires this source without stopping a replacement generation.
func (w *SourceInputActions) CloseGeneration(generation uint64) {
	w.close(generation, true)
}

func (w *SourceInputActions) close(generation uint64, checkGeneration bool) {
	w.mu.Lock()
	if checkGeneration && w.generation != generation {
		var done <-chan struct{}
		if w.activeGeneration == generation {
			done = w.activeDone
		}
		w.mu.Unlock()
		if done != nil {
			<-done
		}
		return
	}
	if !w.closed {
		w.closed = true
	}
	done := w.workerDone
	w.mu.Unlock()
	if done != nil {
		<-done
	}
}

// PTPInstanceSource identifies a TR instance's timing stream across hitless
// upstream reselection. The selected physical port is metadata, not its identity.
type PTPInstanceSource struct {
	ConfigName string
	Generation uint64
}

// Equal reports whether other identifies the same TR instance and lifecycle.
func (s PTPInstanceSource) Equal(other utils.QualificationSource) bool {
	instance, ok := other.(PTPInstanceSource)
	return ok && s == instance
}

// String returns the TR configuration name.
func (s PTPInstanceSource) String() string { return s.ConfigName }

type ptpSourceQualification struct {
	state                   *utils.QualificationState
	configuredUpstreamPorts []string
	lastSelectedPort        string
	selection               parserconstants.BMCASelection
	configName              string
	generation              uint64 // Qualification lifecycle; stable across port reselection.
	observed                bool
}

func (q *ptpSourceQualification) source() utils.QualificationSource {
	return PTPInstanceSource{ConfigName: q.configName, Generation: q.generation}
}

func (q *ptpSourceQualification) ready() bool {
	return q.selection == parserconstants.BMCAExternal && q.state.Qualified()
}

// ConfigureSourceQualification installs the upstream policy before processes start.
func (c *TBC) ConfigureSourceQualification(configuredUpstreamPorts []string, policy utils.QualificationConfig) (uint64, error) {
	state, err := utils.NewQualificationState(policy)
	if err == nil && len(configuredUpstreamPorts) == 0 {
		err = fmt.Errorf("source qualification requires upstream TR ports")
	}
	generation := uint64(0)
	if err == nil {
		generation = sourceGeneration.Add(1)
	}
	c.sourceActions.reset(generation, true)
	c.ptpSource = nil // Invalid replacements fail closed as well.
	if err != nil {
		return 0, err
	}
	c.ptpSource = &ptpSourceQualification{
		state: state, configuredUpstreamPorts: slices.Clone(configuredUpstreamPorts), generation: generation,
		configName: c.cfgName,
	}
	return generation, nil
}

// SetSourceInputAction connects the clock-owned worker to the configured hardware action.
func (c *TBC) SetSourceInputAction(profileName string, apply func(bool) error) (*SourceInputActions, error) {
	if c.ptpSource == nil {
		return nil, fmt.Errorf("source qualification is not configured for %s", c.cfgName)
	}
	if err := c.sourceActions.configure(c.ptpSource.generation, c.cfgName, profileName, apply); err != nil {
		return nil, err
	}
	return &c.sourceActions, nil
}

// SourceQualification returns clock-owned upstream readiness, independently of aggregate InSync.
func (c *TBC) SourceQualification(cfg string) (event.SourceQualification, bool) {
	q := c.ptpSource
	if q == nil || cfg != c.cfgName {
		return event.SourceQualification{}, false
	}
	return event.SourceQualification{
		SourceType: event.PTP4l, IFace: q.lastSelectedPort, Generation: q.generation,
		Ready: q.ready(),
		QualificationResult: utils.QualificationResult{
			Source: q.source(), Qualified: q.state.Qualified(),
		},
	}, true
}

// ObserveSource evaluates a raw observation on the serialized clock loop.
func (c *TBC) ObserveSource(ev event.Event, observation *event.PTPSourceObservation) event.SourceQualification {
	q := c.ptpSource
	if q == nil || ev.Source != event.PTP4l || ev.CfgName != c.cfgName || observation.Generation != q.generation {
		return event.SourceQualification{}
	}
	wasReady, previousSelection := q.ready(), q.selection
	var result utils.QualificationResult
	switch {
	case observation.SourceLost:
		q.selection = parserconstants.BMCAUnknown
		result = q.state.Reset()
	case observation.Selection != parserconstants.BMCAUnknown:
		switch observation.Selection {
		case parserconstants.BMCALocal:
			q.selection = observation.Selection
			result = q.state.Reset()
			result.Reason = "BMCA selected local clock"
		case parserconstants.BMCAExternal:
			q.selection = observation.Selection
			result = utils.QualificationResult{Source: q.source(), Qualified: q.state.Qualified(), Reason: "BMCA selected external clock"}
		default:
			return event.SourceQualification{}
		}
		if observation.ClockID != "" {
			c.leadingClockData.clockID = observation.ClockID
		}
	case observation.PortRole != nil:
		// Port roles only label the timing stream; they do not change readiness.
		if !slices.Contains(q.configuredUpstreamPorts, ev.IFace) || *observation.PortRole != parserconstants.PortRoleSlave {
			return event.SourceQualification{}
		}
		q.lastSelectedPort = ev.IFace
		return event.SourceQualification{}
	default:
		if observation.ServoState == "" {
			return event.SourceQualification{}
		}
		if ev.IFace != "" && ev.IFace != "master" {
			if !slices.Contains(q.configuredUpstreamPorts, ev.IFace) || (q.lastSelectedPort != "" && ev.IFace != q.lastSelectedPort) {
				return event.SourceQualification{}
			}
			q.lastSelectedPort = ev.IFace
		}
		result = q.state.Evaluate(utils.QualificationSample{Source: q.source(), Offset: observation.Offset, ServoState: observation.ServoState,
			SourceAvailable: q.selection == parserconstants.BMCAExternal && (observation.ServoState == "s2" || observation.ServoState == "s3")})
	}
	q.observed = true
	decision := event.SourceQualification{SourceType: event.PTP4l, IFace: q.lastSelectedPort, Generation: q.generation,
		Ready: q.ready(), QualificationResult: result}
	c.sourceActions.observe(decision)
	if q.ready() != wasReady || q.selection != previousSelection || observation.SourceLost {
		c.evaluateState()
	}
	return decision
}

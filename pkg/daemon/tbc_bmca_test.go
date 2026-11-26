package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/clock"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/clockmgr"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/config"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/event"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/hardwareconfig"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/parser"
	parserconstants "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/parser/constants"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/plugin"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/pmc"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/process"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/utils"
	ptpv1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"
	"github.com/stretchr/testify/require"
)

const bmcaTestConfig = "ptp4l.1.config"

func newBMCATestProcess(t *testing.T, hcm *hardwareconfig.HardwareConfigManager) (*ptpProcess, *clockmgr.ClockManager, func() []bool) {
	t.Helper()
	InitializeOffsetMaps()
	t.Cleanup(InitializeOffsetMaps)
	profile := &ptpv1.PtpProfile{Name: utils.ToPtr("t-bc_test-profile"), PtpSettings: map[string]string{
		"clockType": TBC, "leadingInterface": "eno5", "clockId[eno5]": "123456789", "inSyncConditionThreshold": "10",
	}}
	events := make(chan event.Event, 20)
	cm := clockmgr.Init("test", events, nil, nil, nil, nil)
	clk, err := clock.NewTBC(bmcaTestConfig, cm.GetUtcOffset, &pmc.MockClient{}, "ptp4l.0.config")
	require.NoError(t, err)
	clk.SetConfiguredLeadingInterface("eno5")
	require.NoError(t, cm.AddClock(clk))
	p := &ptpProcess{
		ExecProcess: ExecProcess{name: event.Ptp4lProcessName, configName: bmcaTestConfig, messageTag: "[" + bmcaTestConfig + ":{level}]", eventCh: events},
		nodeProfile: profile, clockType: event.TBC, logParser: parser.NewPTP4LExtractor(), ptpClockThreshold: getPTPThreshold(profile),
		ifaces:        config.IFaces{{Name: "eno2"}, {Name: "eno3"}, {Name: "eno20"}},
		tBCAttributes: tBCProcessAttributes{trPortsConfigFile: bmcaTestConfig, trIfaceNames: []string{"eno2", "eno3"}},
		dn:            &Daemon{hardwareConfigManager: hcm, processManager: &ProcessManager{clockMgr: cm}},
		pm: &plugin.PluginManager{Plugins: map[string]*plugin.Plugin{
			"test": {AfterRunPTPCommand: func(_ *interface{}, _ *ptpv1.PtpProfile, _ string) error { return nil }},
		}},
	}
	policy, err := resolveSourceQualificationPolicy(profile)
	require.NoError(t, err)
	require.NoError(t, p.configureSourceQualification(policy))
	// Real aggregate prerequisites are already healthy. Retained LOCKED PTP
	// details must not establish readiness before BMCA/qualification/application.
	for i := 0; i <= event.WindowSize; i++ {
		now := time.Now().UnixMilli()
		cm.ProcessEvent(event.Event{Source: event.DPLL, CfgName: bmcaTestConfig, IFace: "eno5", Time: now, Data: &event.DPLLData{
			State: event.PTP_LOCKED, LeadingSource: true, Offset: utils.ToPtr(int64(5)),
			InSyncConditionThreshold: 100, InSyncConditionTimes: 1, ToFreeRunThreshold: 1500, MaxInSpecOffset: 500,
		}})
		cm.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: bmcaTestConfig, IFace: "eno2", Time: now,
			Data: &event.OffsetData{State: event.PTP_LOCKED, Offset: 5}})
	}
	var mu sync.Mutex
	var actions []bool
	apply := p.sourceQualification.apply
	p.sourceQualification.apply = func(ready bool) error {
		mu.Lock()
		actions = append(actions, ready)
		mu.Unlock()
		return apply(ready)
	}
	p.sourceQualification.ctx = startQualificationClock(t, cm, events)
	t.Cleanup(p.sourceQualification.close)
	return p, cm, func() []bool { mu.Lock(); defer mu.Unlock(); return append([]bool(nil), actions...) }
}

func bmcaLine(message string) string {
	return fmt.Sprintf("ptp4l[1.123]: [%s:5] %s", bmcaTestConfig, message)
}

// Read a detached snapshot after the test clock loop has processed earlier events.
func bmcaSnapshot(t *testing.T, p *ptpProcess, cm *clockmgr.ClockManager) process.EventStats {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stats, err := waitForBMCASnapshot(ctx, p, cm)
	require.NoError(t, err)
	waitForSourceActions(t, p)
	return stats
}

func waitForSourceActions(t *testing.T, p *ptpProcess) {
	t.Helper()
	if q := p.sourceQualification; q != nil {
		q.mu.Lock()
		actions := q.actions
		q.mu.Unlock()
		if actions != nil {
			done := actions.Done()
			if done == nil {
				return
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("source input actions did not finish")
			}
		}
	}
}

func waitForBMCASnapshot(ctx context.Context, p *ptpProcess, cm *clockmgr.ClockManager) (process.EventStats, error) {
	reply := qualificationTestBarrier(p.eventCh)
	barrier := event.Event{Source: event.MONITORING, CfgName: p.configName, ClockType: p.clockType,
		Data: &event.PTPSourceObservation{}}
	select {
	case p.eventCh <- barrier:
	case <-ctx.Done():
		return process.EventStats{}, fmt.Errorf("send snapshot barrier: %w", ctx.Err())
	}
	select {
	case <-reply:
	case <-ctx.Done():
		return process.EventStats{}, fmt.Errorf("wait for snapshot barrier reply: %w", ctx.Err())
	}
	select {
	case stats := <-cm.StatsUpdatesCh():
		return stats, nil
	case <-ctx.Done():
		return process.EventStats{}, fmt.Errorf("wait for clock snapshot: %w", ctx.Err())
	}
}

func TestBMCASnapshotDeadline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		message string
	}{
		{"send", "send snapshot barrier"},
		{"reply", "wait for snapshot barrier reply"},
		{"snapshot", "wait for clock snapshot"},
		{"shared deadline", "wait for clock snapshot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				capacity := 0
				if tc.name == "send" {
					capacity = 1
				}
				events := make(chan event.Event, capacity)
				t.Cleanup(func() { qualificationTestBarriers.Delete(events) })
				if capacity != 0 {
					events <- event.Event{CfgName: "earlier", Data: &event.OffsetData{}}
				}
				cm := clockmgr.Init("test", events, nil, nil, nil, nil)
				if tc.name == "snapshot" || tc.name == "shared deadline" {
					<-cm.StatsUpdatesCh()
				}
				p := &ptpProcess{ExecProcess: ExecProcess{configName: bmcaTestConfig, eventCh: events}}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				start := time.Now()
				done := make(chan error, 1)
				go func() { _, err := waitForBMCASnapshot(ctx, p, cm); done <- err }()
				if tc.name != "send" {
					if tc.name == "shared deadline" {
						time.Sleep(400 * time.Millisecond)
					}
					var barrier event.Event
					select {
					case barrier = <-events:
					case err := <-done:
						t.Fatalf("snapshot did not send a barrier: %v", err)
					}
					require.Equal(t, event.MONITORING, barrier.Source)
					require.Equal(t, bmcaTestConfig, barrier.CfgName)
					_, ok := barrier.Data.(*event.PTPSourceObservation)
					require.True(t, ok)
					if tc.name != "reply" {
						if tc.name == "shared deadline" {
							time.Sleep(400 * time.Millisecond)
						}
						qualificationTestBarrier(events) <- struct{}{}
					}
				}
				err := <-done
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.ErrorContains(t, err, tc.message)
				require.Equal(t, time.Second, time.Since(start))
			})
		})
	}
}

func exerciseTBCBMCA(t *testing.T, hcm *hardwareconfig.HardwareConfigManager, assertInput func(bool)) {
	t.Helper()
	p, cm, actions := newBMCATestProcess(t, hcm)
	line := func(message string) { p.processOutput(bmcaLine(message)) }
	assertReady := func(want bool) {
		t.Helper()
		stats := bmcaSnapshot(t, p, cm)
		require.Equal(t, want, stats.SourceQualified[bmcaTestConfig])
		if assertInput != nil {
			assertInput(want)
		}
	}
	// Initial BMCA selection starts the source stream, but fresh servo samples
	// are still required before the source qualifies.
	line("port 1 (eno2): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED")
	for i := 0; i < 100; i++ {
		line("unrelated diagnostic")
	}
	require.Empty(t, actions(), "port changes and cached zero offsets must never apply input actions")
	line("selected best master clock upstream-A")
	assertReady(false)
	for i := 0; i < 4; i++ {
		line("master offset 5 s2 freq 0 path delay 100")
	}
	assertReady(false)
	line("master offset -5 s2 freq 0 path delay 100")
	assertReady(true)
	require.Equal(t, event.PTP_LOCKED, bmcaSnapshot(t, p, cm).ClockStates[bmcaTestConfig])
	before, _ := cm.SourceQualification(bmcaTestConfig)

	// Hitless external reselection and port-role churn preserve readiness. Both
	// named and numbered roles are metadata, including a non-TR port whose name
	// collides with a configured port's prefix.
	line("port 1 (eno2): SLAVE to FAULTY on FAULT_DETECTED (FT_UNSPECIFIED)")
	line("port 2: MASTER to UNCALIBRATED on RS_SLAVE")
	line("selected best master clock upstream-B")
	line("port 2: UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED")
	line("port 3 (eno20): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED")
	line("port 2 (eno3): SLAVE to MASTER on ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES")
	assertReady(true)
	after, _ := cm.SourceQualification(bmcaTestConfig)
	require.Equal(t, event.PTP_LOCKED, bmcaSnapshot(t, p, cm).ClockStates[bmcaTestConfig], "role changes cannot force aggregate holdover")
	require.Equal(t, "eno3", after.IFace)
	require.Equal(t, before.Source, after.Source, "port selection cannot change the qualified timing stream identity")
	require.Equal(t, []bool{false, true}, actions(), "hitless reselection must not run holdover entry/exit")

	p.processOutput("ptp4l[2]: [ptp4l.0.config] selected local clock downstream-clock as best master")
	assertReady(true)
	// Local BMCA loss immediately revokes readiness despite stale LOCKED details.
	line("selected local clock arbitrary-local-id as best master")
	assertReady(false)
	require.Equal(t, event.PTP_HOLDOVER, bmcaSnapshot(t, p, cm).ClockStates[bmcaTestConfig], "stale LOCKED details cannot hide loss")
	line("port 1: UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED")
	for i := 0; i < 8; i++ {
		line("master offset 5 s2 freq 0 path delay 100")
	}
	assertReady(false)
	line("selected best master clock upstream-A")
	assertReady(false)
	for i := 0; i < 4; i++ {
		line("master offset 5 s2 freq 0 path delay 100")
	}
	assertReady(false)
	line("master offset 5 s2 freq 0 path delay 100")
	assertReady(true)
	require.Equal(t, []bool{false, true, false, true}, actions(), "recovery must re-enable input through the same apply cache")

	// Offset degradation can disqualify an externally selected source; recovery
	// requires another complete run of fresh in-range samples.
	for i := 0; i < 5; i++ {
		line("master offset 11 s2 freq 0 path delay 100")
	}
	assertReady(false)
	for i := 0; i < 5; i++ {
		line("master offset 5 s2 freq 0 path delay 100")
	}
	assertReady(true)
	p.invalidateSourceQualification()
	assertReady(false)
}

func TestTBCBMCAPluginPath(t *testing.T) {
	exerciseTBCBMCA(t, nil, nil)
}

func TestTBCBMCASelectionDuringApply(t *testing.T) {
	p, cm, actions := newBMCATestProcess(t, nil)
	cm.SetApplying(true)
	bmcaSnapshot(t, p, cm) // Drain the snapshot before the selection arrives.
	p.processOutput(bmcaLine("selected best master clock upstream-A"))
	require.False(t, bmcaSnapshot(t, p, cm).SourceQualified[bmcaTestConfig])
	require.Empty(t, actions(), "retaining a selection must not apply hardware during profile apply")
	cm.SetApplying(false)
	p.processOutput(bmcaLine("port 1 (eno2): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED"))
	for i := 0; i < 5; i++ {
		p.processOutput(bmcaLine("master offset 5 s2 freq 0 path delay 100"))
	}
	stats := bmcaSnapshot(t, p, cm)
	require.True(t, stats.SourceQualified[bmcaTestConfig], "the initial selection must survive apply without another BMCA log line")
	require.Equal(t, event.PTP_LOCKED, stats.ClockStates[bmcaTestConfig])
	require.Equal(t, []bool{false, true}, actions(), "replayed evaluation must reach the normal input-action path")
}

func TestTBCBMCAPortSelectionDuringApply(t *testing.T) {
	p, cm, actions := newBMCATestProcess(t, nil)
	cm.SetApplying(true)
	bmcaSnapshot(t, p, cm)
	roleDone, continueBMCA, stop := make(chan struct{}), make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.processOutput(bmcaLine("port 2 (eno3): UNCALIBRATED to SLAVE on MASTER_CLOCK_SELECTED"))
		close(roleDone)
		select {
		case <-continueBMCA:
		case <-stop:
			return
		}
		p.processOutput(bmcaLine("selected best master clock upstream-B"))
	}()
	t.Cleanup(func() { close(stop); p.sourceQualification.close(); <-done })
	select {
	case <-roleDone:
	case <-time.After(time.Second):
		t.Fatal("selected port blocked the scanner during apply")
	}
	bmcaSnapshot(t, p, cm) // Drain the role's snapshot before sending BMCA.
	close(continueBMCA)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("BMCA selection blocked the scanner during apply")
	}
	require.False(t, bmcaSnapshot(t, p, cm).SourceQualified[bmcaTestConfig])
	source, exists := cm.SourceQualification(bmcaTestConfig)
	require.True(t, exists)
	require.Empty(t, source.IFace, "port selection must not mutate the clock during apply")
	require.Empty(t, actions(), "retained observations must not apply hardware during profile apply")
	cm.SetApplying(false)
	for i := 0; i < 5; i++ {
		p.processOutput(bmcaLine("master offset 5 s2 freq 0 path delay 100"))
	}
	stats := bmcaSnapshot(t, p, cm)
	source, exists = cm.SourceQualification(bmcaTestConfig)
	require.True(t, exists && stats.SourceQualified[bmcaTestConfig])
	require.Equal(t, "eno3", source.IFace, "qualification must retain the selected port")
	p.tBCAttributes.offsetEventWindow = utils.NewWindow(1)
	p.eventCh = make(chan event.Event, 1)
	p.sendPtp4lOffsetEvent()
	require.Len(t, p.eventCh, 1)
	cm.ProcessEvent(<-p.eventCh)
	var selected *event.DataDetails
	for _, data := range cm.GetClock(bmcaTestConfig).ProcessData() {
		if data.ProcessName == event.PTP4l {
			selected = data.GetDataDetails("eno3")
		}
	}
	require.NotNil(t, selected, "the clock must label offsets with its selected port")
}

func TestTBCBMCAObsoleteApplyObservationCannotAct(t *testing.T) {
	for _, outcome := range []string{"cancel", "close"} {
		t.Run(outcome, func(t *testing.T) {
			p, cm, actions := newBMCATestProcess(t, nil)
			ctx, cancel := context.WithCancel(p.sourceQualification.ctx)
			defer cancel()
			p.sourceQualification.ctx = ctx
			cm.SetApplying(true)
			bmcaSnapshot(t, p, cm)
			p.observeSource("", &event.PTPSourceObservation{Selection: parserconstants.BMCAExternal})
			bmcaSnapshot(t, p, cm)
			if outcome == "cancel" {
				cancel()
			} else {
				p.sourceQualification.close()
			}
			cm.RemoveAllClocks()
			cm.SetApplying(false)
			require.Empty(t, actions(), "a stopped observer must not apply a retained result")
		})
	}
}

func TestTBCBMCAInputFailureDoesNotRetry(t *testing.T) {
	for _, failingReady := range []bool{false, true} {
		t.Run(fmt.Sprintf("ready=%t", failingReady), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, cm, _ := newBMCATestProcess(t, nil)
				line := func(message string) { p.processOutput(bmcaLine(message)) }
				line("selected best master clock upstream-A")
				for i := 0; i < 5; i++ {
					line("master offset 5 s2 freq 0 path delay 100")
				}
				require.Equal(t, event.PTP_LOCKED, bmcaSnapshot(t, p, cm).ClockStates[bmcaTestConfig])
				fail, enabled := true, true
				var actions []bool
				var actionMu sync.Mutex
				q := p.sourceQualification
				q.mu.Lock()
				apply := q.apply
				q.apply = func(ready bool) error {
					actionMu.Lock()
					defer actionMu.Unlock()
					actions = append(actions, ready)
					if ready == failingReady && fail {
						if ready {
							enabled = true // A failed write may partially enable the input.
						}
						return errors.New("pin action failed")
					}
					enabled = ready
					return apply(ready)
				}
				q.mu.Unlock()
				observed := func() ([]bool, bool) {
					actionMu.Lock()
					defer actionMu.Unlock()
					return append([]bool(nil), actions...), enabled
				}
				line("selected local clock local-id as best master")
				require.Equal(t, event.PTP_HOLDOVER, bmcaSnapshot(t, p, cm).ClockStates[bmcaTestConfig], "loss is observed even if disabling fails")
				if failingReady {
					line("selected best master clock upstream-A")
					for i := 0; i < 5; i++ {
						line("master offset 5 s2 freq 0 path delay 100")
					}
					bmcaSnapshot(t, p, cm)
				}
				want := []bool{false}
				if failingReady {
					want = append(want, true)
				}
				got, _ := observed()
				require.Equal(t, want, got, "the failing action must be attempted once")
				actionMu.Lock()
				fail = false
				actionMu.Unlock()
				time.Sleep(1500 * time.Millisecond)
				synctest.Wait()
				got, _ = observed()
				require.Equal(t, want, got, "time alone must not repeat a failed action")
				for i := 0; i < 3; i++ {
					p.observeSource("", &event.PTPSourceObservation{ServoState: "s2", Offset: 5})
				}
				selection := parserconstants.BMCALocal
				if failingReady {
					selection = parserconstants.BMCAExternal
				}
				p.observeSource("", &event.PTPSourceObservation{Selection: selection})
				stats := bmcaSnapshot(t, p, cm)
				got, _ = observed()
				require.Equal(t, want, got, "unchanged observations must not repeat a failed action")
				require.Equal(t, failingReady, stats.SourceQualified[bmcaTestConfig])
				wantClockState, wantSourceState := event.PTP_HOLDOVER, event.PTP_FREERUN
				if failingReady {
					wantClockState, wantSourceState = event.PTP_LOCKED, event.PTP_LOCKED
				}
				require.Equal(t, wantClockState, stats.ClockStates[bmcaTestConfig])
				p.tBCAttributes.offsetEventWindow = utils.NewWindow(1)
				p.sendPtp4lOffsetEvent()
				require.Equal(t, wantSourceState, bmcaSnapshot(t, p, cm).States[bmcaTestConfig][event.PTP4l], "source state follows qualification, not hardware action results")
				if failingReady {
					_, enabledNow := observed()
					require.True(t, enabledNow, "model a partially applied enable")
					line("selected local clock local-id as best master")
					bmcaSnapshot(t, p, cm)
					got, enabledNow = observed()
					require.Equal(t, []bool{false, true, false}, got, "loss must attempt to disable a partially enabled input")
					require.False(t, enabledNow)
				} else {
					line("selected best master clock upstream-A")
					for i := 0; i < 5; i++ {
						line("master offset 5 s2 freq 0 path delay 100")
					}
					require.Equal(t, event.PTP_LOCKED, bmcaSnapshot(t, p, cm).ClockStates[bmcaTestConfig])
					recoveryActions, enabledNow := observed()
					require.Equal(t, []bool{false, true}, recoveryActions, "recovery must attempt the new action")
					require.True(t, enabledNow)
				}
			})
		})
	}
}

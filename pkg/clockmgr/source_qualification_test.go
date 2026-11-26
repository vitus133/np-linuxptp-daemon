package clockmgr_test

import (
	"sync"
	"testing"
	"time"

	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/clock"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/clockmgr"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/event"
	parserconstants "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/parser/constants"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/pmc"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/process"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestSourceQualificationSnapshots(t *testing.T) {
	// Reset/remove touch shared debug state, so keep this test serial.
	m := clockmgr.Init("test", make(chan event.Event), nil, nil, nil, nil)
	set := qualificationPublisher(t, m)
	set(true)
	stats := receiveStatsSnapshot(t, m.StatsUpdatesCh())
	require.True(t, stats.SourceQualified["ptp4l.0.config"], "latest state retained even without a waiting consumer")
	require.NotEqual(t, event.PTP_LOCKED, stats.ClockStates["ptp4l.0.config"], "source qualification must not fabricate aggregate lock")
	source, ok := m.SourceQualification("ptp4l.0.config")
	require.True(t, ok)
	require.Equal(t, event.PTP4l, source.SourceType)
	require.Equal(t, clock.PTPInstanceSource{ConfigName: "ptp4l.0.config", Generation: source.Generation}, source.Source)
	require.Equal(t, "tr0", source.IFace)
	require.Empty(t, clockmgr.SnapshotStatsForTest(m, []process.StatsRequest{{ClockID: "ptp4l.0.config", Source: event.TS2PHC}}).SourceQualified)
	set(false)
	require.False(t, receiveStatsSnapshot(t, m.StatsUpdatesCh()).SourceQualified["ptp4l.0.config"])
	require.True(t, stats.SourceQualified["ptp4l.0.config"], "snapshot is detached")
	newSet := qualificationPublisher(t, m)
	require.False(t, receiveStatsSnapshot(t, m.StatsUpdatesCh()).SourceQualified["ptp4l.0.config"])
	set(true)
	require.False(t, receiveStatsSnapshot(t, m.StatsUpdatesCh()).SourceQualified["ptp4l.0.config"], "superseded owner cannot republish readiness")
	newSet(true)
	require.True(t, receiveStatsSnapshot(t, m.StatsUpdatesCh()).SourceQualified["ptp4l.0.config"])
	m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", Reset: true})
	require.False(t, receiveStatsSnapshot(t, m.StatsUpdatesCh()).SourceQualified["ptp4l.0.config"])
	newSet(true)
	require.False(t, receiveStatsSnapshot(t, m.StatsUpdatesCh()).SourceQualified["ptp4l.0.config"], "reset revokes old publisher")
	set = qualificationPublisher(t, m)
	set(true)
	m.RemoveAllClocks()
	set(true)
	require.Empty(t, receiveStatsSnapshot(t, m.StatsUpdatesCh()).SourceQualified, "removed owner cannot resurrect readiness")
	require.Empty(t, m.StatsUpdatesCh(), "removed owner cannot publish another snapshot")
}

func TestSourceInputActionTeardownDoesNotHoldManagerLock(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "remove", true: "replace"}[replace], func(t *testing.T) {
			m := clockmgr.Init("test", make(chan event.Event), nil, nil, nil, nil)
			qualificationPublisher(t, m)
			source, exists := m.SourceQualification("ptp4l.0.config")
			require.True(t, exists)
			started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			var releaseOnce sync.Once
			finish := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(finish)
			_, err := m.SetSourceInputAction("ptp4l.0.config", source.Generation, "test", func(bool) error {
				close(started)
				<-release
				m.SourceQualification("ptp4l.0.config")
				return nil
			})
			require.NoError(t, err)
			m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config",
				Data: &event.PTPSourceObservation{Generation: source.Generation, Selection: parserconstants.BMCAExternal}})
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("input action did not start")
			}
			go func() {
				if replace {
					clk, err := clock.NewTBC("ptp4l.0.config", m.GetUtcOffset, &pmc.MockClient{}, "ptp4.1.config")
					if err == nil {
						err = m.AddClock(clk)
					}
					done <- err
				} else {
					m.RemoveAllClocks()
					done <- nil
				}
			}()
			time.Sleep(10 * time.Millisecond)
			finish()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("clock teardown deadlocked with the input action")
			}
		})
	}
}

func TestSourceInputActionRejectsObsoleteGeneration(t *testing.T) {
	m := clockmgr.Init("test", make(chan event.Event), nil, nil, nil, nil)
	qualificationPublisher(t, m)
	old, exists := m.SourceQualification("ptp4l.0.config")
	require.True(t, exists)
	generation, err := m.ConfigureSourceQualification("ptp4l.0.config", []string{"tr0"}, utils.QualificationConfig{
		QualifiedThreshold: 100, DisqualifiedThreshold: 200, QualifiedSamples: 1, DisqualifiedSamples: 1})
	require.NoError(t, err)
	_, err = m.SetSourceInputAction("ptp4l.0.config", old.Generation, "old", func(bool) error { return nil })
	require.Error(t, err)
	_, err = m.SetSourceInputAction("ptp4l.0.config", generation, "new", nil)
	require.Error(t, err)
	actions, err := m.SetSourceInputAction("ptp4l.0.config", generation, "new", func(bool) error { return nil })
	require.NoError(t, err)
	t.Cleanup(actions.Close)
}

func qualificationPublisher(t *testing.T, m *clockmgr.ClockManager) func(bool) {
	t.Helper()
	clk, err := clock.NewTBC("ptp4l.0.config", m.GetUtcOffset, &pmc.MockClient{}, "ptp4.1.config")
	require.NoError(t, err)
	require.NoError(t, m.AddClock(clk))
	generation, err := m.ConfigureSourceQualification("ptp4l.0.config", []string{"tr0"}, utils.QualificationConfig{
		QualifiedThreshold: 100, DisqualifiedThreshold: 200, QualifiedSamples: 1, DisqualifiedSamples: 1})
	require.NoError(t, err)
	return func(qualified bool) {
		if qualified {
			m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", Data: &event.PTPSourceObservation{
				Generation: generation, Selection: parserconstants.BMCAExternal}})
			m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", IFace: "tr0", Data: &event.PTPSourceObservation{
				Generation: generation, PortRole: utils.ToPtr(parserconstants.PortRoleSlave)}})
		}
		m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", IFace: "tr0", Data: &event.PTPSourceObservation{
			Generation: generation, ServoState: "s2", Offset: 10, SourceLost: !qualified}})
	}
}

func TestSourceQualificationEventRoundTrip(t *testing.T) {
	events := make(chan event.Event, 2)
	m := clockmgr.Init("test", events, nil, nil, nil, nil)
	qualificationPublisher(t, m)
	generation, err := m.ConfigureSourceQualification("ptp4l.0.config", []string{"tr0"}, utils.QualificationConfig{
		QualifiedThreshold: 100, DisqualifiedThreshold: 200, QualifiedSamples: 2, DisqualifiedSamples: 1})
	require.NoError(t, err)
	role := &event.PTPSourceObservation{Generation: generation, PortRole: utils.ToPtr(parserconstants.PortRoleSlave)}
	sample := &event.PTPSourceObservation{Generation: generation, ServoState: "s2", Offset: 10}
	wrap := func(data event.EventData) event.Event {
		return event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", IFace: "tr0", Data: data}
	}
	events <- wrap(role)
	events <- wrap(sample)
	require.False(t, clockmgr.SnapshotStatsForTest(m, []process.StatsRequest{{ClockID: "ptp4l.0.config"}}).SourceQualified["ptp4l.0.config"], "queued observations are not evaluated readiness")
	m.ProcessEvent(<-events)
	selected, exists := m.SourceQualification("ptp4l.0.config")
	require.True(t, exists)
	require.Equal(t, "tr0", selected.IFace)
	require.False(t, selected.Qualified)
	m.ProcessEvent(wrap(&event.PTPSourceObservation{Generation: generation, Selection: parserconstants.BMCAExternal}))
	m.ProcessEvent(<-events)
	result, exists := m.SourceQualification("ptp4l.0.config")
	require.True(t, exists)
	require.False(t, result.Qualified)
	require.Equal(t, clock.PTPInstanceSource{ConfigName: "ptp4l.0.config", Generation: generation}, result.Source)
	m.ProcessEvent(wrap(&event.OffsetData{State: event.PTP_LOCKED, Offset: 10}))
	require.False(t, clockmgr.SnapshotStatsForTest(m, []process.StatsRequest{{ClockID: "ptp4l.0.config"}}).SourceQualified["ptp4l.0.config"], "averaged offsets must not count as fresh qualification samples")
	m.ProcessEvent(wrap(sample))
	result, exists = m.SourceQualification("ptp4l.0.config")
	require.True(t, exists && result.Qualified)
	m.SetApplying(true)
	m.ProcessEvent(wrap(sample))
	require.False(t, receiveStatsSnapshot(t, m.StatsUpdatesCh()).SourceQualified["ptp4l.0.config"], "ordinary samples are suppressed during apply")
	m.SetApplying(false)
	m.RemoveAllClocks()
	m.ProcessEvent(wrap(sample))
	_, exists = m.SourceQualification("ptp4l.0.config")
	require.False(t, exists, "removed clocks must ignore their old scanner")
}

func TestSourceQualificationBMCARetainedDuringApply(t *testing.T) {
	for _, selection := range []parserconstants.BMCASelection{parserconstants.BMCAExternal, parserconstants.BMCALocal} {
		t.Run(string(selection), func(t *testing.T) {
			m := clockmgr.Init("test", make(chan event.Event), nil, nil, nil, nil)
			qualificationPublisher(t, m)
			source, ok := m.SourceQualification("ptp4l.0.config")
			require.True(t, ok)
			observation := &event.PTPSourceObservation{Generation: source.Generation, Selection: selection}
			wrap := func(data event.EventData) event.Event {
				return event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", IFace: "tr0", Data: data}
			}

			m.SetApplying(true)
			m.ProcessEvent(wrap(observation))
			require.Equal(t, event.PTP_NOTSET, receiveStatsSnapshot(t, m.StatsUpdatesCh()).ClockStates["ptp4l.0.config"], "retention must not evaluate the clock during apply")
			sample := &event.PTPSourceObservation{Generation: source.Generation, ServoState: "s2", Offset: 10}
			m.ProcessEvent(wrap(sample))

			m.SetApplying(false)
			result, exists := m.SourceQualification("ptp4l.0.config")
			require.True(t, exists)
			require.Equal(t, source.Generation, result.Generation)
			require.False(t, result.Ready, "suppressed samples must not count towards qualification")
			m.ProcessEvent(wrap(sample))
			result, exists = m.SourceQualification("ptp4l.0.config")
			require.True(t, exists)
			require.Equal(t, selection == parserconstants.BMCAExternal, result.Ready, "fresh samples must use the retained selection without another BMCA event")
			m.SetApplying(false)
			replayed, exists := m.SourceQualification("ptp4l.0.config")
			require.True(t, exists)
			require.Equal(t, result, replayed, "the retained observation must be evaluated only once")
		})
	}
}

func TestSourceQualificationPortSelectionReplayedAfterApply(t *testing.T) {
	m := clockmgr.Init("test", make(chan event.Event), nil, nil, nil, nil)
	qualificationPublisher(t, m)
	_, err := m.ConfigureSourceQualification("ptp4l.0.config", []string{"tr0", "tr1"}, utils.QualificationConfig{
		QualifiedThreshold: 100, DisqualifiedThreshold: 200, QualifiedSamples: 1, DisqualifiedSamples: 1})
	require.NoError(t, err)
	source, exists := m.SourceQualification("ptp4l.0.config")
	require.True(t, exists)
	role := &event.PTPSourceObservation{Generation: source.Generation, PortRole: utils.ToPtr(parserconstants.PortRoleSlave)}
	selection := &event.PTPSourceObservation{Generation: source.Generation, Selection: parserconstants.BMCAExternal}
	m.SetApplying(true)
	m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", IFace: "tr0", Data: role})
	*role.PortRole = parserconstants.PortRoleMaster // Reusing the observation must not alter the replay.
	before, _ := m.SourceQualification("ptp4l.0.config")
	require.Empty(t, before.IFace, "the clock must not change during apply")
	m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", Data: selection})
	m.SetApplying(false)
	after, exists := m.SourceQualification("ptp4l.0.config")
	require.True(t, exists)
	require.Equal(t, "tr0", after.IFace, "port selection must be replayed before BMCA")
	m.SetApplying(true)
	laterRole := &event.PTPSourceObservation{Generation: source.Generation, PortRole: utils.ToPtr(parserconstants.PortRoleSlave)}
	m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", IFace: "tr1", Data: laterRole})
	m.SetApplying(false)
	after, _ = m.SourceQualification("ptp4l.0.config")
	require.Equal(t, "tr1", after.IFace, "later port selections must retain their order")
	m.SetApplying(true)
	obsolete := &event.PTPSourceObservation{Generation: source.Generation, PortRole: utils.ToPtr(parserconstants.PortRoleSlave)}
	m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", IFace: "tr0", Data: obsolete})
	m.RemoveAllClocks()
	qualificationPublisher(t, m)
	m.SetApplying(false)
	replacement, exists := m.SourceQualification("ptp4l.0.config")
	require.True(t, exists)
	require.Empty(t, replacement.IFace, "an obsolete port must not affect a replacement clock")
}

func TestSourceQualificationBMCAApplyOrder(t *testing.T) {
	m := clockmgr.Init("test", make(chan event.Event), nil, nil, nil, nil)
	set := qualificationPublisher(t, m)
	set(true)
	source, ok := m.SourceQualification("ptp4l.0.config")
	require.True(t, ok)
	require.True(t, source.Ready)
	m.SetApplying(true)
	for _, selection := range []parserconstants.BMCASelection{parserconstants.BMCALocal, parserconstants.BMCAExternal} {
		observation := &event.PTPSourceObservation{Generation: source.Generation, Selection: selection}
		m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", Data: observation})
	}
	m.SetApplying(false)
	result, exists := m.SourceQualification("ptp4l.0.config")
	require.True(t, exists)
	require.False(t, result.Qualified, "the local selection must reset qualification before the subsequent external selection")
	sample := &event.PTPSourceObservation{Generation: source.Generation, ServoState: "s2", Offset: 10}
	m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", IFace: "tr0", Data: sample})
	result, exists = m.SourceQualification("ptp4l.0.config")
	require.True(t, exists && result.Ready, "the final external selection must be retained in arrival order")
}

func TestSourceQualificationPendingBMCAInvalidation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		invalidate func(*testing.T, *clockmgr.ClockManager)
	}{
		{"removed", func(_ *testing.T, m *clockmgr.ClockManager) { m.RemoveAllClocks() }},
		{"replaced", func(t *testing.T, m *clockmgr.ClockManager) { qualificationPublisher(t, m) }},
		{"reconfigured", func(t *testing.T, m *clockmgr.ClockManager) {
			_, err := m.ConfigureSourceQualification("ptp4l.0.config", []string{"tr0"}, utils.QualificationConfig{
				QualifiedThreshold: 100, DisqualifiedThreshold: 200, QualifiedSamples: 1, DisqualifiedSamples: 1})
			require.NoError(t, err)
		}},
		{"invalid reconfiguration", func(t *testing.T, m *clockmgr.ClockManager) {
			_, err := m.ConfigureSourceQualification("ptp4l.0.config", nil, utils.QualificationConfig{})
			require.Error(t, err)
		}},
		{"PTP reset", func(_ *testing.T, m *clockmgr.ClockManager) {
			m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", Reset: true})
		}},
		{"all-source reset", func(_ *testing.T, m *clockmgr.ClockManager) {
			m.ProcessEvent(event.Event{CfgName: "ptp4l.0.config", Reset: true})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := clockmgr.Init("test", make(chan event.Event), nil, nil, nil, nil)
			qualificationPublisher(t, m)
			source, ok := m.SourceQualification("ptp4l.0.config")
			require.True(t, ok)
			observation := &event.PTPSourceObservation{Generation: source.Generation, Selection: parserconstants.BMCAExternal}
			ev := event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", Data: observation}
			m.SetApplying(true)
			m.ProcessEvent(ev)
			tc.invalidate(t, m)
			qualificationPublisher(t, m)
			m.ProcessEvent(ev)
			m.SetApplying(false)
			source, ok = m.SourceQualification("ptp4l.0.config")
			require.True(t, ok)
			sample := &event.PTPSourceObservation{Generation: source.Generation, ServoState: "s2", Offset: 10}
			m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", IFace: "tr0", Data: sample})
			replacement, exists := m.SourceQualification("ptp4l.0.config")
			require.True(t, exists)
			require.False(t, replacement.Ready, "an old selection must not establish availability in the replacement")
		})
	}
}

func TestSourceQualificationPendingBMCASurvivesAggregateReset(t *testing.T) {
	for _, source := range []event.EventSource{event.DPLL, event.TS2PHC} {
		t.Run(string(source), func(t *testing.T) {
			m := clockmgr.Init("test", make(chan event.Event), nil, nil, nil, nil)
			qualificationPublisher(t, m)
			qualification, ok := m.SourceQualification("ptp4l.0.config")
			require.True(t, ok)
			observation := &event.PTPSourceObservation{Generation: qualification.Generation, Selection: parserconstants.BMCAExternal}
			m.SetApplying(true)
			m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", Data: observation})
			m.ProcessEvent(event.Event{Source: source, CfgName: "ts2phc.0.config", Reset: true})
			m.SetApplying(false)
			sample := &event.PTPSourceObservation{Generation: qualification.Generation, ServoState: "s2", Offset: 10}
			m.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", IFace: "tr0", Data: sample})
			result, exists := m.SourceQualification("ptp4l.0.config")
			require.True(t, exists && result.Ready)
		})
	}
}

func TestSourceLossDuringApplyInvalidatesPendingSelection(t *testing.T) {
	m := clockmgr.Init("test", make(chan event.Event), nil, nil, nil, nil)
	qualificationPublisher(t, m)
	source, exists := m.SourceQualification("ptp4l.0.config")
	require.True(t, exists)
	wrap := func(observation *event.PTPSourceObservation) event.Event {
		return event.Event{Source: event.PTP4l, CfgName: "ptp4l.0.config", IFace: "tr0", Data: observation}
	}
	m.SetApplying(true)
	m.ProcessEvent(wrap(&event.PTPSourceObservation{Generation: source.Generation, Selection: parserconstants.BMCAExternal}))
	m.ProcessEvent(wrap(&event.PTPSourceObservation{Generation: source.Generation, SourceLost: true}))
	m.SetApplying(false)
	m.ProcessEvent(wrap(&event.PTPSourceObservation{Generation: source.Generation, ServoState: "s2", Offset: 10}))
	after, exists := m.SourceQualification("ptp4l.0.config")
	require.True(t, exists)
	require.False(t, after.Ready, "a source loss must invalidate an earlier pending selection")
}

func TestSourceQualificationApplyingRejectsUnrelatedObservations(t *testing.T) {
	m := clockmgr.Init("test", make(chan event.Event), nil, nil, nil, nil)
	qualificationPublisher(t, m)
	source, ok := m.SourceQualification("ptp4l.0.config")
	require.True(t, ok)
	m.SetApplying(true)
	for _, ev := range []event.Event{
		{Source: event.PTP4l, CfgName: "missing", Data: &event.PTPSourceObservation{Generation: source.Generation, Selection: parserconstants.BMCAExternal}},
		{Source: event.PTP4l, CfgName: "ts2phc.0.config", Data: &event.PTPSourceObservation{Generation: source.Generation, Selection: parserconstants.BMCAExternal}},
		{Source: event.TS2PHC, CfgName: "ptp4l.0.config", Data: &event.PTPSourceObservation{Generation: source.Generation, Selection: parserconstants.BMCAExternal}},
		{Source: event.PTP4l, CfgName: "ptp4l.0.config", Data: &event.PTPSourceObservation{Generation: source.Generation + 1, Selection: parserconstants.BMCAExternal}},
		{Source: event.PTP4l, CfgName: "ptp4l.0.config", Data: &event.PTPSourceObservation{Generation: source.Generation, PortRole: utils.ToPtr(parserconstants.PortRoleSlave)}},
		{Source: event.PTP4l, CfgName: "ptp4l.0.config", IFace: "tr0", Data: &event.PTPSourceObservation{Generation: source.Generation, PortRole: utils.ToPtr(parserconstants.PortRoleMaster)}},
	} {
		m.ProcessEvent(ev)
	}
	m.SetApplying(false)
	after, exists := m.SourceQualification("ptp4l.0.config")
	require.True(t, exists)
	require.False(t, after.Ready)
	require.Empty(t, after.IFace, "unrelated observations must not select a port")
}

func TestSourceQualificationApplyPublishesReadiness(t *testing.T) {
	m := clockmgr.Init("test", make(chan event.Event), nil, nil, nil, nil)
	set := qualificationPublisher(t, m)
	set(true)
	require.True(t, receiveStatsSnapshot(t, m.StatsUpdatesCh()).SourceQualified["ptp4l.0.config"])
	m.SetApplying(true)
	require.False(t, receiveStatsSnapshot(t, m.StatsUpdatesCh()).SourceQualified["ptp4l.0.config"])
	m.SetApplying(false)
	require.True(t, receiveStatsSnapshot(t, m.StatsUpdatesCh()).SourceQualified["ptp4l.0.config"], "apply completion must publish unsuppressed readiness even without another observation")
}

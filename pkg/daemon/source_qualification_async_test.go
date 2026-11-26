package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/event"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/parser"
	parserconstants "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/parser/constants"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestSourceObservationDoesNotWaitForProfileApply(t *testing.T) {
	p, cm, _ := newBMCATestProcess(t, nil)
	cm.SetApplying(true)
	bmcaSnapshot(t, p, cm)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.processOutput(bmcaLine("selected best master clock upstream-A"))
	}()
	t.Cleanup(func() { p.sourceQualification.close(); cm.SetApplying(false); <-done })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scanner waited for profile apply")
	}
}

func TestSourceForwardingUsesConfiguredClockID(t *testing.T) {
	p, _, _ := newBMCATestProcess(t, nil)
	p.eventCh = make(chan event.Event, 1)
	p.forwardSourceData(nil, &parser.PTPEvent{ConfigName: bmcaTestConfig, BMCASelection: parserconstants.BMCAExternal})
	require.Len(t, p.eventCh, 1)
	observation, ok := (<-p.eventCh).Data.(*event.PTPSourceObservation)
	require.True(t, ok)
	clockID, err := p.getPTPClockID()
	require.NoError(t, err)
	require.Equal(t, clockID, observation.ClockID)
}

func TestSourceObservationDoesNotWaitForHardware(t *testing.T) {
	p, cm, _ := newBMCATestProcess(t, nil)
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once, startOnce sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	q := p.sourceQualification
	q.mu.Lock()
	apply := q.apply
	q.apply = func(ready bool) error {
		startOnce.Do(func() { close(started); <-release })
		return apply(ready)
	}
	q.mu.Unlock()
	go func() {
		defer close(done)
		p.processOutput(bmcaLine("selected best master clock upstream-A"))
	}()
	t.Cleanup(func() { finish(); q.close(); <-done })
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("hardware action did not start")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scanner waited for the hardware action")
	}
	moreDone := make(chan struct{})
	go func() {
		defer close(moreDone)
		for i := 0; i < 5; i++ {
			p.processOutput(bmcaLine("master offset 5 s2 freq 0 path delay 100"))
		}
		p.processOutput(bmcaLine("selected local clock local-id as best master"))
	}()
	t.Cleanup(func() { finish(); <-moreDone })
	select {
	case <-moreDone:
	case <-time.After(time.Second):
		t.Fatal("scanner could not read subsequent observations while hardware was blocked")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stats, err := waitForBMCASnapshot(ctx, p, cm)
	require.NoError(t, err)
	require.False(t, stats.SourceQualified[bmcaTestConfig], "source loss must reach the clock while hardware is blocked")
}

func TestScannerReadsWhileSourceInputActionIsBlocked(t *testing.T) {
	p, _, _ := newBMCATestProcess(t, nil)
	started, release := make(chan struct{}), make(chan struct{})
	var once, startOnce sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	q := p.sourceQualification
	q.mu.Lock()
	q.apply = func(bool) error {
		startOnce.Do(func() { close(started); <-release })
		return nil
	}
	q.mu.Unlock()
	reader, writer := io.Pipe()
	p.runScanner(reader)
	written, writerDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(writerDone)
		if _, err := fmt.Fprintln(writer, bmcaLine("selected best master clock upstream-A")); err != nil {
			return
		}
		if _, err := fmt.Fprintln(writer, bmcaLine("unrelated diagnostic")); err == nil {
			close(written)
		}
		_ = writer.Close()
	}()
	t.Cleanup(func() {
		finish()
		q.close()
		_ = reader.Close()
		_ = writer.Close()
		<-writerDone
		p.wg.Wait()
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("input action did not start")
	}
	select {
	case <-written:
	case <-time.After(time.Second):
		t.Fatal("scanner stopped reading while hardware was blocked")
	}
}

func TestSourceObservationOverflowDropsEvent(t *testing.T) {
	p := &ptpProcess{
		ExecProcess:         ExecProcess{name: event.Ptp4lProcessName, configName: "ptp4l.0.config", eventCh: make(chan event.Event, 1)},
		sourceQualification: &sourceQualificationRuntime{generation: 7, ctx: context.Background()},
	}
	p.eventCh <- event.Event{CfgName: "occupied"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.observeSource("", &event.PTPSourceObservation{Selection: parserconstants.BMCAExternal})
	}()
	t.Cleanup(func() { p.sourceQualification.close(); <-done })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("full event channel blocked the scanner")
	}
	require.Equal(t, "occupied", (<-p.eventCh).CfgName)
	select {
	case ev := <-p.eventCh:
		t.Fatalf("overflowed event was unexpectedly recovered: %v", ev)
	case <-time.After(20 * time.Millisecond):
	}
	p.observeSource("", &event.PTPSourceObservation{Selection: parserconstants.BMCALocal})
	ev := <-p.eventCh
	observation, ok := ev.Data.(*event.PTPSourceObservation)
	require.True(t, ok)
	require.Equal(t, parserconstants.BMCALocal, observation.Selection, "later events must still be sent")
}

func TestAggregateRecoveryFollowsDPLLNotHardwareResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, cm, _ := newBMCATestProcess(t, nil)
		pushDPLL := func(state event.PTPState) {
			cm.ProcessEvent(event.Event{Source: event.DPLL, CfgName: bmcaTestConfig, IFace: "eno5", ClockType: event.TBC, Time: time.Now().UnixMilli(), Data: &event.DPLLData{
				State: state, LeadingSource: true, Offset: utils.ToPtr(int64(5)), InSyncConditionThreshold: 100,
				InSyncConditionTimes: 1, ToFreeRunThreshold: 1500, MaxInSpecOffset: 500,
			}})
		}
		pushDPLL(event.PTP_HOLDOVER)
		p.sourceQualification.mu.Lock()
		p.sourceQualification.apply = func(ready bool) error {
			if ready {
				return errors.New("simulated partial enable failure")
			}
			return nil
		}
		p.sourceQualification.mu.Unlock()
		p.processOutput(bmcaLine("selected best master clock upstream-A"))
		for i := 0; i < 5; i++ {
			p.processOutput(bmcaLine("master offset 5 s2 freq 0 path delay 100"))
		}
		require.NotEqual(t, event.PTP_LOCKED, bmcaSnapshot(t, p, cm).ClockStates[bmcaTestConfig])
		time.Sleep(16 * time.Second)
		for i := 0; i <= event.WindowSize; i++ {
			cm.ProcessEvent(event.Event{Source: event.PTP4l, CfgName: bmcaTestConfig, IFace: "eno2", ClockType: event.TBC,
				Time: time.Now().UnixMilli(), Data: &event.OffsetData{State: event.PTP_LOCKED, Offset: 5}})
			pushDPLL(event.PTP_HOLDOVER)
		}
		require.NotEqual(t, event.PTP_LOCKED, bmcaSnapshot(t, p, cm).ClockStates[bmcaTestConfig])
		pushDPLL(event.PTP_LOCKED)
		require.Equal(t, event.PTP_LOCKED, bmcaSnapshot(t, p, cm).ClockStates[bmcaTestConfig], "reported DPLL lock and converged offsets must determine recovery")
	})
}

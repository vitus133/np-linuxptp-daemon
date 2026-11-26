package clock

import (
	"sync"
	"testing"
	"time"

	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/event"
	"github.com/stretchr/testify/require"
)

func waitSourceInputActions(t *testing.T, actions *SourceInputActions) {
	t.Helper()
	if done := actions.Done(); done != nil {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("source input actions did not finish")
		}
	}
}

func TestSourceInputActionQueueIsBuffered(t *testing.T) {
	var actions SourceInputActions
	actions.reset(7, true)
	require.Equal(t, maxPendingSourceActions, cap(actions.pendingActions))
}

func TestSourceInputActionsAreOrdered(t *testing.T) {
	started, release := make(chan bool, 3), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	first := true
	var actions SourceInputActions
	actions.reset(7, true)
	require.NoError(t, actions.configure(7, "cfg", "profile", func(ready bool) error {
		started <- ready
		if first {
			first = false
			<-release
		}
		return nil
	}))
	t.Cleanup(func() { finish(); actions.Close() })
	decision := func(ready bool) { actions.observe(event.SourceQualification{Generation: 7, Ready: ready}) }
	decision(false)
	select {
	case ready := <-started:
		require.False(t, ready)
	case <-time.After(time.Second):
		t.Fatal("first input action did not start")
	}
	decision(true)
	decision(false)
	require.Empty(t, started, "later actions must wait for the in-flight action")
	finish()
	for _, want := range []bool{true, false} {
		select {
		case ready := <-started:
			require.Equal(t, want, ready)
		case <-time.After(time.Second):
			t.Fatal("pending input action did not run")
		}
	}
	waitSourceInputActions(t, &actions)
	decision(true)
	select {
	case ready := <-started:
		require.True(t, ready, "the worker must restart after becoming idle")
	case <-time.After(time.Second):
		t.Fatal("idle input worker did not restart")
	}
	waitSourceInputActions(t, &actions)
}

func TestSourceInputActionOverflowDropsAction(t *testing.T) {
	started, release := make(chan bool, maxPendingSourceActions+1), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	first := true
	var actions SourceInputActions
	actions.reset(7, true)
	require.NoError(t, actions.configure(7, "cfg", "profile", func(ready bool) error {
		started <- ready
		if first {
			first = false
			<-release
		}
		return nil
	}))
	t.Cleanup(func() { finish(); actions.Close() })
	actions.observe(event.SourceQualification{Generation: 7, Ready: false})
	select {
	case ready := <-started:
		require.False(t, ready)
	case <-time.After(time.Second):
		t.Fatal("first input action did not start")
	}
	for i := 0; i < maxPendingSourceActions; i++ {
		actions.observe(event.SourceQualification{Generation: 7, Ready: i%2 == 0})
	}
	actions.observe(event.SourceQualification{Generation: 7, Ready: true})
	actions.observe(event.SourceQualification{Generation: 7, Ready: true})
	actions.mu.Lock()
	pending := len(actions.pendingActions)
	actions.mu.Unlock()
	require.Equal(t, maxPendingSourceActions, pending, "overflowed actions must not be retried")
	finish()
	for i := 0; i < maxPendingSourceActions; i++ {
		select {
		case ready := <-started:
			require.Equal(t, i%2 == 0, ready, "queued actions must retain their order")
		case <-time.After(time.Second):
			t.Fatal("queued input action did not run")
		}
	}
	waitSourceInputActions(t, &actions)
	require.Empty(t, started)
}

func TestSourceInputActionShutdownPreservesPendingLoss(t *testing.T) {
	started, release := make(chan bool, 3), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	var actions SourceInputActions
	actions.reset(7, true)
	require.NoError(t, actions.configure(7, "cfg", "profile", func(ready bool) error {
		started <- ready
		if ready {
			<-release
		}
		return nil
	}))
	t.Cleanup(func() { finish(); actions.Close() })
	actions.observe(event.SourceQualification{Generation: 7, Ready: true})
	select {
	case ready := <-started:
		require.True(t, ready)
	case <-time.After(time.Second):
		t.Fatal("input enable did not start")
	}
	actions.observe(event.SourceQualification{Generation: 7, Ready: false})
	actions.observe(event.SourceQualification{Generation: 7, Ready: true})
	actions.observe(event.SourceQualification{Generation: 7, Ready: false})
	closed := make(chan struct{})
	go func() { actions.Close(); close(closed) }()
	require.Eventually(t, func() bool {
		actions.mu.Lock()
		defer actions.mu.Unlock()
		return actions.closed
	}, time.Second, time.Millisecond)
	finish()
	for i := 0; i < 2; i++ {
		select {
		case ready := <-started:
			require.False(t, ready, "queued losses must run but pending enables must be cancelled")
		case <-time.After(time.Second):
			t.Fatal("teardown discarded a pending loss action")
		}
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("teardown did not join the input worker")
	}
}

func TestSourceInputActionsDiscardOldGeneration(t *testing.T) {
	started, release := make(chan bool, 3), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	first := true
	var actions SourceInputActions
	actions.reset(7, true)
	require.NoError(t, actions.configure(7, "cfg", "profile", func(ready bool) error {
		started <- ready
		if first {
			first = false
			<-release
		}
		return nil
	}))
	t.Cleanup(func() { finish(); actions.Close() })
	actions.observe(event.SourceQualification{Generation: 7, Ready: false})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first input action did not start")
	}
	actions.observe(event.SourceQualification{Generation: 7, Ready: true})
	actions.reset(8, false)
	actions.observe(event.SourceQualification{Generation: 8, Ready: false})
	finish()
	select {
	case ready := <-started:
		require.False(t, ready, "an old generation must not enable the input")
	case <-time.After(time.Second):
		t.Fatal("new-generation action did not run")
	}
	waitSourceInputActions(t, &actions)
	require.Empty(t, started)
}

func TestOldSourceCannotCloseReplacementActions(t *testing.T) {
	var actions SourceInputActions
	actions.reset(7, true)
	require.NoError(t, actions.configure(7, "cfg", "old", func(bool) error { return nil }))
	actions.reset(8, true)
	called := make(chan bool, 1)
	require.NoError(t, actions.configure(8, "cfg", "new", func(ready bool) error { called <- ready; return nil }))
	t.Cleanup(actions.Close)
	actions.CloseGeneration(7)
	actions.observe(event.SourceQualification{Generation: 8, Ready: true})
	select {
	case ready := <-called:
		require.True(t, ready)
	case <-time.After(time.Second):
		t.Fatal("old source closed the replacement input worker")
	}
}

func TestOldSourceTeardownWaitsOnlyForItsAction(t *testing.T) {
	oldStarted, oldRelease := make(chan struct{}), make(chan struct{})
	newStarted, newRelease := make(chan struct{}), make(chan struct{})
	var oldOnce, newOnce sync.Once
	finishOld := func() { oldOnce.Do(func() { close(oldRelease) }) }
	finishNew := func() { newOnce.Do(func() { close(newRelease) }) }
	var actions SourceInputActions
	actions.reset(7, true)
	require.NoError(t, actions.configure(7, "cfg", "old", func(bool) error {
		close(oldStarted)
		<-oldRelease
		return nil
	}))
	t.Cleanup(func() { finishOld(); finishNew(); actions.Close() })
	actions.observe(event.SourceQualification{Generation: 7, Ready: true})
	select {
	case <-oldStarted:
	case <-time.After(time.Second):
		t.Fatal("old input action did not start")
	}
	actions.reset(8, true)
	require.NoError(t, actions.configure(8, "cfg", "new", func(bool) error {
		close(newStarted)
		<-newRelease
		return nil
	}))
	actions.observe(event.SourceQualification{Generation: 8, Ready: true})
	oldClosed := make(chan struct{})
	go func() { actions.CloseGeneration(7); close(oldClosed) }()
	select {
	case <-oldClosed:
		t.Fatal("old source teardown did not wait for its in-flight action")
	case <-time.After(20 * time.Millisecond):
	}
	finishOld()
	select {
	case <-newStarted:
	case <-time.After(time.Second):
		t.Fatal("replacement input action did not start")
	}
	select {
	case <-oldClosed:
	case <-time.After(time.Second):
		t.Fatal("old source teardown waited for the replacement action")
	}
}

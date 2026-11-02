package traffic

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

type stalledWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *stalledWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

func TestBlockedLogSinkHasBoundedQueueAndCannotHoldShutdown(t *testing.T) {
	upstream, _ := backend(t)
	baselineGoroutines := runtime.NumGoroutine()
	writer := &stalledWriter{entered: make(chan struct{}), release: make(chan struct{})}
	g, err := NewGateway(Config{Upstream: upstream, MaxConnections: 1, DialTimeout: time.Second, IdleTimeout: time.Second, ShutdownTimeout: 40 * time.Millisecond, Log: writer})
	if err != nil {
		t.Fatal(err)
	}
	ln := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		close(writer.release)
		select {
		case <-g.logDone:
		case <-time.After(time.Second):
			t.Error("released log writer did not terminate")
		}
	})
	cfg := probeConfig(ln.Addr().String())
	for i := 0; i < logQueueCapacity+12; i++ {
		if err := probeOnce(context.Background(), cfg, []byte("echo"), make([]byte, 4)); err != nil {
			t.Fatalf("blocked logging changed echo behavior: %v", err)
		}
		waitFor(t, func() bool { return g.Metrics()["active_connections"].(int) == 0 })
	}
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("log sink was never called")
	}
	m := g.Metrics()
	if m["log_queue_length"].(int) != logQueueCapacity || m["log_dropped_total"].(uint64) == 0 {
		t.Fatalf("log overflow was not bounded and counted: %#v", m)
	}
	if runtime.NumGoroutine() > baselineGoroutines+8 {
		t.Fatal("blocked logging accumulated session goroutines")
	}
	started := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(400 * time.Millisecond):
		t.Fatal("blocked writer prevented bounded shutdown")
	}
	if time.Since(started) > 400*time.Millisecond {
		t.Fatal("shutdown exceeded budget tolerance")
	}
	if !g.Metrics()["log_shutdown_timed_out"].(bool) {
		t.Fatal("unflushed blocked sink was not reported")
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

func TestShortLogWriteIsCountedAsFailure(t *testing.T) {
	upstream, _ := backend(t)
	g, err := NewGateway(Config{Upstream: upstream, MaxConnections: 1, DialTimeout: time.Second, IdleTimeout: time.Second, ShutdownTimeout: time.Second, Log: shortWriter{}})
	if err != nil {
		t.Fatal(err)
	}
	ln := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, ln) }()
	if err := probeOnce(context.Background(), probeConfig(ln.Addr().String()), []byte("echo"), make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return g.Metrics()["log_write_errors_total"].(uint64) == 1 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if g.Metrics()["log_written_total"].(uint64) != 0 {
		t.Fatal("partial log record was reported as written")
	}
}

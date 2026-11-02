package traffic

import (
	"context"
	"fmt"
	"io"
	"math"
	"testing"
	"time"
)

func TestProbeTinyPositiveRatesDoNotOverflowIntoUnpacedTraffic(t *testing.T) {
	upstream, _ := backend(t)
	for _, rate := range []float64{1e-12, 1e-20, math.SmallestNonzeroFloat64} {
		t.Run(fmt.Sprintf("rate_%g", rate), func(t *testing.T) {
			cfg := probeConfig(upstream)
			cfg.Duration = 150 * time.Millisecond
			cfg.Rate = rate
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, err := Probe(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if ctx.Err() != nil {
				t.Fatal("bounded tiny-rate run did not finish within its observation window")
			}
			if result.Attempts != 1 || result.Successes != 1 || len(result.Errors) != 0 {
				t.Fatalf("rate with no second start slot must produce one verified operation: attempts=%d successes=%d errors=%v", result.Attempts, result.Successes, result.Errors)
			}
			if result.DurationSeconds < cfg.Duration.Seconds() {
				t.Fatal("tiny rate shortened the observation window")
			}
		})
	}
}

func TestPacedProbeObservesFullWindowAfterLastStartSlot(t *testing.T) {
	upstream, _ := backend(t)
	for _, rate := range []float64{1, 2} {
		t.Run(fmt.Sprintf("rate_%g", rate), func(t *testing.T) {
			cfg := probeConfig(upstream)
			cfg.Duration = time.Second
			cfg.Rate = rate
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := Probe(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if ctx.Err() != nil {
				t.Fatal("paced observation did not complete")
			}
			if result.Attempts == 0 || result.Successes != result.Attempts || len(result.Errors) != 0 {
				t.Fatalf("controlled echo did not verify paced operations: %#v", result)
			}
			if result.DurationSeconds < cfg.Duration.Seconds() {
				t.Fatalf("requested one-second window ended after %g seconds", result.DurationSeconds)
			}
			if result.AchievedRate != float64(result.Attempts)/result.DurationSeconds {
				t.Fatal("achieved rate must retain the actual-duration denominator")
			}
		})
	}
}

func TestPacedProbeObservationWaitIsCancelable(t *testing.T) {
	upstream, _ := backend(t)
	cfg := probeConfig(upstream)
	cfg.Duration = 5 * time.Second
	cfg.Rate = math.SmallestNonzeroFloat64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := Probe(ctx, cfg); done <- err }()
	// The lone start slot completes quickly, but the observation remains open.
	select {
	case err := <-done:
		t.Fatalf("paced observation returned before cancellation: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt the remaining paced observation")
	}
}

func TestPacedProbeCountsCompletionTailBeyondSchedulingWindow(t *testing.T) {
	listener := listen(t)
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		payload, err := io.ReadAll(conn)
		if err != nil {
			return
		}
		time.Sleep(150 * time.Millisecond)
		_, _ = conn.Write(payload)
	}()
	cfg := probeConfig(listener.Addr().String())
	cfg.Duration = 50 * time.Millisecond
	cfg.Concurrency = 1
	cfg.Rate = 1
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := Probe(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("controlled tail-response fixture did not stop")
	}
	if result.Attempts != 1 || result.Successes != 1 || len(result.Errors) != 0 {
		t.Fatalf("operation begun inside the window must finish: %#v", result)
	}
	if result.DurationSeconds <= cfg.Duration.Seconds() {
		t.Fatal("actual duration omitted the operation completion tail")
	}
	if len(result.Samples) != 1 || result.Samples[0].ElapsedSeconds > result.DurationSeconds {
		t.Fatal("completed operation must lie inside the recorded actual duration")
	}
}

func TestProbeRejectsNonfiniteNegativeAndExcessiveRates(t *testing.T) {
	for _, rate := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -math.SmallestNonzeroFloat64, 100001} {
		cfg := probeConfig("127.0.0.1:1")
		cfg.Rate = rate
		if _, err := Probe(context.Background(), cfg); err == nil {
			t.Fatalf("accepted unsupported rate %g", rate)
		}
	}
}

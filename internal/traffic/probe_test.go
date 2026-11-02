package traffic

import (
	"context"
	"io"
	"math"
	"net"
	"testing"
	"time"
)

func probeConfig(target string) ProbeConfig {
	return ProbeConfig{Target: target, Duration: 100 * time.Millisecond, Concurrency: 4, Payload: 4096, Timeout: time.Second}
}

func TestProbeMeasuresVerifiedTraffic(t *testing.T) {
	upstream, _ := backend(t)
	cfg := probeConfig(upstream)
	cfg.Rate = 100
	r, err := Probe(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Attempts < 8 || r.Attempts > 11 || r.Successes != r.Attempts || r.Bytes != r.Successes*4096 || len(r.Errors) != 0 {
		t.Fatalf("invalid result %#v", r)
	}
	if r.LatencyMS["p99"] < r.LatencyMS["p50"] || r.LatencySampleCount != int(r.Successes) {
		t.Fatal("invalid latency summary")
	}
}

func TestProbeLargePayloadDoesNotDeadlock(t *testing.T) {
	upstream, _ := backend(t)
	cfg := probeConfig(upstream)
	cfg.Payload = 4 * 1024 * 1024
	cfg.Concurrency = 1
	cfg.Duration = 20 * time.Millisecond
	r, err := Probe(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Successes == 0 || len(r.Errors) != 0 {
		t.Fatalf("large payload failed %#v", r)
	}
}

func TestProbeDetectsCorruption(t *testing.T) {
	ln := listen(t)
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = io.ReadFull(c, buf)
				_, _ = c.Write(make([]byte, 4096))
			}()
		}
	}()
	cfg := probeConfig(ln.Addr().String())
	cfg.Concurrency = 1
	r, err := Probe(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Successes != 0 || r.Errors["integrity"] == 0 {
		t.Fatalf("corruption not detected %#v", r)
	}
}

func TestProbeFailureClassesAndBounds(t *testing.T) {
	ln := listen(t)
	target := ln.Addr().String()
	ln.Close()
	cfg := probeConfig(target)
	r, err := Probe(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Successes != 0 || r.Errors["connection_refused"] == 0 {
		t.Fatalf("wrong failure %#v", r)
	}
	for _, change := range []func(*ProbeConfig){func(c *ProbeConfig) { c.Payload = 0 }, func(c *ProbeConfig) { c.Concurrency = 10000 }, func(c *ProbeConfig) { c.Payload = 4 * 1024 * 1024; c.Concurrency = 32 }, func(c *ProbeConfig) { c.Rate = math.NaN() }, func(c *ProbeConfig) { c.Hold = c.Timeout }} {
		invalid := cfg
		change(&invalid)
		if _, err := Probe(context.Background(), invalid); err == nil {
			t.Fatal("invalid workload accepted")
		}
	}
}

func TestProbeDetectsExtraEchoBytes(t *testing.T) {
	ln := listen(t)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = io.ReadFull(c, buf)
				_, _ = c.Write(append(buf, 42))
			}()
		}
	}()
	cfg := probeConfig(ln.Addr().String())
	cfg.Concurrency = 1
	r, err := Probe(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Successes != 0 || r.Errors["integrity"] == 0 {
		t.Fatalf("extra echo bytes not detected %#v", r)
	}
}

func TestProbeCancellationInterruptsEstablishedSocket(t *testing.T) {
	ln := listen(t)
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cfg := probeConfig(ln.Addr().String())
	cfg.Concurrency = 1
	cfg.Timeout = time.Minute
	cfg.Duration = time.Second
	done := make(chan struct{})
	go func() { defer close(done); _, _ = Probe(ctx, cfg) }()
	c := <-accepted
	defer c.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("cancellation did not interrupt established socket")
	}
}

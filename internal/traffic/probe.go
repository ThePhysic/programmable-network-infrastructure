package traffic

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

type ProbeConfig struct {
	Target      string
	Duration    time.Duration
	Concurrency int
	Payload     int
	Timeout     time.Duration
	Rate        float64
	Hold        time.Duration
}

type Sample struct {
	ElapsedSeconds float64 `json:"elapsed_seconds"`
	LatencyMS      float64 `json:"latency_ms"`
	Success        bool    `json:"success"`
	Error          string  `json:"error,omitempty"`
}

type ProbeResult struct {
	ExperimentID              string             `json:"experiment_id,omitempty"`
	FlowID                    string             `json:"flow_id,omitempty"`
	Attempts                  uint64             `json:"attempts"`
	Successes                 uint64             `json:"successes"`
	Errors                    map[string]uint64  `json:"errors"`
	Bytes                     uint64             `json:"bytes"`
	DurationSeconds           float64            `json:"duration_seconds"`
	ConfiguredDurationSeconds float64            `json:"configured_duration_seconds"`
	AchievedRate              float64            `json:"achieved_rate"`
	LatencyMS                 map[string]float64 `json:"latency_ms"`
	LatencySampleCount        int                `json:"latency_sample_count"`
	LatencySampling           string             `json:"latency_sampling"`
	LatencyBoundary           string             `json:"latency_boundary"`
	Samples                   []Sample           `json:"samples"`
	SamplesTruncated          bool               `json:"samples_truncated"`
	Workload                  ProbeWorkload      `json:"workload"`
}

type ProbeWorkload struct {
	Target         string  `json:"target"`
	Concurrency    int     `json:"concurrency"`
	Payload        int     `json:"payload_bytes"`
	TimeoutSeconds float64 `json:"timeout_seconds"`
	Rate           float64 `json:"configured_rate"`
	HoldSeconds    float64 `json:"hold_seconds"`
}

// Probe creates new TCP sessions and verifies exact echoed bytes. Unless canceled,
// a paced run observes the full configured window even after its last start slot.
// Already-started operations can finish within Timeout after that window ends.
func Probe(ctx context.Context, cfg ProbeConfig) (ProbeResult, error) {
	result := ProbeResult{Errors: map[string]uint64{}, LatencyMS: map[string]float64{}, Samples: []Sample{}, ConfiguredDurationSeconds: cfg.Duration.Seconds(), LatencySampling: "reservoir of at most 100000 successful operations", LatencyBoundary: "successful TCP dial, optional hold, full payload write, half-close and exact echo through EOF", Workload: ProbeWorkload{cfg.Target, cfg.Concurrency, cfg.Payload, cfg.Timeout.Seconds(), cfg.Rate, cfg.Hold.Seconds()}}
	result.ExperimentID = os.Getenv("PNID_EXPERIMENT_ID")
	result.FlowID = os.Getenv("PNID_FLOW_ID")
	if _, _, err := net.SplitHostPort(cfg.Target); err != nil {
		return result, fmt.Errorf("target: %w", err)
	}
	if cfg.Duration <= 0 || cfg.Duration > time.Hour || cfg.Concurrency < 1 || cfg.Concurrency > 1024 || cfg.Payload < 1 || cfg.Payload > 4*1024*1024 || int64(cfg.Concurrency)*int64(cfg.Payload)*2 > 64*1024*1024 || cfg.Timeout <= 0 || cfg.Timeout > time.Minute || cfg.Rate < 0 || cfg.Rate > 100000 || math.IsNaN(cfg.Rate) || math.IsInf(cfg.Rate, 0) || cfg.Hold < 0 || cfg.Hold >= cfg.Timeout {
		return result, fmt.Errorf("invalid workload bounds: duration (0,1h], concurrency 1..1024, payload 1..4MiB, total buffers <=64MiB, timeout (0,1m], finite rate 0..100000 and 0<=hold<timeout")
	}
	// A spacing at least as long as the window permits only the initial start.
	// Clamp in floating point before converting: a legitimate tiny positive rate
	// can produce an infinite or >int64 nanosecond interval.
	paceInterval := cfg.Duration
	if cfg.Rate > 0 {
		if nanos := float64(time.Second) / cfg.Rate; nanos < float64(cfg.Duration) {
			paceInterval = time.Duration(nanos)
		}
	}
	var start, end time.Time
	var mu sync.Mutex
	var paceMu sync.Mutex
	var next time.Time
	rng := rand.New(rand.NewSource(1))
	latencies := make([]float64, 0, 100000)
	var wg sync.WaitGroup
	var ready sync.WaitGroup
	ready.Add(cfg.Concurrency)
	startSignal := make(chan struct{})
	for worker := 0; worker < cfg.Concurrency; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			payload := make([]byte, cfg.Payload)
			for i := range payload {
				payload[i] = byte((i + worker*31) % 251)
			}
			response := make([]byte, cfg.Payload)
			ready.Done()
			<-startSignal
			for {
				if ctx.Err() != nil || !time.Now().Before(end) {
					return
				}
				if cfg.Rate > 0 {
					paceMu.Lock()
					slot := next
					next = next.Add(paceInterval)
					paceMu.Unlock()
					if !slot.Before(end) {
						return
					}
					if wait := time.Until(slot); wait > 0 {
						timer := time.NewTimer(wait)
						select {
						case <-timer.C:
						case <-ctx.Done():
							timer.Stop()
							return
						}
					}
				}
				if ctx.Err() != nil || !time.Now().Before(end) {
					return
				}
				attemptStart := time.Now()
				err := probeOnce(ctx, cfg, payload, response)
				latency := float64(time.Since(attemptStart)) / float64(time.Millisecond)
				sample := Sample{ElapsedSeconds: time.Since(start).Seconds(), LatencyMS: latency, Success: err == nil, Error: Classify(err)}
				if err != nil && err.Error() == "echo payload mismatch" {
					sample.Error = "integrity"
				}
				mu.Lock()
				result.Attempts++
				if err == nil {
					result.Successes++
					result.Bytes += uint64(cfg.Payload)
					if len(latencies) < cap(latencies) {
						latencies = append(latencies, latency)
					} else if at := rng.Int63n(int64(result.Successes)); at < int64(len(latencies)) {
						latencies[at] = latency
					}
				} else {
					result.Errors[sample.Error]++
				}
				if len(result.Samples) < 10000 {
					result.Samples = append(result.Samples, sample)
				} else {
					result.SamplesTruncated = true
				}
				mu.Unlock()
			}
		}(worker)
	}
	// Exclude buffer preparation and worker setup from the scheduling window.
	ready.Wait()
	start = time.Now()
	end = start.Add(cfg.Duration)
	next = start
	close(startSignal)
	wg.Wait()
	if remaining := time.Until(end); cfg.Rate > 0 && remaining > 0 {
		timer := time.NewTimer(remaining)
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
		timer.Stop()
	}
	result.DurationSeconds = time.Since(start).Seconds()
	result.AchievedRate = float64(result.Attempts) / result.DurationSeconds
	sort.Float64s(latencies)
	result.LatencySampleCount = len(latencies)
	for key, q := range map[string]float64{"p50": .5, "p95": .95, "p99": .99} {
		if len(latencies) > 0 {
			at := int(math.Ceil(float64(len(latencies))*q)) - 1
			result.LatencyMS[key] = latencies[at]
		}
	}
	return result, nil
}

func probeOnce(ctx context.Context, cfg ProbeConfig, payload, response []byte) (resultErr error) {
	operation, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	defer func() {
		if resultErr != nil && operation.Err() != nil {
			resultErr = operation.Err()
		}
	}()
	conn, err := (&net.Dialer{Timeout: cfg.Timeout}).DialContext(operation, "tcp", cfg.Target)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := operation.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	// Context cancellation interrupts established sockets as well as dial.
	stop := context.AfterFunc(operation, func() { conn.Close() })
	defer stop()
	if cfg.Hold > 0 {
		timer := time.NewTimer(cfg.Hold)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-operation.Done():
			return operation.Err()
		}
	}
	// Read and write concurrently: an echo peer may stop reading while its send
	// buffer is full, so a write-then-read client can deadlock on large payloads.
	written := make(chan error, 1)
	go func() {
		_, err := io.CopyN(conn, bytes.NewReader(payload), int64(len(payload)))
		if err == nil {
			closeWrite(conn)
		}
		written <- err
	}()
	_, readErr := io.ReadFull(conn, response)
	if readErr != nil {
		conn.Close()
	}
	writeErr := <-written
	if readErr != nil {
		return readErr
	}
	if writeErr != nil {
		return writeErr
	}
	if !bytes.Equal(payload, response) {
		return fmt.Errorf("echo payload mismatch")
	}
	var extra [1]byte
	n, err := conn.Read(extra[:])
	if n != 0 {
		return fmt.Errorf("echo payload mismatch")
	}
	if err != io.EOF {
		return err
	}
	return nil
}

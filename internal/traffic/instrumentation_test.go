package traffic

import (
	"bytes"
	"context"
	"encoding/json"
	"runtime"
	"testing"
	"time"
)

func TestExperimentIdentityReachesProbeAndSessionLog(t *testing.T) {
	t.Setenv("PNID_EXPERIMENT_ID", "experiment-test")
	t.Setenv("PNID_FLOW_ID", "client-gateway-backend")
	upstream, _ := backend(t)
	var logs bytes.Buffer
	g, err := NewGateway(Config{Upstream: upstream, MaxConnections: 2, DialTimeout: time.Second, IdleTimeout: time.Second, ShutdownTimeout: time.Second, Log: &logs})
	if err != nil {
		t.Fatal(err)
	}
	ln := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, ln) }()
	cfg := probeConfig(ln.Addr().String())
	cfg.Concurrency = 1
	cfg.Duration = 20 * time.Millisecond
	cfg.Rate = 100
	r, err := Probe(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if r.ExperimentID != "experiment-test" || r.FlowID != "client-gateway-backend" || r.Successes == 0 {
		t.Fatalf("probe identity missing: %#v", r)
	}
	decoder := json.NewDecoder(&logs)
	var record map[string]any
	if err := decoder.Decode(&record); err != nil {
		t.Fatal(err)
	}
	if record["experiment_id"] != r.ExperimentID || record["flow_id"] != r.FlowID {
		t.Fatalf("session identity missing: %#v", record)
	}
}

func TestProcessCPUMetricsAreExplicitAndCumulative(t *testing.T) {
	first := processCPU()
	if runtime.GOOS != "linux" {
		if first["cpu_measurement_available"] != false {
			t.Fatal("unsupported CPU measurement must be explicit")
		}
		return
	}
	if first["cpu_measurement_available"] != true {
		t.Fatal("Linux process CPU measurement unavailable")
	}
	user := first["cpu_user_seconds"].(float64)
	system := first["cpu_system_seconds"].(float64)
	total := first["cpu_total_seconds"].(float64)
	if user < 0 || system < 0 || total != user+system {
		t.Fatalf("invalid CPU readings: %#v", first)
	}
	second := processCPU()
	if second["cpu_total_seconds"].(float64) < total {
		t.Fatal("cumulative CPU went backwards")
	}
}

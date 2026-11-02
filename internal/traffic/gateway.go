// Package traffic implements bounded, observable TCP lab workloads.
package traffic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Upstream        string
	DNSServer       string
	MaxConnections  int
	DialTimeout     time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	Log             io.Writer
}

// Gateway owns every accepted socket, including sockets still dialing upstream.
type Gateway struct {
	cfg       Config
	started   time.Time
	mu        sync.Mutex
	active    map[net.Conn]net.Conn
	closing   bool
	errors    map[string]uint64
	accepted  atomic.Uint64
	rejected  atomic.Uint64
	bytesUp   atomic.Uint64
	bytesDown atomic.Uint64
	sessions  atomic.Uint64
	logMu     sync.Mutex
}

func NewGateway(cfg Config) (*Gateway, error) {
	if cfg.Upstream == "" || cfg.MaxConnections < 1 || cfg.MaxConnections > 4096 || cfg.DialTimeout <= 0 || cfg.IdleTimeout <= 0 || cfg.ShutdownTimeout <= 0 {
		return nil, fmt.Errorf("upstream, 1..4096 connections and positive timeouts are required")
	}
	if _, _, err := net.SplitHostPort(cfg.Upstream); err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}
	if cfg.DNSServer != "" {
		if _, _, err := net.SplitHostPort(cfg.DNSServer); err != nil {
			return nil, fmt.Errorf("DNS server: %w", err)
		}
	}
	return &Gateway{cfg: cfg, started: time.Now(), active: make(map[net.Conn]net.Conn), errors: make(map[string]uint64)}, nil
}

func (g *Gateway) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: g.cfg.DialTimeout}
	if g.cfg.DNSServer != "" {
		d.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: g.cfg.DialTimeout}).DialContext(ctx, network, g.cfg.DNSServer)
		}}
	}
	return d.DialContext(ctx, "tcp", g.cfg.Upstream)
}

// Serve accepts until cancellation, drains for ShutdownTimeout, then closes all
// remaining sessions. It does not replay or retry stream bytes.
func (g *Gateway) Serve(ctx context.Context, listener net.Listener) error {
	defer listener.Close()
	dialCtx, cancelDials := context.WithCancel(context.Background())
	defer cancelDials()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-stop:
		}
	}()
	var workers sync.WaitGroup
	var acceptErr error
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				acceptErr = err
			}
			break
		}
		g.accepted.Add(1)
		g.mu.Lock()
		if len(g.active) >= g.cfg.MaxConnections {
			g.mu.Unlock()
			g.rejected.Add(1)
			client.Close()
			continue
		}
		g.active[client] = nil
		g.mu.Unlock()
		workers.Add(1)
		go func() { defer workers.Done(); g.session(dialCtx, client) }()
	}
	finished := make(chan struct{})
	go func() { workers.Wait(); close(finished) }()
	timer := time.NewTimer(g.cfg.ShutdownTimeout)
	defer timer.Stop()
	select {
	case <-finished:
	case <-timer.C:
		cancelDials()
		g.mu.Lock()
		g.closing = true
		for client, upstream := range g.active {
			client.Close()
			if upstream != nil {
				upstream.Close()
			}
		}
		g.mu.Unlock()
		<-finished
	}
	return acceptErr
}

type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c idleConn) Read(b []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}
func (c idleConn) Write(b []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

type copyResult struct {
	n         int64
	err       error
	direction string
}

func closeWrite(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}

func (g *Gateway) session(ctx context.Context, client net.Conn) {
	id := g.sessions.Add(1)
	started := time.Now()
	var dialLatency time.Duration
	var outcome string
	defer func() {
		client.Close()
		g.mu.Lock()
		delete(g.active, client)
		if outcome != "" {
			g.errors[outcome]++
		}
		g.mu.Unlock()
		g.log(map[string]any{"event": "session", "session_id": id, "observed_at": time.Now().UTC().Format(time.RFC3339Nano), "duration_ms": float64(time.Since(started)) / float64(time.Millisecond), "upstream_connect_ms": float64(dialLatency) / float64(time.Millisecond), "error": outcome})
	}()
	upstream, err := g.dial(ctx)
	dialLatency = time.Since(started)
	if err != nil {
		outcome = "upstream_" + Classify(err)
		return
	}
	defer upstream.Close()
	g.mu.Lock()
	if g.closing {
		g.mu.Unlock()
		outcome = "canceled"
		return
	}
	g.active[client] = upstream
	g.mu.Unlock()
	// Closing the client on forced shutdown must interrupt both forwarding legs.
	done := make(chan copyResult, 2)
	copyLeg := func(dst, src net.Conn, direction string) {
		buf := make([]byte, 32*1024)
		n, err := io.CopyBuffer(idleConn{dst, g.cfg.IdleTimeout}, idleConn{src, g.cfg.IdleTimeout}, buf)
		if err == nil {
			closeWrite(dst)
		} else {
			client.Close()
			upstream.Close()
		}
		done <- copyResult{n, err, direction}
	}
	go copyLeg(upstream, client, "up")
	go copyLeg(client, upstream, "down")
	for i := 0; i < 2; i++ {
		r := <-done
		if r.direction == "up" {
			g.bytesUp.Add(uint64(r.n))
		} else {
			g.bytesDown.Add(uint64(r.n))
		}
		if r.err != nil {
			classified := Classify(r.err)
			// The paired copy may report a local close before the leg which
			// actually failed reports its timeout/reset. Preserve the cause.
			if outcome == "" || outcome == "closed" || classified == "timeout" {
				outcome = classified
			}
		}
	}
}

func (g *Gateway) log(v any) {
	if g.cfg.Log == nil {
		return
	}
	g.logMu.Lock()
	defer g.logMu.Unlock()
	_ = json.NewEncoder(g.cfg.Log).Encode(v)
}

func (g *Gateway) Metrics() map[string]any {
	g.mu.Lock()
	errs := make(map[string]uint64, len(g.errors))
	for k, v := range g.errors {
		errs[k] = v
	}
	active := len(g.active)
	g.mu.Unlock()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	m := map[string]any{"active_connections": active, "accepted": g.accepted.Load(), "rejected": g.rejected.Load(), "bytes_up": g.bytesUp.Load(), "bytes_down": g.bytesDown.Load(), "errors": errs, "goroutines": runtime.NumGoroutine(), "uptime_seconds": time.Since(g.started).Seconds(), "heap_alloc_bytes": mem.HeapAlloc, "heap_sys_bytes": mem.HeapSys, "gc_cycles": mem.NumGC, "max_connections": g.cfg.MaxConnections}
	if raw, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "VmRSS:" {
				if n, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					m["rss_bytes"] = n * 1024
				}
			}
		}
	}
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		m["file_descriptors"] = len(entries)
	}
	return m
}

// Handler exposes process liveness separately from an active upstream check.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g.Metrics())
	})
	mux.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"alive": true})
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), g.cfg.DialTimeout)
		defer cancel()
		conn, err := g.dial(ctx)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"ready": false, "error": Classify(err)})
			return
		}
		conn.Close()
		_ = json.NewEncoder(w).Encode(map[string]bool{"ready": true})
	})
	return mux
}

func Classify(err error) string {
	if err == nil {
		return ""
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns_error"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "refused"):
		return "connection_refused"
	case strings.Contains(s, "reset") || strings.Contains(s, "broken pipe"):
		return "reset"
	case strings.Contains(s, "network is unreachable"):
		return "network_unreachable"
	case strings.Contains(s, "no route to host"):
		return "no_route"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	default:
		return "io_error"
	}
}

// ServeBackend implements a bounded echo endpoint with per-operation deadlines.
func ServeBackend(ctx context.Context, listener net.Listener, maximum int, idle, shutdown time.Duration) error {
	if maximum < 1 || maximum > 4096 || idle <= 0 || shutdown <= 0 {
		return fmt.Errorf("invalid backend limits")
	}
	cfg := Config{Upstream: "127.0.0.1:1", MaxConnections: maximum, DialTimeout: time.Second, IdleTimeout: idle, ShutdownTimeout: shutdown}
	owner, _ := NewGateway(cfg)
	defer listener.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-stop:
		}
	}()
	var wg sync.WaitGroup
	var acceptErr error
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				acceptErr = err
			}
			break
		}
		owner.mu.Lock()
		if len(owner.active) >= maximum {
			owner.mu.Unlock()
			conn.Close()
			continue
		}
		owner.active[conn] = nil
		owner.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			defer func() { owner.mu.Lock(); delete(owner.active, conn); owner.mu.Unlock() }()
			buf := make([]byte, 32*1024)
			_, _ = io.CopyBuffer(idleConn{conn, idle}, idleConn{conn, idle}, buf)
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	timer := time.NewTimer(shutdown)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		owner.mu.Lock()
		for c := range owner.active {
			c.Close()
		}
		owner.mu.Unlock()
		<-done
	}
	return acceptErr
}

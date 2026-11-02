package traffic

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func backend(t *testing.T) (string, context.CancelFunc) {
	t.Helper()
	ln := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeBackend(ctx, ln, 128, time.Second, 50*time.Millisecond) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("backend did not stop")
		}
	})
	return ln.Addr().String(), cancel
}

func gateway(t *testing.T, upstream string, maximum int, idle, shutdown time.Duration) (*Gateway, string, context.CancelFunc, <-chan error) {
	t.Helper()
	g, err := NewGateway(Config{Upstream: upstream, MaxConnections: maximum, DialTimeout: 100 * time.Millisecond, IdleTimeout: idle, ShutdownTimeout: shutdown})
	if err != nil {
		t.Fatal(err)
	}
	ln := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, ln) }()
	t.Cleanup(cancel)
	return g, ln.Addr().String(), cancel, done
}

func waitFor(t *testing.T, predicate func() bool) {
	t.Helper()
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		if predicate() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not reached")
}

func TestGatewayConcurrentIntegrityAndHalfClose(t *testing.T) {
	upstream, _ := backend(t)
	g, address, cancel, done := gateway(t, upstream, 32, time.Second, 100*time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", address)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			payload := bytes.Repeat([]byte{byte(id), 0, 255}, 4096)
			writeDone := make(chan error, 1)
			go func() {
				_, err := conn.Write(payload)
				if err == nil {
					err = conn.(*net.TCPConn).CloseWrite()
				}
				writeDone <- err
			}()
			got, err := io.ReadAll(conn)
			if err != nil {
				t.Error(err)
			}
			if err := <-writeDone; err != nil {
				t.Error(err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("session %d bytes corrupted", id)
			}
		}(i)
	}
	wg.Wait()
	waitFor(t, func() bool { return g.Metrics()["active_connections"].(int) == 0 })
	m := g.Metrics()
	if m["bytes_up"].(uint64) != 16*4096*3 || m["bytes_down"].(uint64) != 16*4096*3 {
		t.Fatalf("incorrect byte counters: %#v", m)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGatewayDrainsResponseAfterClientHalfClose(t *testing.T) {
	ln := listen(t)
	defer ln.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		data, _ := io.ReadAll(c)
		time.Sleep(20 * time.Millisecond)
		_, _ = c.Write(append([]byte("reply:"), data...))
	}()
	_, address, cancel, done := gateway(t, ln.Addr().String(), 2, time.Second, 100*time.Millisecond)
	c, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write([]byte("request"))
	_ = c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "reply:request" {
		t.Fatalf("half-close lost response: %q", got)
	}
	<-serverDone
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGatewayRejectsOverloadAndAccountsResources(t *testing.T) {
	upstream, _ := backend(t)
	g, address, cancel, done := gateway(t, upstream, 1, time.Second, 50*time.Millisecond)
	first, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	waitFor(t, func() bool { return g.Metrics()["active_connections"].(int) == 1 })
	second, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := second.Read(b[:]); err == nil {
		t.Fatal("overload was not rejected")
	}
	if g.Metrics()["rejected"].(uint64) != 1 {
		t.Fatal("rejection metric missing")
	}
	first.Close()
	waitFor(t, func() bool { return g.Metrics()["active_connections"].(int) == 0 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGatewayIdleTimeoutAndForcedShutdown(t *testing.T) {
	upstream, _ := backend(t)
	g, address, cancel, done := gateway(t, upstream, 2, 40*time.Millisecond, 20*time.Millisecond)
	c, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := c.Read(b[:]); err == nil {
		t.Fatal("idle connection remained open")
	}
	waitFor(t, func() bool { return g.Metrics()["active_connections"].(int) == 0 })
	if g.Metrics()["errors"].(map[string]uint64)["timeout"] == 0 {
		t.Fatal("idle timeout was not classified")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Shutdown must interrupt both copies even when the idle budget is long.
	g2, address2, cancel2, done2 := gateway(t, upstream, 2, 30*time.Second, 20*time.Millisecond)
	c2, err := net.Dial("tcp", address2)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	waitFor(t, func() bool { return g2.Metrics()["active_connections"].(int) == 1 })
	started := time.Now()
	cancel2()
	select {
	case err := <-done2:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("forced shutdown exceeded bound")
	}
	if time.Since(started) > 300*time.Millisecond || g2.Metrics()["active_connections"].(int) != 0 {
		t.Fatal("shutdown leaked resources")
	}
}

func TestGatewayReadinessAndUpstreamFailure(t *testing.T) {
	closed := listen(t)
	address := closed.Addr().String()
	closed.Close()
	g, listenAddress, cancel, done := gateway(t, address, 2, time.Second, 20*time.Millisecond)
	for path, want := range map[string]int{"/live": 200, "/health": 503, "/metrics": 200} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		g.Handler().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s status %d", path, w.Code)
		}
		var body any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
	}
	c, err := net.Dial("tcp", listenAddress)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, _ = c.Read(b[:])
	c.Close()
	waitFor(t, func() bool { return g.Metrics()["errors"].(map[string]uint64)["upstream_connection_refused"] == 1 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGatewayConfigurationValidation(t *testing.T) {
	if _, err := NewGateway(Config{}); err == nil {
		t.Fatal("accepted invalid configuration")
	}
	if _, err := NewGateway(Config{Upstream: "broken", MaxConnections: 1, DialTimeout: time.Second, IdleTimeout: time.Second, ShutdownTimeout: time.Second}); err == nil {
		t.Fatal("accepted malformed upstream")
	}
}

func TestGatewayUsesConfiguredDNSAndPreservesDNSError(t *testing.T) {
	upstream, _ := backend(t)
	_, port, _ := net.SplitHostPort(upstream)
	dns, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, peer, err := dns.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			if n < 17 {
				continue
			}
			at := 12
			name := ""
			for at < n && q[at] != 0 {
				size := int(q[at])
				at++
				if at+size >= n {
					break
				}
				name += string(q[at:at+size]) + "."
				at += size
			}
			at++
			if at+4 > n {
				continue
			}
			questionEnd := at + 4
			answer := append([]byte(nil), q[:questionEnd]...)
			answer[2] = 0x81
			answer[3] = 0x80
			for i := 6; i < 12; i++ {
				answer[i] = 0
			}
			if name != "backend.lab." {
				answer[3] = 0x83
			} else if binary.BigEndian.Uint16(q[at:at+2]) == 1 {
				answer[7] = 1
				answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1)
			}
			_, _ = dns.WriteTo(answer, peer)
		}
	}()
	cfg := Config{Upstream: net.JoinHostPort("backend.lab", port), DNSServer: dns.LocalAddr().String(), MaxConnections: 2, DialTimeout: time.Second, IdleTimeout: time.Second, ShutdownTimeout: time.Millisecond}
	g, err := NewGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := g.dial(context.Background())
	if err != nil {
		t.Fatalf("custom DNS did not resolve: %v", err)
	}
	conn.Close()
	cfg.Upstream = net.JoinHostPort("missing.lab", port)
	missing, err := NewGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = missing.dial(context.Background())
	if Classify(err) != "dns_error" {
		t.Fatalf("DNS failure misclassified: %v", err)
	}
}

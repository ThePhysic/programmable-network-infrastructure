package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"netlab/internal/traffic"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_ = json.NewEncoder(os.Stderr).Encode(map[string]string{"event": "fatal", "error": err.Error()})
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: netlab-agent gateway|backend|probe [flags]")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "gateway":
		listen := fs.String("listen", "127.0.0.1:18080", "TCP listen address")
		upstream := fs.String("upstream", "", "upstream host:port")
		dns := fs.String("dns-server", "", "optional lab DNS host:port")
		metrics := fs.String("metrics", "127.0.0.1:19091", "metrics HTTP address (empty disables)")
		maximum := fs.Int("max-connections", 16, "maximum concurrent sessions")
		dial := fs.Duration("dial-timeout", 800*time.Millisecond, "upstream dial timeout")
		idle := fs.Duration("idle-timeout", 2*time.Second, "per-direction read/write inactivity timeout")
		shutdown := fs.Duration("shutdown-timeout", 2*time.Second, "graceful drain budget")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected arguments")
		}
		gateway, err := traffic.NewGateway(traffic.Config{Upstream: *upstream, DNSServer: *dns, MaxConnections: *maximum, DialTimeout: *dial, IdleTimeout: *idle, ShutdownTimeout: *shutdown, Log: os.Stderr})
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			return err
		}
		defer listener.Close()
		var server *http.Server
		if *metrics != "" {
			ml, err := net.Listen("tcp", *metrics)
			if err != nil {
				return err
			}
			server = &http.Server{Handler: gateway.Handler(), ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: *dial + 2*time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
			go func() {
				if err := server.Serve(&boundedListener{Listener: ml, slots: make(chan struct{}, 32)}); err != nil && err != http.ErrServerClosed {
					fmt.Fprintln(os.Stderr, err)
					cancel()
				}
			}()
			defer func() {
				stop, done := context.WithTimeout(context.Background(), time.Second)
				defer done()
				_ = server.Shutdown(stop)
			}()
		}
		return gateway.Serve(ctx, listener)
	case "backend":
		listen := fs.String("listen", "127.0.0.1:19090", "TCP listen address")
		maximum := fs.Int("max-connections", 256, "maximum concurrent sessions")
		idle := fs.Duration("idle-timeout", 3*time.Second, "read/write inactivity timeout")
		shutdown := fs.Duration("shutdown-timeout", 2*time.Second, "graceful drain budget")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected arguments")
		}
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			return err
		}
		defer listener.Close()
		return traffic.ServeBackend(ctx, listener, *maximum, *idle, *shutdown)
	case "probe":
		target := fs.String("target", "127.0.0.1:18080", "target host:port")
		duration := fs.Duration("duration", 2*time.Second, "request scheduling duration")
		concurrency := fs.Int("concurrency", 2, "maximum concurrent workers")
		payload := fs.Int("payload", 256, "payload bytes per connection")
		timeout := fs.Duration("timeout", 1500*time.Millisecond, "whole operation timeout")
		rate := fs.Float64("rate", 0, "global target attempts/sec; 0 unpaced")
		hold := fs.Duration("hold", 0, "hold connection before echo exchange (overload experiments)")
		output := fs.String("output", "", "JSON output path (also emits JSON on stdout)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected arguments")
		}
		result, err := traffic.Probe(ctx, traffic.ProbeConfig{Target: *target, Duration: *duration, Concurrency: *concurrency, Payload: *payload, Timeout: *timeout, Rate: *rate, Hold: *hold})
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if *output != "" {
			if err := os.WriteFile(*output, data, 0600); err != nil {
				return err
			}
		}
		_, err = os.Stdout.Write(data)
		return err
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// The HTTP diagnostics port has an independent connection budget, so slow
// readers cannot create an unlimited number of HTTP serving goroutines.
type boundedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &boundedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}

type boundedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *boundedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }

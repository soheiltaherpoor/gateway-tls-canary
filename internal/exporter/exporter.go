// Package exporter probes the configured targets on a schedule and serves Prometheus metrics.
package exporter

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/soheiltaherpoor/gateway-tls-canary/internal/config"
	"github.com/soheiltaherpoor/gateway-tls-canary/internal/probe"
)

// ProbeFunc probes one target.
type ProbeFunc func(ctx context.Context, t config.Target) (*probe.Result, error)

type state struct {
	haveResult bool // at least one successful probe so far
	success    bool // the latest probe succeeded
	match      bool
	chainValid bool
	notAfter   time.Time
	leafPin    string
	issuer     string
	duration   time.Duration
	last       time.Time
	lastErr    string
}

// Exporter holds the latest observation of every target.
type Exporter struct {
	cfg   *config.Config
	probe ProbeFunc
	log   *slog.Logger
	now   func() time.Time

	mu    sync.Mutex
	state map[string]*state
}

// New returns an exporter. now may be nil.
func New(cfg *config.Config, fn ProbeFunc, log *slog.Logger, now func() time.Time) *Exporter {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	e := &Exporter{cfg: cfg, probe: fn, log: log, now: now, state: map[string]*state{}}
	for _, t := range cfg.Targets {
		e.state[t.Name] = &state{}
	}
	return e
}

// ProbeAll probes every target once, in order.
func (e *Exporter) ProbeAll(ctx context.Context) {
	for _, t := range e.cfg.Targets {
		e.probeOne(ctx, t)
	}
}

func (e *Exporter) probeOne(ctx context.Context, t config.Target) {
	res, err := e.probe(ctx, t)

	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.state[t.Name]
	s.last = e.now()
	if err != nil {
		s.success = false
		s.lastErr = err.Error()
		e.log.Warn("probe failed", "target", t.Name, "error", err)
		return
	}
	prevKnown, prevMatch := s.haveResult, s.match
	_, matched := res.Matches(t.Pins)
	s.haveResult, s.success, s.lastErr = true, true, ""
	s.match, s.chainValid, s.duration = matched, res.ChainValid, res.Duration
	s.leafPin, s.issuer = res.Chain[0].Pin, res.Chain[0].Issuer
	s.notAfter = res.Chain[0].NotAfter

	switch {
	case !matched:
		// Log on every probe while it lasts: this is the line to alert on if you scrape logs.
		e.log.Error("PIN MISMATCH: presented chain has no pinned key",
			"target", t.Name, "leaf_pin", s.leafPin, "issuer", s.issuer, "chain_valid", res.ChainValid)
	case prevKnown && !prevMatch:
		e.log.Info("pin matches again", "target", t.Name)
	}
}

// Run probes immediately and then every interval until ctx ends.
func (e *Exporter) Run(ctx context.Context) {
	e.ProbeAll(ctx)
	tick := time.NewTicker(e.cfg.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			e.ProbeAll(ctx)
		}
	}
}

// Handler serves /metrics and /healthz.
func (e *Exporter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		e.writeMetrics(w)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	return mux
}

func b2f(b bool) int {
	if b {
		return 1
	}
	return 0
}

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func (e *Exporter) writeMetrics(w io.Writer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	names := make([]string, 0, len(e.state))
	for n := range e.state {
		names = append(names, n)
	}
	sort.Strings(names)

	family := func(name, help string, each func(n string, s *state) (string, bool)) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
		for _, n := range names {
			if line, ok := each(n, e.state[n]); ok {
				fmt.Fprintf(w, "%s%s\n", name, line)
			}
		}
	}
	lbl := func(n string) string { return fmt.Sprintf(`{target="%s"}`, esc(n)) }

	family("tls_canary_probe_success", "1 if the latest probe completed a TLS handshake, 0 if not.",
		func(n string, s *state) (string, bool) {
			return fmt.Sprintf("%s %d", lbl(n), b2f(s.success)), !s.last.IsZero()
		})
	family("tls_canary_pin_match", "1 if the presented chain contains a pinned key, 0 if not. Keeps its last value while probes fail; absent until the first successful probe.",
		func(n string, s *state) (string, bool) {
			return fmt.Sprintf("%s %d", lbl(n), b2f(s.match)), s.haveResult
		})
	family("tls_canary_chain_valid", "1 if the presented chain verifies against the trust roots for the requested name.",
		func(n string, s *state) (string, bool) {
			return fmt.Sprintf("%s %d", lbl(n), b2f(s.chainValid)), s.haveResult
		})
	family("tls_canary_cert_not_after_timestamp_seconds", "Expiry of the presented leaf certificate, Unix time.",
		func(n string, s *state) (string, bool) {
			return fmt.Sprintf("%s %d", lbl(n), s.notAfter.Unix()), s.haveResult
		})
	family("tls_canary_probe_duration_seconds", "Dial plus handshake time of the latest successful probe.",
		func(n string, s *state) (string, bool) {
			return fmt.Sprintf("%s %.6f", lbl(n), s.duration.Seconds()), s.haveResult
		})
	family("tls_canary_last_probe_timestamp_seconds", "When the latest probe finished, Unix time.",
		func(n string, s *state) (string, bool) {
			return fmt.Sprintf("%s %d", lbl(n), s.last.Unix()), !s.last.IsZero()
		})
	family("tls_canary_info", "Always 1; labels carry the leaf key pin and issuer last seen.",
		func(n string, s *state) (string, bool) {
			return fmt.Sprintf(`{target="%s",leaf_pin="%s",issuer="%s"} 1`, esc(n), esc(s.leafPin), esc(s.issuer)), s.haveResult
		})
}

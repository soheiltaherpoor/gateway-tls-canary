package exporter

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soheiltaherpoor/gateway-tls-canary/internal/config"
	"github.com/soheiltaherpoor/gateway-tls-canary/internal/probe"
)

var (
	pinGood = "sha256:" + strings.Repeat("aa", 32)
	pinBad  = "sha256:" + strings.Repeat("bb", 32)
)

func testConfig() *config.Config {
	return &config.Config{
		Interval: time.Minute,
		Timeout:  5 * time.Second,
		Targets: []config.Target{
			{Name: "zeta", Address: "z:443", Pins: []string{pinGood}},
			{Name: "alpha", Address: "a:443", Pins: []string{pinGood}},
		},
	}
}

func result(pin string, valid bool) *probe.Result {
	return &probe.Result{
		Chain: []probe.CertInfo{{
			Pin: pin, Issuer: `CN=My "Quoted" CA`, NotAfter: time.Unix(1800000000, 0),
		}},
		ChainValid: valid,
		Duration:   25 * time.Millisecond,
	}
}

type script struct {
	res map[string]*probe.Result
	err map[string]error
}

func (s *script) fn(_ context.Context, t config.Target) (*probe.Result, error) {
	if e := s.err[t.Name]; e != nil {
		return nil, e
	}
	return s.res[t.Name], nil
}

func metrics(e *Exporter) string {
	rec := httptest.NewRecorder()
	e.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

func has(t *testing.T, body, want string) {
	t.Helper()
	if !strings.Contains(body, want) {
		t.Errorf("metrics missing %q\n%s", want, body)
	}
}

func lacks(t *testing.T, body, bad string) {
	t.Helper()
	if strings.Contains(body, bad) {
		t.Errorf("metrics must not contain %q\n%s", bad, body)
	}
}

func TestMatchAndMismatch(t *testing.T) {
	s := &script{res: map[string]*probe.Result{"alpha": result(pinGood, true), "zeta": result(pinBad, true)}}
	e := New(testConfig(), s.fn, nil, func() time.Time { return time.Unix(1700000000, 0) })
	e.ProbeAll(context.Background())
	body := metrics(e)

	has(t, body, `tls_canary_pin_match{target="alpha"} 1`)
	has(t, body, `tls_canary_pin_match{target="zeta"} 0`)
	has(t, body, `tls_canary_probe_success{target="zeta"} 1`)
	has(t, body, `tls_canary_chain_valid{target="alpha"} 1`)
	has(t, body, `tls_canary_cert_not_after_timestamp_seconds{target="alpha"} 1800000000`)
	has(t, body, `tls_canary_last_probe_timestamp_seconds{target="alpha"} 1700000000`)
	has(t, body, `tls_canary_probe_duration_seconds{target="alpha"} 0.025000`)
	has(t, body, `tls_canary_info{target="alpha",leaf_pin="`+pinGood+`",issuer="CN=My \"Quoted\" CA"} 1`)
	has(t, body, "# TYPE tls_canary_pin_match gauge")
	if strings.Index(body, `target="alpha"`) > strings.Index(body, `target="zeta"`) {
		t.Error("targets must be listed in sorted order")
	}
}

func TestChainInvalidButPinMatches(t *testing.T) {
	s := &script{res: map[string]*probe.Result{"alpha": result(pinGood, false), "zeta": result(pinGood, false)}}
	e := New(testConfig(), s.fn, nil, nil)
	e.ProbeAll(context.Background())
	body := metrics(e)
	has(t, body, `tls_canary_chain_valid{target="alpha"} 0`)
	has(t, body, `tls_canary_pin_match{target="alpha"} 1`)
}

func TestFirstProbeFailsThenSucceeds(t *testing.T) {
	s := &script{
		res: map[string]*probe.Result{"alpha": result(pinGood, true), "zeta": result(pinGood, true)},
		err: map[string]error{"alpha": errors.New("connect: refused")},
	}
	e := New(testConfig(), s.fn, nil, nil)
	e.ProbeAll(context.Background())
	body := metrics(e)
	has(t, body, `tls_canary_probe_success{target="alpha"} 0`)
	lacks(t, body, `tls_canary_pin_match{target="alpha"}`) // nothing is known yet: no false 0 or 1
	has(t, body, `tls_canary_pin_match{target="zeta"} 1`)

	delete(s.err, "alpha")
	e.ProbeAll(context.Background())
	has(t, metrics(e), `tls_canary_pin_match{target="alpha"} 1`)
}

func TestMismatchSurvivesAFailedProbe(t *testing.T) {
	s := &script{res: map[string]*probe.Result{"alpha": result(pinBad, true), "zeta": result(pinGood, true)}}
	e := New(testConfig(), s.fn, nil, nil)
	e.ProbeAll(context.Background())
	s.err = map[string]error{"alpha": errors.New("timeout")}
	e.ProbeAll(context.Background())
	body := metrics(e)
	has(t, body, `tls_canary_probe_success{target="alpha"} 0`)
	has(t, body, `tls_canary_pin_match{target="alpha"} 0`) // an alert must not clear just because the next probe failed
}

func TestLogging(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	s := &script{res: map[string]*probe.Result{"alpha": result(pinBad, false), "zeta": result(pinGood, true)}}
	e := New(testConfig(), s.fn, log, nil)
	e.ProbeAll(context.Background())
	if out := buf.String(); !strings.Contains(out, "PIN MISMATCH") || !strings.Contains(out, "target=alpha") || !strings.Contains(out, pinBad) {
		t.Fatalf("mismatch must be logged with target and observed pin:\n%s", out)
	}
	buf.Reset()
	s.res["alpha"] = result(pinGood, true)
	e.ProbeAll(context.Background())
	if !strings.Contains(buf.String(), "pin matches again") {
		t.Errorf("recovery must be logged:\n%s", buf.String())
	}
	buf.Reset()
	e.ProbeAll(context.Background())
	if buf.Len() != 0 {
		t.Errorf("steady state must be quiet:\n%s", buf.String())
	}
}

func TestRunProbesImmediatelyAndStops(t *testing.T) {
	s := &script{res: map[string]*probe.Result{"alpha": result(pinGood, true), "zeta": result(pinGood, true)}}
	e := New(testConfig(), s.fn, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(metrics(e), `tls_canary_pin_match{target="zeta"} 1`) {
		if time.Now().After(deadline) {
			t.Fatal("no probe happened right after start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestHealthzAndContentType(t *testing.T) {
	e := New(testConfig(), (&script{}).fn, nil, nil)
	rec := httptest.NewRecorder()
	e.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	rec = httptest.NewRecorder()
	e.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content type %q", ct)
	}
}

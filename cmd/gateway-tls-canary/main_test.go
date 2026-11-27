package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/soheiltaherpoor/gateway-tls-canary/internal/probe"
	"github.com/soheiltaherpoor/gateway-tls-canary/internal/testutil"
)

const host = "gateway.example.com"

func pinOf(t *testing.T, der []byte) string {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return probe.Pin(c)
}

func writeConfig(t *testing.T, addr string, pins ...string) string {
	t.Helper()
	cfg := map[string]any{
		"timeout": "2s",
		"targets": []any{map[string]any{"name": "gw", "address": addr, "sni": host, "pins": pins}},
	}
	b, _ := json.Marshal(cfg)
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func exec(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestLearn(t *testing.T) {
	root := testutil.NewRoot(t, "root")
	inter := root.NewIntermediate(t, "inter")
	leaf := inter.IssueLeaf(t, time.Time{}, host)
	srv := testutil.StartServer(t, leaf)

	code, out, errs := exec("learn", "-sni", host, srv.Addr)
	if code != exitOK {
		t.Fatalf("exit %d: %s %s", code, out, errs)
	}
	for _, want := range []string{"[0] leaf", "[1] intermediate or root", pinOf(t, leaf.Certificate[0]), pinOf(t, inter.DER), "does NOT verify"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code, _, _ := exec("learn"); code != exitUsage {
		t.Errorf("learn without address: exit %d", code)
	}
}

func TestCheckExitCodes(t *testing.T) {
	good := testutil.NewRoot(t, "good").NewIntermediate(t, "good inter")
	srv := testutil.StartServer(t, good.IssueLeaf(t, time.Time{}, host))
	pin := pinOf(t, good.DER)
	other := "sha256:" + strings.Repeat("00", 32)

	code, out, _ := exec("check", "-config", writeConfig(t, srv.Addr, other, pin))
	if code != exitOK || !strings.Contains(out, "[ OK ]") || !strings.Contains(out, "position 1") {
		t.Errorf("match: exit %d\n%s", code, out)
	}

	code, out, _ = exec("check", "-config", writeConfig(t, srv.Addr, other))
	if code != exitMismatch || !strings.Contains(out, "PIN MISMATCH") || !strings.Contains(out, pin) {
		t.Errorf("mismatch must exit 1 and show the observed pins: exit %d\n%s", code, out)
	}

	code, out, _ = exec("check", "-config", writeConfig(t, testutil.ClosedAddr(t), pin))
	if code != exitProbe || !strings.Contains(out, "[ERR ]") {
		t.Errorf("unreachable must exit 2: exit %d\n%s", code, out)
	}
}

func TestCheckJSON(t *testing.T) {
	good := testutil.NewRoot(t, "good").NewIntermediate(t, "good inter")
	srv := testutil.StartServer(t, good.IssueLeaf(t, time.Time{}, host))
	code, out, _ := exec("check", "-json", "-config", writeConfig(t, srv.Addr, pinOf(t, good.DER)))
	var rows []checkRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil || code != exitOK {
		t.Fatalf("exit %d, %v\n%s", code, err, out)
	}
	if len(rows) != 1 || rows[0].Status != "ok" || rows[0].MatchedIndex == nil || *rows[0].MatchedIndex != 1 || rows[0].ChainValid == nil {
		t.Errorf("%+v", rows)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bogus"},
		{"check"},
		{"check", "-config", "/nonexistent.json"},
		{"serve"},
	} {
		if code, _, _ := exec(args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
	if code, out, _ := exec("version"); code != exitOK || strings.TrimSpace(out) != version {
		t.Errorf("version: %d %q", code, out)
	}
}

func TestInvalidConfigIsAUsageError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(p, []byte(`{"targets":[{"name":"gw","address":"h:443","pins":[]}]}`), 0o600)
	code, _, errs := exec("check", "-config", p)
	if code != exitUsage || !strings.Contains(errs, "at least one pin") {
		t.Errorf("exit %d: %s", code, errs)
	}
}

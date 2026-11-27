package probe

import (
	"context"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/soheiltaherpoor/gateway-tls-canary/internal/testutil"
)

const name = "gateway.example.com"

func pinOf(t *testing.T, der []byte) string {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Pin(c)
}

type pki struct {
	root, inter *testutil.CA
}

func newPKI(t *testing.T, label string) pki {
	root := testutil.NewRoot(t, label+" root")
	return pki{root: root, inter: root.NewIntermediate(t, label+" intermediate")}
}

func TestProbeReadsChainAndPins(t *testing.T) {
	p := newPKI(t, "good")
	leaf := p.inter.IssueLeaf(t, time.Time{}, name)
	srv := testutil.StartServer(t, leaf)

	res, err := Probe(context.Background(), srv.Addr, name, Options{RootCAs: p.root.Pool()})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Chain) != 2 {
		t.Fatalf("chain length %d, want 2 (leaf, intermediate)", len(res.Chain))
	}
	if res.Chain[0].Pin != pinOf(t, leaf.Certificate[0]) || res.Chain[1].Pin != pinOf(t, p.inter.DER) {
		t.Errorf("pins do not match the certificates: %+v", res.Chain)
	}
	if !strings.HasPrefix(res.Chain[0].Pin, "sha256:") || len(res.Chain[0].Pin) != len("sha256:")+64 {
		t.Errorf("pin format: %q", res.Chain[0].Pin)
	}
	if !res.ChainValid || res.ChainError != "" {
		t.Errorf("chain should verify: valid=%v err=%q", res.ChainValid, res.ChainError)
	}
	if got := srv.SNI(); got != name {
		t.Errorf("server saw SNI %q, want %q", got, name)
	}
	if res.TLSVersion == "" || res.Duration <= 0 {
		t.Errorf("missing metadata: %+v", res)
	}
}

func TestSNIDefaultsToHostAndCanBeOverridden(t *testing.T) {
	p := newPKI(t, "good")
	srv := testutil.StartServer(t, p.inter.IssueLeaf(t, time.Time{}, name))

	if _, err := Probe(context.Background(), srv.Addr, "", Options{}); err != nil {
		t.Fatal(err)
	}
	// An IP literal is never sent as SNI, so the server sees an empty name.
	if got := srv.SNI(); got != "" {
		t.Errorf("SNI for an IP address should be empty, got %q", got)
	}
	if _, err := Probe(context.Background(), srv.Addr, name, Options{}); err != nil {
		t.Fatal(err)
	}
	if got := srv.SNI(); got != name {
		t.Errorf("explicit sni not sent: %q", got)
	}
}

func TestUntrustedChainIsReportedNotRejected(t *testing.T) {
	p := newPKI(t, "private")
	srv := testutil.StartServer(t, p.inter.IssueLeaf(t, time.Time{}, name))
	res, err := Probe(context.Background(), srv.Addr, name, Options{RootCAs: x509.NewCertPool()})
	if err != nil {
		t.Fatalf("an untrusted chain must still be observed: %v", err)
	}
	if res.ChainValid || res.ChainError == "" || len(res.Chain) != 2 {
		t.Errorf("want invalid chain with details, got %+v", res)
	}
}

func TestWrongNameAndExpiry(t *testing.T) {
	p := newPKI(t, "good")
	srv := testutil.StartServer(t, p.inter.IssueLeaf(t, time.Time{}, name))

	res, err := Probe(context.Background(), srv.Addr, "other.example.com", Options{RootCAs: p.root.Pool()})
	if err != nil {
		t.Fatal(err)
	}
	if res.ChainValid {
		t.Error("certificate for another name must not verify")
	}

	future := func() time.Time { return time.Now().Add(30 * 24 * time.Hour) }
	res, err = Probe(context.Background(), srv.Addr, name, Options{RootCAs: p.root.Pool(), Now: future})
	if err != nil {
		t.Fatal(err)
	}
	if res.ChainValid {
		t.Error("expired certificate must not verify")
	}
}

func TestMatches(t *testing.T) {
	p := newPKI(t, "good")
	leaf := p.inter.IssueLeaf(t, time.Time{}, name)
	srv := testutil.StartServer(t, leaf)
	res, err := Probe(context.Background(), srv.Addr, name, Options{})
	if err != nil {
		t.Fatal(err)
	}
	leafPin, interPin := pinOf(t, leaf.Certificate[0]), pinOf(t, p.inter.DER)
	if i, ok := res.Matches([]string{"sha256:" + strings.Repeat("0", 64), leafPin}); !ok || i != 0 {
		t.Errorf("leaf pin: %d %v", i, ok)
	}
	if i, ok := res.Matches([]string{interPin}); !ok || i != 1 {
		t.Errorf("intermediate pin: %d %v", i, ok)
	}
	if _, ok := res.Matches([]string{"sha256:" + strings.Repeat("0", 64)}); ok {
		t.Error("unknown pin must not match")
	}
	if _, ok := res.Matches(nil); ok {
		t.Error("no pins must not match")
	}
}

// Renewal with a new key keeps an intermediate pin valid but changes the leaf pin.
func TestRenewalKeepsIntermediatePin(t *testing.T) {
	p := newPKI(t, "good")
	old := p.inter.IssueLeaf(t, time.Time{}, name)
	renewed := p.inter.IssueLeaf(t, time.Time{}, name)
	srv := testutil.StartServer(t, renewed)
	res, err := Probe(context.Background(), srv.Addr, name, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Matches([]string{pinOf(t, old.Certificate[0])}); ok {
		t.Error("old leaf pin must no longer match a re-keyed certificate")
	}
	if _, ok := res.Matches([]string{pinOf(t, p.inter.DER)}); !ok {
		t.Error("intermediate pin must survive a leaf renewal")
	}
}

// The case the tool exists for: a proxy re-signs traffic with a CA the host trusts.
// The chain verifies, the pins do not match.
func TestTrustedInterceptorIsDetected(t *testing.T) {
	real := newPKI(t, "real")
	mitm := newPKI(t, "interceptor")
	pins := []string{pinOf(t, real.inter.DER)}

	srv := testutil.StartServer(t, mitm.inter.IssueLeaf(t, time.Time{}, name))
	trust := mitm.root.Pool() // the interceptor's CA is installed on the probing host
	res, err := Probe(context.Background(), srv.Addr, name, Options{RootCAs: trust})
	if err != nil {
		t.Fatal(err)
	}
	if !res.ChainValid {
		t.Fatalf("setup: the interceptor's chain should verify: %s", res.ChainError)
	}
	if _, ok := res.Matches(pins); ok {
		t.Fatal("interception must be reported as a pin mismatch even though the chain is valid")
	}
}

func TestFailures(t *testing.T) {
	t.Run("connection refused", func(t *testing.T) {
		_, err := Probe(context.Background(), testutil.ClosedAddr(t), name, Options{Timeout: 2 * time.Second})
		if err == nil || !strings.Contains(err.Error(), "connect") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("not TLS", func(t *testing.T) {
		addr := testutil.StartRaw(t, func(c net.Conn) {
			defer c.Close()
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		})
		_, err := Probe(context.Background(), addr, name, Options{Timeout: 2 * time.Second})
		if err == nil || !strings.Contains(err.Error(), "TLS handshake") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("server never answers", func(t *testing.T) {
		addr := testutil.StartRaw(t, func(c net.Conn) { time.Sleep(5 * time.Second); c.Close() })
		start := time.Now()
		_, err := Probe(context.Background(), addr, name, Options{Timeout: 300 * time.Millisecond})
		if err == nil || time.Since(start) > 3*time.Second {
			t.Fatalf("want a timeout error within the limit, got %v after %s", err, time.Since(start))
		}
	})
	t.Run("bad address", func(t *testing.T) {
		if _, err := Probe(context.Background(), "no-port", name, Options{}); err == nil {
			t.Fatal("expected error")
		}
	})
}

// Package testutil builds throwaway certificate authorities and TLS servers for tests.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// CA is a certificate authority that can issue intermediates and leaves.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	DER  []byte
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func newCA(t testing.TB, cn string, parent *CA) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	signer, signKey := tpl, key
	if parent != nil {
		signer, signKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{Cert: cert, Key: key, DER: der}
}

// NewRoot returns a self-signed root CA.
func NewRoot(t testing.TB, cn string) *CA { return newCA(t, cn, nil) }

// NewIntermediate returns a CA signed by c.
func (c *CA) NewIntermediate(t testing.TB, cn string) *CA { return newCA(t, cn, c) }

// Pool returns a trust pool containing this CA.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.Cert)
	return p
}

// IssueLeaf returns a server certificate for the DNS names, presented as [leaf, c].
// notAfter may be zero for the default (24h).
func (c *CA) IssueLeaf(t testing.TB, notAfter time.Time, dns ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: dns[0]},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, c.DER}, PrivateKey: key}
}

// Server is a TLS server that completes handshakes and records the SNI it was asked for.
type Server struct {
	Addr string
	mu   sync.Mutex
	sni  string
	ln   net.Listener
}

// StartServer listens on 127.0.0.1 with a random port and presents cert.
func StartServer(t testing.TB, cert tls.Certificate) *Server {
	t.Helper()
	s := &Server{}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.mu.Lock()
			s.sni = h.ServerName
			s.mu.Unlock()
			return &cert, nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.ln, s.Addr = ln, ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

// SNI returns the server name the last client asked for.
func (s *Server) SNI() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sni
}

// StartRaw listens and runs handle for every connection (for non-TLS and hanging servers).
func StartRaw(t testing.TB, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// ClosedAddr returns a local address nothing listens on.
func ClosedAddr(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// Package probe connects to a TLS endpoint and records the certificate chain it presents.
package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

// CertInfo describes one certificate from the presented chain.
type CertInfo struct {
	Subject   string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	IsCA      bool
	// Pin is "sha256:" plus the hex SHA-256 of the certificate's SubjectPublicKeyInfo.
	Pin string
}

// Result is what one probe observed.
type Result struct {
	Chain      []CertInfo // as presented: leaf first
	ChainValid bool       // chain verifies for the requested name against the trust roots
	ChainError string     // why not, when ChainValid is false
	TLSVersion string
	Duration   time.Duration
}

// Options tune a probe. The zero value is usable.
type Options struct {
	Timeout time.Duration    // dial plus handshake, default 10s
	RootCAs *x509.CertPool   // trust roots for the ChainValid check; nil means the system roots
	Now     func() time.Time // for tests
}

// Pin returns the pin of a certificate: the SHA-256 of its public key info.
// It survives certificate renewal as long as the key pair is reused.
func Pin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Probe dials address, sends sni (default: the host part of address) and reads the chain.
//
// The handshake deliberately does not verify the chain: the point of a canary is to see
// what is presented even when it is untrusted or re-signed by a CA the host trusts. The chain
// is verified separately afterwards and reported in ChainValid.
func Probe(ctx context.Context, address, sni string, o Options) (*Result, error) {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("address %q: %w", address, err)
	}
	if sni == "" {
		sni = host
	}

	start := time.Now()
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer raw.Close()

	conn := tls.Client(raw, &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // intentional, see the function comment; verified below
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("server presented no certificate")
	}

	res := &Result{TLSVersion: tls.VersionName(state.Version), Duration: time.Since(start)}
	for _, c := range certs {
		res.Chain = append(res.Chain, CertInfo{
			Subject:   c.Subject.String(),
			Issuer:    c.Issuer.String(),
			NotBefore: c.NotBefore,
			NotAfter:  c.NotAfter,
			IsCA:      c.IsCA,
			Pin:       Pin(c),
		})
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	_, verr := certs[0].Verify(x509.VerifyOptions{
		DNSName:       sni,
		Roots:         o.RootCAs,
		Intermediates: intermediates,
		CurrentTime:   now,
	})
	res.ChainValid = verr == nil
	if verr != nil {
		res.ChainError = verr.Error()
	}
	return res, nil
}

// Matches reports whether any certificate in the presented chain carries one of the pins,
// and the position of the first such certificate (0 is the leaf).
func (r *Result) Matches(pins []string) (int, bool) {
	for i, c := range r.Chain {
		for _, p := range pins {
			if c.Pin == p {
				return i, true
			}
		}
	}
	return -1, false
}

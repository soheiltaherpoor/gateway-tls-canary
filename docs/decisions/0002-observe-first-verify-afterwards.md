# 2. Complete the handshake without verifying, then verify separately

Status: accepted

## Context

A normal TLS client aborts when the chain is untrusted. For a canary that hides the evidence: the interesting case is a chain the probing host does not trust, or one it does trust because a corporate or hostile CA was installed on it.

## Decision

The probe completes the handshake with certificate verification switched off, records the presented chain, then runs `x509.Verify` itself against the host's trust roots for the requested name. The two results are reported separately as `pin_match` and `chain_valid`.

## Consequences

- A re-signed chain that the host trusts shows `chain_valid 1` and `pin_match 0`, which is exactly the alarm.
- `chain_valid 0` with a matching pin means a trust-store or clock problem on the probing host, or an expired certificate.
- Nothing but the handshake is sent, so skipping verification cannot leak credentials.

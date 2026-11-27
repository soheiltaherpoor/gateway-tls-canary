# gateway-tls-canary

[![CI](https://github.com/soheiltaherpoor/gateway-tls-canary/actions/workflows/ci.yml/badge.svg)](https://github.com/soheiltaherpoor/gateway-tls-canary/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Pins the public keys of the TLS endpoints you depend on and alerts when they change, to catch interception and unannounced CA or key changes. One static Go binary, standard library only, Prometheus metrics.

## Why

If something between your servers and a payment gateway starts re-signing TLS traffic, your clients still connect and the certificate can even verify, because the proxy's CA is trusted on the host. Nothing breaks, so nothing alerts. A pin comparison does notice: the keys in the presented chain are not the ones you recorded.

## Quick start

```sh
go install github.com/soheiltaherpoor/gateway-tls-canary/cmd/gateway-tls-canary@latest

# 1. Record what the endpoint presents today (run it from the server that will do the probing)
gateway-tls-canary learn gateway.example.com:443
```

```text
gateway.example.com:443  TLS 1.3
chain verifies against the system trust roots

[0] leaf
    subject  CN=gateway.example.com
    issuer   CN=Example Intermediate CA
    expires  2027-01-15
    pin      sha256:...

[1] intermediate or root
    subject  CN=Example Intermediate CA
    issuer   CN=Example Root CA
    expires  2030-06-01
    pin      sha256:...
```

Put the pins you want in a config (see [`examples/config.example.json`](examples/config.example.json)):

```json
{
  "targets": [
    {"name": "payment-gateway", "address": "gateway.example.com:443",
     "pins": ["sha256:<intermediate pin>", "sha256:<leaf pin>"]}
  ]
}
```

```sh
# 2. One-off check, for cron or CI: exit 0 ok, 1 pin mismatch, 2 probe failed, 3 usage error
gateway-tls-canary check -config config.json
# 3. Or run continuously and let Prometheus scrape it
gateway-tls-canary serve -config config.json
```

Output of `check` (illustrative):

```text
[ OK ] payment-gateway  pinned key found at chain position 1; chain valid: true; leaf expires 2027-01-15
```
and when the chain changes:
```text
[FAIL] payment-gateway  PIN MISMATCH: no certificate in the presented chain has a pinned key (chain valid: true)
         [0] sha256:...
         [1] sha256:...
```

## Which pin to choose

| Pin | Survives leaf renewal | Catches a different CA | Notes |
|---|---|---|---|
| Intermediate CA key | Yes | Yes | Good default. Changes only when the provider changes CA. |
| Leaf key | Only if the key is reused | Yes | Strictest. Update before every re-key. |

You can list both. A target matches when any certificate in the presented chain has any listed pin. See [ADR 1](docs/decisions/0001-pin-public-keys-of-any-chain-certificate.md).

**Planned rotation:** add the new pin to the config and reload, let the provider rotate, then remove the old pin. If you only learn about a rotation when the alert fires, check with the provider before accepting the new pin.

## Metrics

`serve` listens on `127.0.0.1:9195` by default.

| Metric | Meaning |
|---|---|
| `tls_canary_pin_match{target}` | 1 if the chain contains a pinned key, 0 if not. Keeps its last value while probes fail. |
| `tls_canary_probe_success{target}` | 1 if the latest handshake completed. |
| `tls_canary_chain_valid{target}` | 1 if the chain verifies for the name against this host's trust store. |
| `tls_canary_cert_not_after_timestamp_seconds{target}` | Leaf expiry. |
| `tls_canary_probe_duration_seconds{target}` | Dial plus handshake time. |
| `tls_canary_last_probe_timestamp_seconds{target}` | When the latest probe finished. |
| `tls_canary_info{target,leaf_pin,issuer}` | Always 1; shows what was last seen. |

[`examples/alerts.yml`](examples/alerts.yml) has alerts for mismatch, failing or stale probes, invalid chain and nearing expiry. To get the mismatch in a chat, route it through Alertmanager, for example with [alert-chatops-bridge](https://github.com/soheiltaherpoor/alert-chatops-bridge).

## Configuration

| Key | Default | Notes |
|---|---|---|
| `listen` | `127.0.0.1:9195` | Use `":9195"` in a container and keep the port on a private network. |
| `interval` | `5m` | At least 10s. |
| `timeout` | `10s` | Dial plus handshake; between 1s and the interval. |
| `targets[].name` | | Letters, digits, `_ . -`; unique. |
| `targets[].address` | | `host:port`. |
| `targets[].sni` | the host part | Set it when probing an IP address or a name that differs from the host. |
| `targets[].pins` | | At least one, `sha256:` plus 64 hex characters. |

Unknown keys are rejected, so a typo cannot silently disable a setting.

## Docker

```sh
make docker
docker run --rm -v $PWD/config.json:/config.json:ro gateway-tls-canary
```

`scratch` image with the CA bundle (used for `chain_valid`), runs as UID 65534. Set `"listen": ":9195"` in the config. See [`examples/docker-compose.yml`](examples/docker-compose.yml).

## How it was tested

Unit tests build throwaway certificate authorities and TLS servers and cover: reading and pinning a real chain; SNI handling; an untrusted chain being reported rather than rejected; wrong name and expiry; leaf renewal under an intermediate pin; a re-signing proxy whose CA the host trusts (chain valid, pin mismatch); refused connections, non-TLS servers and servers that never answer; the metrics output and logging; the exit codes. The example alert rules are checked with `promtool` in CI.

## Limitations

- It sees what the probing host sees. An attacker who intercepts only some networks or only some clients can be invisible from where the canary runs; probe from the servers that matter.
- A pin match proves the endpoint presents the expected keys, not that the connection cannot be intercepted by someone holding those keys.
- Legitimate CA or key changes at the endpoint alert until you add the new pin.
- `chain_valid` depends on the host's trust store and clock.
- TLS 1.2 or higher only. Endpoints that still speak older versions will show as probe failures.
- It does not replace Certificate Transparency monitoring, which sees certificates issued for your own domains.

## Design decisions

[docs/decisions](docs/decisions): what a pin is, observe first and verify afterwards, metrics instead of notifications.

## License

MIT, see [LICENSE](LICENSE).

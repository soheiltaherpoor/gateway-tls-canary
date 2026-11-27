# Security policy

If you find a vulnerability in gateway-tls-canary, please report it privately through GitHub's "Report a vulnerability" button on the Security tab of this repository, rather than in a public issue.

The tool makes outbound TLS connections to the endpoints you list and serves read-only metrics. It sends no data to the endpoints beyond a normal TLS handshake. The handshake deliberately does not abort on an untrusted certificate, because its purpose is to observe what is presented; it never sends credentials or application data. Do not expose the metrics port to the internet.

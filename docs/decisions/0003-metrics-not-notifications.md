# 3. Export metrics and exit codes; leave notification to the monitoring stack

Status: accepted

## Context

Teams already have Prometheus, Alertmanager or a cron job with a mail command. A canary that sends its own messages needs credentials, retries and routing that those tools already provide.

## Decision

`serve` exposes Prometheus metrics and logs mismatches; `check` returns exit code 0 (ok), 1 (pin mismatch), 2 (probe failed) or 3 (usage or config error) for cron and CI. Example alert rules are included. Standard library only.

## Consequences

- To get a chat message, route the `TlsPinMismatch` alert through Alertmanager, for example with [alert-chatops-bridge](https://github.com/soheiltaherpoor/alert-chatops-bridge).
- `pin_match` keeps its last value while probes fail, so a mismatch alert does not clear just because the next probe timed out. `probe_success` and `last_probe_timestamp` cover the "canary itself is broken" case.
- No built-in de-duplication or silences; Alertmanager owns that.

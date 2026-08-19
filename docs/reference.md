# Reference

## Tools

### `health_check`

No parameters. Returns `{status, service, version, binaries, missing}`.
`status` is `"healthy"` when `dig`/`ping`/`mtr`/`whois` are all on PATH,
`"degraded"` when at least one is missing — the corresponding tools fail at
call time, but the server itself keeps running.

### `dns_lookup(hostname, record_type="A", resolver=None, transport="plain")`

Resolve a DNS record via `dig`. `record_type`: `A`/`AAAA`/`MX`/`TXT`/`NS`/
`CNAME`/`SOA`/`PTR`/`CAA`. Pass `resolver` to query a specific nameserver
instead of the host default (e.g. to check propagation to a given
resolver). `transport`: `"plain"` (UDP/TCP 53, default), `"dot"`
(DNS-over-TLS, 853) or `"doh"` (DNS-over-HTTPS, 443) — requires `dig` from
BIND 9.18+; an older `dig` rejects `dot`/`doh` outright instead of silently
falling back to plain DNS.

### `dnssec_check(hostname, resolver="1.1.1.1", transport="plain")`

Query a known-validating resolver and report whether the AD bit is set.
`transport` as above — useful to compare validation over plain DNS vs. an
encrypted transport when port 53 may be intercepted.

### `ping_host(host, count=4)`

ICMP ping. `count` is clamped to 1-10. On macOS, IPv6 literals are
dispatched to `ping6` (macOS's `ping` rejects them outright); on Linux,
`ping` handles both families and `ping6` is never used.

### `traceroute_path(host, cycles=3)`

Hop-by-hop path/loss report via `mtr --report` (fixed cycles, not a
live/continuous run). `cycles` clamped to 1-10. Needs `mtr-packet`'s
`cap_net_raw` capability; without it, fails cleanly with a `ToolError`
rather than crashing the server.

### `tcp_port_check(host, port, timeout=5.0)`

Is a TCP port open — a plain socket connect to exactly one `host:port`, not
a port scan. No loop or range argument, by design.

### `http_check(url, timeout=5.0)`

HEAD/GET a URL and report status, redirect chain, and latency.

### `tls_cert_check(host, port=443)`

Fetch the certificate a host presents and report subject/issuer/validity/
SANs. Against a bare IP on an SNI-hosted/CDN-fronted origin this can fail
the handshake — normal TLS behavior, not a tool bug (see
[index](index.md#design-notes)).

### `whois_lookup(domain)`

WHOIS lookup for a domain.

### `asn_lookup(target)`

ASN + country-code lookup for an IP, or org info for an AS number (e.g.
`AS15169` or `15169`), via Team Cymru's whois service — no API key or
GeoIP database needed. Takes an IP literal or AS number, not a hostname;
resolve first with `dns_lookup` if you only have a name.

## Errors

Every tool catches `ValueError` (bad input) and `ToolError` (the wrapped
command failed) and returns them as a `"error: ..."` string rather than
raising, so a caller always gets a string back.

## CLI

```bash
netdiag-mcp --version   # print version
netdiag-mcp --check     # report which wrapped binaries are present (exit 0 when all are)
```

`--check` exits non-zero if any of `dig`/`ping`/`mtr`/`whois` is missing —
useful in a deploy script to fail fast before the server would otherwise
degrade silently.

## Security notes

- Every external-binary call passes an argv list (never a shell string), so
  no tool argument can break out into shell syntax.
- Hostname/IP and port arguments are validated and size/range-clamped
  before use — tool input is model-driven and treated as untrusted, the
  same as any other tool-calling surface.
- All tools are read-only; there is no write/mutating tool in this server.

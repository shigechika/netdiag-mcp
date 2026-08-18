<!-- mcp-name: io.github.shigechika/netdiag-mcp -->

# netdiag-mcp

English | [日本語](README.ja.md)

MCP server for on-demand network diagnostics — DNS lookups (with a DNSSEC AD-bit check), ping, an `mtr`-based path report, TCP port checks, HTTP status/redirect checks, TLS certificate inspection, and WHOIS, all from one server.

Built for triaging "can't reach X" / "is DNS propagated yet" reports without shelling into a jump host for each one-off `dig`/`ping`/`curl`.

## Tools

| Tool | Purpose |
|---|---|
| `dns_lookup` | Resolve a DNS record via `dig` (A/AAAA/MX/TXT/NS/CNAME/SOA/PTR/CAA), optionally against a specific resolver and over plain DNS/DoT/DoH |
| `dnssec_check` | Query a known-validating resolver and report whether the AD bit is set (plain/DoT/DoH) — the only reliable way to confirm DNSSEC validation, since an RRSIG being present in a plain `dig` reply does not by itself prove anything validated it |
| `ping_host` | ICMP ping (count clamped to 1-10) |
| `traceroute_path` | Hop-by-hop path/loss report via `mtr --report` (fixed cycles, not a live/continuous run) |
| `tcp_port_check` | Is a TCP port open — a plain socket connect, not a port scan |
| `http_check` | HEAD/GET a URL and report status, redirect chain, and latency |
| `tls_cert_check` | Fetch the certificate a host presents and report subject/issuer/validity/SANs |
| `whois_lookup` | WHOIS lookup for a domain |
| `asn_lookup` | ASN + country-code lookup for an IP, or org info for an AS number, via Team Cymru's whois service — no API key or GeoIP database needed |
| `health_check` | Version and which wrapped binaries (`dig`/`ping`/`mtr`/`whois`) are present on PATH |

All tools are read-only and single-target (no batch/sweep mode) — this is a
convenience wrapper around checks an operator would run by hand, not a
scanning tool. `nmap`-style multi-host/multi-port scanning is intentionally
out of scope; deliberately probing many hosts or ports is a different,
higher-blast-radius action that deserves its own tooling and approval flow.

`tcp_port_check`, `http_check` and `tls_cert_check` use Python's own
socket/ssl/httpx stack rather than shelling out to `nc`/`curl`/`openssl`, so
those three tools work even on a host with only the `dig`/`ping`/`mtr`/`whois`
binaries installed (or none of them — `health_check` reports which are
missing without failing the whole server).

`dns_lookup`/`dnssec_check` support DNS-over-TLS and DNS-over-HTTPS via
`transport="dot"`/`"doh"` (dig's `+tls`/`+https`). This needs `dig` from
BIND 9.18+ — an older `dig` rejects the flag outright rather than silently
falling back to plain DNS, so a stale binary fails loudly instead of giving
a false sense of having checked over an encrypted transport.

`tls_cert_check`/`http_check` against a bare IP address can fail TLS
handshake with a "handshake failure" or similar error on SNI-hosted /
CDN-fronted origins (e.g. behind Cloudflare) — TLS's SNI extension only
carries hostnames, so an IP literal can't route to the right certificate on
a shared edge. This is normal TLS behavior, not a tool bug; check by
hostname when the target is CDN-fronted.

## Setup

### 1. System dependencies

`dns_lookup`, `dnssec_check`, `ping_host`, `traceroute_path` and
`whois_lookup` shell out to `dig`, `ping`, `mtr` and `whois` respectively.
Install whichever of these you want available:

```bash
# Debian/Ubuntu
sudo apt install dnsutils iputils-ping mtr-tiny whois
```

`mtr` needs raw-socket access. Debian/Ubuntu's `mtr-tiny` package grants
`cap_net_raw` to the `mtr-packet` helper at install time, so it normally
works for an unprivileged service user without further setup — verify with
`getcap "$(command -v mtr-packet)"` if `traceroute_path` reports a socket
permission error. Without that capability, `traceroute_path` fails cleanly
with a `ToolError` rather than crashing the server.

### 2. Install

```bash
pip install netdiag-mcp
# or
uv tool install netdiag-mcp
```

### 3. Claude Code (manual)

```bash
claude mcp add netdiag -- netdiag-mcp
```

No environment variables are required.

## CLI

```bash
netdiag-mcp --version   # print version
netdiag-mcp --check     # report which wrapped binaries are present (exit 0 when all are)
```

## Security notes

- Every external-binary call passes an argv list (never a shell string), so
  no tool argument can break out into shell syntax.
- Hostname/IP and port arguments are validated and size/range-clamped before
  use — tool input is model-driven and treated as untrusted, the same as any
  other tool-calling surface.
- `tcp_port_check` connects to exactly one host:port per call; there is no
  loop or range argument, by design.

## License

MIT

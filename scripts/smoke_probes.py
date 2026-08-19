"""Probe specs for this server's tools — the netdiag-specific half of the smoke test.

Every registered tool needs an entry here (the harness fails on a tool with no
spec), so adding a tool forces a decision: how would we know it works?

**All read-only, no skips.** Every tool in this server is a read-only
diagnostic (there is no config-changing tool at all), so unlike other
servers in this family, nothing here is skipped for blast-radius reasons.

**Public, stable targets only.** This server takes no config and has no
inventory to discover a target from (unlike a device-fleet server), so every
probe targets a well-known public endpoint chosen for being unlikely to
change: Cloudflare's 1.1.1.1 (ping/traceroute/TCP/ASN) and IANA's
example.com (DNS/HTTP/TLS/WHOIS, explicitly reserved by IANA for
documentation and testing use, RFC 2606).

Every tool wrapper in server.py catches (ValueError, ToolError) and returns
"error: ..." instead of raising, so that is the one failure shape every
probe below must refuse.
"""

from smoke_harness import Probe

#: The one failure shape every tool in this server can render instead of a
#: real answer (see server.py's per-tool try/except).
NO_ERROR = (r"^error:",)

PROBES: dict[str, Probe] = {
    "health_check": Probe(
        require_keys=("status", "service", "version"),
        must_match=(r'"status": "(healthy|degraded)"',),
        allow_empty=True,
    ),
    "dns_lookup": Probe(
        args={"hostname": "example.com", "record_type": "A"},
        must_match=(r"(?i)example\.com\.\s+\d+\s+IN\s+A\s+",),
        must_not_match=NO_ERROR,
    ),
    "dnssec_check": Probe(
        # cloudflare.com is DNSSEC-signed and 1.1.1.1 is a validating
        # resolver, so this exercises the actual "AD bit set" success path,
        # not just "the tool ran".
        args={"hostname": "cloudflare.com", "resolver": "1.1.1.1"},
        must_match=(r"^DNSSEC validated \(AD bit set\)",),
        must_not_match=NO_ERROR,
    ),
    "ping_host": Probe(
        args={"host": "1.1.1.1", "count": 2},
        must_match=(r"\d+ (packets transmitted|received)",),
        must_not_match=NO_ERROR,
    ),
    "traceroute_path": Probe(
        args={"host": "1.1.1.1", "cycles": 1},
        # "Loss%" is mtr --report's column header, present whether or not
        # every hop answered — the thing this probe verifies is that mtr
        # ran and produced a report at all.
        must_match=(r"Loss%",),
        must_not_match=NO_ERROR,
    ),
    "tcp_port_check": Probe(
        args={"host": "1.1.1.1", "port": 443},
        must_match=(r"^1\.1\.1\.1:443 open \(",),
        must_not_match=NO_ERROR,
    ),
    "http_check": Probe(
        args={"url": "https://example.com"},
        must_match=(r"^\d{3} \S+\s+\d+ms\s+final_url=",),
        must_not_match=NO_ERROR,
    ),
    "tls_cert_check": Probe(
        args={"host": "example.com"},
        must_match=(r"^subject: ", r"^issuer: ", r"^validity: "),
        must_not_match=NO_ERROR,
    ),
    "whois_lookup": Probe(
        args={"domain": "example.com"},
        # example.com's registry is IANA itself (not a Verisign/registrar
        # whois server), whose response uses "domain:" rather than the
        # "Domain Name:" label common elsewhere.
        must_match=(r"(?im)^domain:\s*example\.com",),
        must_not_match=NO_ERROR,
    ),
    "asn_lookup": Probe(
        # 1.1.1.1 is Cloudflare's, stably AS13335.
        args={"target": "1.1.1.1"},
        must_match=(r"13335",),
        must_not_match=NO_ERROR,
    ),
}

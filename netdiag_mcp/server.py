"""netdiag-mcp — MCP Server tools."""

import shutil

from mcp.server.fastmcp import FastMCP

from netdiag_mcp import tools
from netdiag_mcp.tools import ToolError

mcp = FastMCP("netdiag-mcp")

# health_check probes these; missing ones degrade rather than fail outright
# so the server stays usable for whichever tools still have their binary.
_REQUIRED_BINARIES = ("dig", "ping", "mtr", "whois")


@mcp.tool()
def health_check() -> dict:
    """Service health: version and which wrapped binaries are present on PATH.

    Returns a fixed shape (status/service/version + backend fields) so a
    monitoring caller never has to branch on missing keys. status is
    "healthy" when every wrapped binary is found, "degraded" when at least
    one is missing (the corresponding tools will fail at call time).
    """
    from netdiag_mcp import __version__

    binaries = {name: shutil.which(name) is not None for name in _REQUIRED_BINARIES}
    missing = [name for name, present in binaries.items() if not present]
    return {
        "status": "healthy" if not missing else "degraded",
        "service": "netdiag-mcp",
        "version": __version__,
        "binaries": binaries,
        "missing": missing,
    }


@mcp.tool()
def dns_lookup(hostname: str, record_type: str = "A", resolver: str | None = None, transport: str = "plain") -> str:
    """Resolve a DNS record via `dig`. record_type: A/AAAA/MX/TXT/NS/CNAME/SOA/PTR/CAA.

    Pass resolver to query a specific nameserver instead of the host default
    (e.g. to check whether a change has propagated to a given resolver).
    transport: "plain" (UDP/TCP 53, default), "dot" (DNS-over-TLS, 853) or
    "doh" (DNS-over-HTTPS, 443). Requires dig from BIND 9.18+; an older dig
    rejects dot/doh outright instead of silently querying over plain DNS.
    """
    try:
        return tools.dns_lookup(hostname, record_type, resolver, transport)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def dnssec_check(hostname: str, resolver: str = "1.1.1.1", transport: str = "plain") -> str:
    """Check whether a name validates DNSSEC against a known-validating resolver (AD bit).

    transport: "plain" (default), "dot" or "doh" — compare validation over
    plain DNS vs. an encrypted transport when port 53 may be intercepted.
    """
    try:
        return tools.dnssec_check(hostname, resolver, transport)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def ping_host(host: str, count: int = 4) -> str:
    """ICMP ping a host or IP. count is clamped to 1-10."""
    try:
        return tools.ping_host(host, count)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def traceroute_path(host: str, cycles: int = 3) -> str:
    """Path/MTU-style hop report via `mtr --report` (fixed cycles, not a live run). cycles clamped 1-10."""
    try:
        return tools.traceroute_path(host, cycles)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def tcp_port_check(host: str, port: int, timeout: float = 5.0) -> str:
    """Check whether a TCP port is open (plain socket connect, no port scanning)."""
    try:
        return tools.tcp_port_check(host, port, timeout)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def http_check(url: str, timeout: float = 5.0) -> str:
    """HEAD/GET a URL and report status, redirect chain and latency."""
    try:
        return tools.http_check(url, timeout)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def tls_cert_check(host: str, port: int = 443) -> str:
    """Fetch the TLS certificate presented on host:port and report subject/issuer/validity/SANs."""
    try:
        return tools.tls_cert_check(host, port)
    except (ValueError, ToolError) as e:
        return f"error: {e}"


@mcp.tool()
def whois_lookup(domain: str) -> str:
    """WHOIS lookup for a domain."""
    try:
        return tools.whois_lookup(domain)
    except (ValueError, ToolError) as e:
        return f"error: {e}"

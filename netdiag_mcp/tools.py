"""Wrappers around external diagnostic binaries and Python's own socket/ssl/httpx stack.

Every external-binary call uses an argv list (never shell=True), so no
argument can break out into shell syntax regardless of what the caller
passes — validate.py's job is bounding *size*, not escaping.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
from datetime import UTC, datetime

import httpx

from netdiag_mcp.validate import clamp, validate_port, validate_target

DEFAULT_TIMEOUT = 5.0
SUBPROCESS_TIMEOUT = 15.0

DNS_RECORD_TYPES = {"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "CAA"}


class ToolError(Exception):
    """A tool could not run at all (missing binary, timeout, bad input)."""


def _run(binary: str, args: list[str]) -> str:
    if shutil.which(binary) is None:
        raise ToolError(f"{binary} is not installed on this host")
    try:
        proc = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
    except subprocess.TimeoutExpired as e:
        raise ToolError(f"{binary} timed out after {SUBPROCESS_TIMEOUT:g}s") from e
    out = proc.stdout.strip()
    err = proc.stderr.strip()
    if proc.returncode != 0 and not out:
        raise ToolError(err or f"{binary} exited {proc.returncode} with no output")
    return out if not err else f"{out}\n[stderr] {err}" if out else err


def dns_lookup(hostname: str, record_type: str = "A", resolver: str | None = None) -> str:
    target = validate_target(hostname)
    rtype = record_type.strip().upper()
    if rtype not in DNS_RECORD_TYPES:
        raise ToolError(f"unsupported record type {record_type!r}; use one of {sorted(DNS_RECORD_TYPES)}")
    args = []
    if resolver:
        args.append(f"@{validate_target(resolver)}")
    args += [target, rtype, "+noall", "+answer", "+stats"]
    return _run("dig", args)


def dnssec_check(hostname: str, resolver: str = "1.1.1.1") -> str:
    """Query a validating resolver and report whether the AD (Authenticated Data) bit is set.

    A bare `dig` reply with an RRSIG present does NOT mean DNSSEC validated
    — only a resolver that itself validates and sets the AD flag proves
    that. This deliberately targets a known-validating public resolver
    rather than trusting whatever the host's default resolver is.
    """
    target = validate_target(hostname)
    res = validate_target(resolver)
    out = _run("dig", [f"@{res}", target, "+dnssec", "+noall", "+comment", "+answer"])
    ad_set = "flags:" in out and " ad" in out.split("flags:", 1)[1].split(";", 1)[0]
    verdict = "DNSSEC validated (AD bit set)" if ad_set else "DNSSEC NOT validated (AD bit absent)"
    return f"{verdict}\n\n{out}"


def ping_host(host: str, count: int = 4) -> str:
    target = validate_target(host)
    n = clamp(count, 1, 10)
    return _run("ping", ["-c", str(n), target])


def traceroute_path(host: str, cycles: int = 3) -> str:
    """mtr in report mode — a fixed number of cycles, not a live/continuous run."""
    target = validate_target(host)
    n = clamp(cycles, 1, 10)
    return _run("mtr", ["--report", "--report-cycles", str(n), "--no-dns", target])


def whois_lookup(domain: str) -> str:
    target = validate_target(domain)
    return _run("whois", [target])


def tcp_port_check(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Native TCP connect probe — no `nc` dependency, no shell involved at all."""
    target = validate_target(host)
    p = validate_port(port)
    t = clamp(timeout, 1, 15)
    start = datetime.now(UTC)
    try:
        with socket.create_connection((target, p), timeout=t):
            elapsed_ms = (datetime.now(UTC) - start).total_seconds() * 1000
            return f"{target}:{p} open ({elapsed_ms:.1f}ms)"
    except TimeoutError:
        return f"{target}:{p} timed out after {t:g}s"
    except (ConnectionRefusedError, OSError) as e:
        return f"{target}:{p} closed/unreachable: {e}"


def http_check(url: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """HEAD (falling back to GET) via httpx — reports status, redirect chain and latency."""
    t = clamp(timeout, 1, 15)
    try:
        with httpx.Client(follow_redirects=True, timeout=t) as client:
            start = datetime.now(UTC)
            resp = client.head(url)
            if resp.status_code == 405:
                resp = client.get(url)
            elapsed_ms = (datetime.now(UTC) - start).total_seconds() * 1000
    except httpx.HTTPError as e:
        raise ToolError(f"HTTP request failed: {e}") from e
    lines = [f"{resp.status_code} {resp.reason_phrase}  {elapsed_ms:.0f}ms  final_url={resp.url}"]
    if resp.history:
        chain = " -> ".join(str(r.url) for r in [*resp.history, resp])
        lines.append(f"redirects: {chain}")
    for header in ("server", "content-type", "content-length"):
        if header in resp.headers:
            lines.append(f"{header}: {resp.headers[header]}")
    return "\n".join(lines)


def tls_cert_check(host: str, port: int = 443) -> str:
    """Native ssl/socket TLS handshake — reports the peer certificate, not raw openssl s_client text."""
    target = validate_target(host)
    p = validate_port(port)
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((target, p), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
    except ssl.SSLCertVerificationError as e:
        return f"TLS handshake failed certificate verification: {e}"
    except (TimeoutError, OSError) as e:
        raise ToolError(f"could not connect to {target}:{p}: {e}") from e
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    lines = [
        f"subject: {subject.get('commonName', '?')}",
        f"issuer: {issuer.get('commonName', '?')}",
        f"validity: {cert.get('notBefore')} -> {cert.get('notAfter')}",
        f"cipher: {cipher[0]} {cipher[1]}" if cipher else "cipher: ?",
    ]
    if sans:
        lines.append(f"subjectAltName: {', '.join(sans)}")
    return "\n".join(lines)

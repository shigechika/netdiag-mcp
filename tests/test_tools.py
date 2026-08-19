import socket
import subprocess
import threading

import httpx
import pytest

from netdiag_mcp import tools
from netdiag_mcp.tools import ToolError


def test_run_raises_when_binary_missing(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda _: None)
    with pytest.raises(ToolError, match="not installed"):
        tools._run("dig", ["example.com"])


def test_run_raises_on_timeout(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/usr/bin/dig")

    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd="dig", timeout=15)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ToolError, match="timed out"):
        tools._run("dig", ["example.com"])


def test_run_returns_stdout(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda _: "/usr/bin/dig")
    proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="192.0.2.1\n", stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: proc)
    assert tools._run("dig", ["example.com"]) == "192.0.2.1"


def test_dns_lookup_rejects_unknown_record_type():
    with pytest.raises(ToolError, match="unsupported record type"):
        tools.dns_lookup("example.com", "BOGUS")


def test_dns_lookup_rejects_bad_hostname():
    with pytest.raises(ValueError):
        tools.dns_lookup("not a host", "A")


def test_dns_lookup_rejects_unknown_transport():
    with pytest.raises(ToolError, match="unsupported transport"):
        tools.dns_lookup("example.com", "A", transport="quic")


def test_dns_lookup_plain_transport_adds_no_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("args", args) or "ok")
    tools.dns_lookup("example.com", "A", transport="plain")
    assert "+tls" not in captured["args"]
    assert "+https" not in captured["args"]


@pytest.mark.parametrize("transport,flag", [("dot", "+tls"), ("doh", "+https")])
def test_dns_lookup_encrypted_transport_adds_flag(monkeypatch, transport, flag):
    captured = {}
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("args", args) or "ok")
    tools.dns_lookup("example.com", "A", resolver="1.1.1.1", transport=transport)
    assert flag in captured["args"]
    assert "@1.1.1.1" in captured["args"]


def test_dnssec_check_rejects_unknown_transport():
    with pytest.raises(ToolError, match="unsupported transport"):
        tools.dnssec_check("example.com", transport="quic")


@pytest.mark.parametrize("transport,flag", [("dot", "+tls"), ("doh", "+https")])
def test_dnssec_check_encrypted_transport_adds_flag(monkeypatch, transport, flag):
    captured = {}

    def fake_run(binary, args):
        captured["args"] = args
        return ";; flags: qr rd ra ad; QUERY: 1, ANSWER: 1"

    monkeypatch.setattr(tools, "_run", fake_run)
    tools.dnssec_check("example.com", transport=transport)
    assert flag in captured["args"]


def test_dnssec_check_detects_ad_flag(monkeypatch):
    fake_output = ";; flags: qr rd ra ad; QUERY: 1, ANSWER: 1\nexample.com. 300 IN A 192.0.2.1"
    monkeypatch.setattr(tools, "_run", lambda binary, args: fake_output)
    result = tools.dnssec_check("example.com")
    assert "DNSSEC validated" in result


def test_dnssec_check_reports_missing_ad_flag(monkeypatch):
    fake_output = ";; flags: qr rd ra; QUERY: 1, ANSWER: 1\nexample.com. 300 IN A 192.0.2.1"
    monkeypatch.setattr(tools, "_run", lambda binary, args: fake_output)
    result = tools.dnssec_check("example.com")
    assert "NOT validated" in result


def test_ping_host_clamps_count(monkeypatch):
    captured = {}

    def fake_run(binary, args):
        captured["args"] = args
        return "ok"

    monkeypatch.setattr(tools, "_run", fake_run)
    tools.ping_host("example.com", count=999)
    assert captured["args"][1] == "10"  # clamped to the max


def test_ping_host_sets_an_overall_deadline(monkeypatch):
    """Regression guard: without a deadline flag an unreachable target makes
    ping wait its own per-packet default for every probe (observed ~12s for
    count=2 against a black-holed address), which can exceed
    SUBPROCESS_TIMEOUT and turn a clean 100%-loss report into a hard-killed
    generic timeout error instead."""
    captured = {}
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("args", args) or "ok")
    tools.ping_host("example.com", count=4)
    assert "-w" in captured["args"] or "-t" in captured["args"]


def test_ping_host_uses_ping6_for_ipv6_literal_on_macos(monkeypatch):
    """Regression guard: BSD/macOS `ping` is IPv4-only and rejects an IPv6
    literal outright ("cannot resolve ...: Unknown host") — a bare IPv6
    literal must dispatch to `ping6` there. Linux's iputils `ping` handles
    both, so this only applies off-Linux."""
    captured = {}
    monkeypatch.setattr(tools.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("binary", binary) or "ok")
    tools.ping_host("2001:db8::1")
    assert captured["binary"] == "ping6"


def test_ping_host_uses_ping_for_ipv4_on_macos(monkeypatch):
    captured = {}
    monkeypatch.setattr(tools.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("binary", binary) or "ok")
    tools.ping_host("192.0.2.1")
    assert captured["binary"] == "ping"


def test_ping_host_uses_ping_for_ipv6_on_linux(monkeypatch):
    """Linux's iputils ping is dual-stack — no ping6 dispatch needed there."""
    captured = {}
    monkeypatch.setattr(tools.platform, "system", lambda: "Linux")
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("binary", binary) or "ok")
    tools.ping_host("2001:db8::1")
    assert captured["binary"] == "ping"


def test_tcp_port_check_open_port():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    t = threading.Thread(target=lambda: server.accept(), daemon=True)
    t.start()
    try:
        result = tools.tcp_port_check("127.0.0.1", port, timeout=2)
        assert "open" in result
    finally:
        server.close()


def test_tcp_port_check_closed_port():
    # Bind and immediately close to get a port nothing is listening on.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    result = tools.tcp_port_check("127.0.0.1", port, timeout=2)
    # Most platforms RST an unbound loopback port immediately (ECONNREFUSED).
    # Windows CI runners have been observed to instead let the connect()
    # attempt time out rather than refuse it right away, which
    # tcp_port_check already handles as a distinct, valid outcome (see its
    # `except TimeoutError` branch) -- accept either shape rather than
    # assuming one platform's socket behavior everywhere.
    assert "closed" in result or "unreachable" in result or "timed out" in result


def test_http_check_reports_status_and_headers(monkeypatch):
    real_client = httpx.Client

    def handler(request):
        return httpx.Response(200, headers={"server": "test-server"}, request=request)

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(tools.httpx, "Client", fake_client)
    result = tools.http_check("https://example.com")
    assert "200" in result
    assert "server: test-server" in result


def test_http_check_wraps_transport_errors(monkeypatch):
    real_client = httpx.Client

    def handler(request):
        raise httpx.ConnectError("boom", request=request)

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(tools.httpx, "Client", fake_client)
    with pytest.raises(ToolError, match="HTTP request failed"):
        tools.http_check("https://example.com")


def test_tls_cert_check_raises_on_connection_failure():
    # Port 1 is a reserved system port with nothing listening in CI/dev.
    with pytest.raises(ToolError):
        tools.tls_cert_check("127.0.0.1", 1)


@pytest.mark.parametrize("value", ["AS15169", "as15169", "15169"])
def test_asn_lookup_normalizes_as_number(monkeypatch, value):
    captured = {}
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("args", args) or "ok")
    tools.asn_lookup(value)
    assert captured["args"] == ["-h", "whois.cymru.com", " -v AS15169"]


def test_asn_lookup_passes_through_ip(monkeypatch):
    captured = {}
    monkeypatch.setattr(tools, "_run", lambda binary, args: captured.setdefault("args", args) or "ok")
    tools.asn_lookup("8.8.8.8")
    assert captured["args"] == ["-h", "whois.cymru.com", " -v 8.8.8.8"]


def test_asn_lookup_rejects_hostname():
    with pytest.raises(ToolError, match="not a hostname"):
        tools.asn_lookup("example.com")

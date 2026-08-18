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
    assert "closed" in result or "unreachable" in result


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

import ipaddress
import socket

import httpcore
import httpx
import pytest

from netdiag_mcp import nat64, server, tools
from netdiag_mcp.tools import ToolError

PREFIX = "64:ff9b::/96"


def _clear_proxies(monkeypatch):
    for var in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def nat64_env(monkeypatch):
    monkeypatch.setenv(nat64.ENV_VAR, PREFIX)


def test_load_prefix_unset_is_none():
    assert nat64.load_prefix({}) is None
    assert nat64.load_prefix({nat64.ENV_VAR: "  "}) is None


def test_load_prefix_accepts_96():
    assert nat64.load_prefix({nat64.ENV_VAR: "2001:db8:64::/96"}) == ipaddress.IPv6Network("2001:db8:64::/96")


@pytest.mark.parametrize(
    "raw", ["64:ff9b::/64", "192.0.2.0/24", "not-a-prefix", "64:ff9b::1/96", "fd12:3456:789a:0:100::/96"]
)
def test_load_prefix_rejects_malformed(raw):
    with pytest.raises(nat64.Nat64ConfigError):
        nat64.load_prefix({nat64.ENV_VAR: raw})


def test_synthesize_ipv4_literal():
    net = ipaddress.IPv6Network(PREFIX)
    assert nat64.synthesize("192.0.2.33", net) == "64:ff9b::c000:221"


@pytest.mark.parametrize("target", ["example.com", "2001:db8::1"])
def test_synthesize_leaves_other_targets(target):
    assert nat64.synthesize(target, ipaddress.IPv6Network(PREFIX)) == target


def test_synthesize_without_prefix_is_identity():
    assert nat64.synthesize("192.0.2.33", None) == "192.0.2.33"


def test_embedded_ipv4s_well_known_and_configured():
    custom = ipaddress.IPv6Network("2001:db8:64::/96")
    assert nat64.embedded_ipv4s(ipaddress.ip_address("64:ff9b::a9fe:a9fe"), None) == [
        ipaddress.ip_address("169.254.169.254")
    ]
    assert nat64.embedded_ipv4s(ipaddress.ip_address("2001:db8:64::7f00:1"), custom) == [
        ipaddress.ip_address("127.0.0.1")
    ]
    assert nat64.embedded_ipv4s(ipaddress.ip_address("2001:db8::1"), custom) == []
    assert nat64.embedded_ipv4s(ipaddress.ip_address("192.0.2.1"), custom) == []


def test_status_reports_prefix_and_error():
    assert nat64.status({}) == {"prefix": None, "error": None}
    assert nat64.status({nat64.ENV_VAR: PREFIX}) == {"prefix": PREFIX, "error": None}
    assert nat64.status({nat64.ENV_VAR: "64:ff9b::/64"})["error"]


def test_tcp_port_check_connects_through_nat64(monkeypatch, nat64_env):
    seen = {}

    class FakeSock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_connect(addr, timeout):
        seen["addr"] = addr
        return FakeSock()

    monkeypatch.setattr(tools.socket, "create_connection", fake_connect)
    out = tools.tcp_port_check("192.0.2.33", 21)
    assert seen["addr"] == ("64:ff9b::c000:221", 21)
    assert out.startswith("192.0.2.33:21 via NAT64 64:ff9b::c000:221 open")


def test_tcp_port_check_hostname_untouched(monkeypatch, nat64_env):
    seen = {}

    def fake_connect(addr, timeout):
        seen["addr"] = addr
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(tools.socket, "create_connection", fake_connect)
    out = tools.tcp_port_check("example.com", 80)
    assert seen["addr"] == ("example.com", 80)
    assert "NAT64" not in out


def test_ping_and_mtr_use_nat64_address(monkeypatch, nat64_env):
    calls = []
    monkeypatch.setattr(tools.platform, "system", lambda: "Linux")
    monkeypatch.setattr(tools, "_run", lambda binary, args: calls.append((binary, args)) or "ok")
    assert tools.ping_host("192.0.2.33", 2).startswith("192.0.2.33 via NAT64 64:ff9b::c000:221\nok")
    assert tools.traceroute_path("192.0.2.33").startswith("192.0.2.33 via NAT64")
    assert calls[0][1][-1] == "64:ff9b::c000:221"
    assert calls[1][1][-1] == "64:ff9b::c000:221"


def test_ping_on_macos_picks_ping6_for_nat64_address(monkeypatch, nat64_env):
    calls = []
    monkeypatch.setattr(tools.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(tools, "_run", lambda binary, args: calls.append(binary) or "ok")
    tools.ping_host("192.0.2.33", 1)
    assert calls == ["ping6"]


def test_dig_resolver_goes_through_nat64(monkeypatch, nat64_env):
    calls = []
    monkeypatch.setattr(tools, "_run", lambda binary, args: calls.append(args) or "flags: qr rd ra ad; QUERY: 1")
    tools.dns_lookup("example.com", resolver="8.8.8.8")
    tools.dnssec_check("example.com")
    assert calls[0][0] == "@64:ff9b::808:808"
    assert calls[1][0] == "@64:ff9b::101:101"


def test_malformed_prefix_fails_the_tool(monkeypatch):
    monkeypatch.setenv(nat64.ENV_VAR, "64:ff9b::/64")
    with pytest.raises(ToolError, match="/96"):
        tools.tcp_port_check("192.0.2.33", 21)


def test_health_check_degraded_on_malformed_prefix(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda _: "/usr/bin/x")
    monkeypatch.setenv(nat64.ENV_VAR, "bogus")
    result = server.health_check()
    assert result["status"] == "degraded"
    assert result["nat64"]["error"]


def test_health_check_reports_prefix(monkeypatch, nat64_env):
    monkeypatch.setattr(server.shutil, "which", lambda _: "/usr/bin/x")
    result = server.health_check()
    assert result["status"] == "healthy"
    assert result["nat64"] == {"prefix": PREFIX, "error": None}


def test_backend_connects_ipv4_literal_through_nat64(monkeypatch):
    seen = []
    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", lambda self, host, port, **kw: seen.append((host, port)))
    backend = tools._Nat64Backend(ipaddress.IPv6Network(PREFIX))
    backend.connect_tcp("192.0.2.33", 8080, timeout=5)
    backend.connect_tcp("example.com", 443)
    backend.connect_tcp("2001:db8::1", 443)
    assert seen == [("64:ff9b::c000:221", 8080), ("example.com", 443), ("2001:db8::1", 443)]


def test_http_client_sets_backend_on_default_and_proxy_pools(monkeypatch):
    _clear_proxies(monkeypatch)
    monkeypatch.setenv(nat64.ENV_VAR, PREFIX)
    monkeypatch.setenv("HTTPS_PROXY", "proxy.example:3128")
    monkeypatch.setenv("NO_PROXY", "192.0.2.33")
    with tools._http_client() as client:
        pools = [t._pool for t in (client._transport, *client._mounts.values()) if t is not None]
        assert len(pools) >= 2
        assert all(isinstance(pool._network_backend, tools._Nat64Backend) for pool in pools)


def test_http_client_without_prefix_is_plain(monkeypatch):
    monkeypatch.delenv(nat64.ENV_VAR, raising=False)
    with tools._http_client() as client:
        assert not isinstance(client._transport._pool._network_backend, tools._Nat64Backend)


def test_http_client_fails_loudly_without_a_pool(monkeypatch):
    monkeypatch.setenv(nat64.ENV_VAR, PREFIX)
    real_client = httpx.Client
    monkeypatch.setattr(
        tools.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(lambda r: None), **kw)
    )
    with pytest.raises(ToolError, match="not supported"):
        tools._http_client()


def test_http_check_keeps_url_and_host_with_nat64(monkeypatch, nat64_env):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, request=request)

    real_client = httpx.Client
    monkeypatch.setattr(tools, "_http_client", lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    out = tools.http_check("http://192.0.2.33:8080/")
    assert "final_url=http://192.0.2.33:8080/" in out
    assert seen[0].headers["host"] == "192.0.2.33:8080"


@pytest.mark.parametrize("answer", ["64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1"])
def test_http_get_refuses_nat64_form_of_blocked_address(monkeypatch, answer):
    monkeypatch.delenv(nat64.ENV_VAR, raising=False)
    monkeypatch.setattr(
        tools.socket, "getaddrinfo", lambda host, port, *a, **k: [(socket.AF_INET6, None, None, None, (answer, port))]
    )
    with pytest.raises(ToolError, match="blocked address"):
        tools.http_get("https://evil.example/")


def test_http_get_refuses_configured_prefix_form(monkeypatch):
    monkeypatch.setenv(nat64.ENV_VAR, "2001:db8:64::/96")
    with pytest.raises(ToolError, match="blocked address"):
        tools.http_get("http://[2001:db8:64::a9fe:a9fe]/")


def test_http_get_refuses_ipv4_whose_nat64_form_is_blocked(monkeypatch):
    monkeypatch.setenv(nat64.ENV_VAR, "::/96")
    with pytest.raises(ToolError, match="blocked address"):
        tools.http_get("http://0.0.0.1/")


def test_http_get_refuses_blocked_address_inside_overlapping_prefix(monkeypatch):
    monkeypatch.setenv(nat64.ENV_VAR, "::/96")
    with pytest.raises(ToolError, match="blocked address"):
        tools.http_get("http://[::1]/")


def test_synthesize_keeps_ipv4_loopback():
    net = ipaddress.IPv6Network(PREFIX)
    assert nat64.synthesize("127.0.0.1", net) == "127.0.0.1"
    assert nat64.synthesize("127.8.9.10", net) == "127.8.9.10"


def test_backend_dials_loopback_proxy_directly(monkeypatch):
    seen = []
    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", lambda self, host, port, **kw: seen.append(host))
    tools._Nat64Backend(ipaddress.IPv6Network(PREFIX)).connect_tcp("127.0.0.1", 3128)
    assert seen == ["127.0.0.1"]


def test_embedded_ipv4s_local_use_reads_every_layout():
    carried = nat64.embedded_ipv4s(ipaddress.ip_address("64:ff9b:1:c000:2:2100::"), None)
    assert ipaddress.ip_address("192.0.2.33") in carried  # the /48 layout
    carried = nat64.embedded_ipv4s(ipaddress.ip_address("64:ff9b:1::a9fe:a9fe"), None)
    assert ipaddress.ip_address("169.254.169.254") in carried  # the /96 layout


def test_http_get_allows_valid_local_use_48_destination(monkeypatch):
    monkeypatch.delenv(nat64.ENV_VAR, raising=False)
    monkeypatch.setattr(
        tools.socket,
        "getaddrinfo",
        lambda host, port, *a, **k: [(socket.AF_INET6, None, None, None, ("64:ff9b:1:c000:2:2100::", port))],
    )
    assert tools._check_destination("https://ok.example/") == "https://ok.example/"


def test_http_get_refuses_local_use_form_of_metadata(monkeypatch):
    monkeypatch.delenv(nat64.ENV_VAR, raising=False)
    monkeypatch.setattr(
        tools.socket,
        "getaddrinfo",
        lambda host, port, *a, **k: [(socket.AF_INET6, None, None, None, ("64:ff9b:1::a9fe:a9fe", port))],
    )
    with pytest.raises(ToolError, match="blocked address"):
        tools.http_get("https://evil.example/")


def test_tls_verification_failure_names_nat64(monkeypatch, nat64_env):
    import ssl

    class FakeSock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(tools.socket, "create_connection", lambda addr, timeout: FakeSock())

    def fail_wrap(self, sock, server_hostname=None):
        raise ssl.SSLCertVerificationError("bad cert")

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", fail_wrap)
    out = tools.tls_cert_check("192.0.2.33")
    assert "via NAT64 64:ff9b::c000:221" in out


def test_dns_tools_name_the_nat64_resolver(monkeypatch, nat64_env):
    monkeypatch.setattr(tools, "_run", lambda binary, args: "flags: qr rd ra ad; QUERY: 1")
    assert tools.dns_lookup("example.com", resolver="8.8.8.8").startswith(
        "resolver 8.8.8.8 via NAT64 64:ff9b::808:808\n"
    )
    out = tools.dnssec_check("example.com")
    assert out.splitlines()[0] == "DNSSEC validated (AD bit set)"
    assert out.splitlines()[1] == "resolver 1.1.1.1 via NAT64 64:ff9b::101:101"


def test_backend_records_translations(monkeypatch):
    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", lambda self, host, port, **kw: None)
    backend = tools._Nat64Backend(ipaddress.IPv6Network(PREFIX))
    backend.connect_tcp("192.0.2.33", 80)
    backend.connect_tcp("example.com", 443)
    assert backend.translated == {"192.0.2.33": "64:ff9b::c000:221"}


def test_http_check_reports_nat64_line(monkeypatch, nat64_env):
    real_client = httpx.Client

    def fake_http_client(**kw):
        client = real_client(transport=httpx.MockTransport(lambda r: httpx.Response(200, request=r)), **kw)
        client.nat64_translated = {"192.0.2.33": "64:ff9b::c000:221"}
        return client

    monkeypatch.setattr(tools, "_http_client", fake_http_client)
    out = tools.http_check("http://192.0.2.33:8080/")
    assert out.splitlines()[-1] == "via NAT64: 192.0.2.33 -> 64:ff9b::c000:221"


def test_http_get_puts_nat64_line_after_status(monkeypatch, nat64_env):
    real_client = httpx.Client

    def fake_http_client(**kw):
        handler = lambda r: httpx.Response(200, headers={"content-type": "text/plain"}, content=b"ok", request=r)  # noqa: E731
        client = real_client(transport=httpx.MockTransport(handler), **kw)
        client.nat64_translated = {"192.0.2.33": "64:ff9b::c000:221"}
        return client

    monkeypatch.setattr(tools, "_http_client", fake_http_client)
    head = tools.http_get("http://192.0.2.33/").split("\n\n", 1)[0].splitlines()
    assert head[0].endswith("bytes=2")
    assert head[1] == "via NAT64: 192.0.2.33 -> 64:ff9b::c000:221"


def test_embedded_ipv4s_checks_local_use_layouts_inside_configured_prefix():
    custom = ipaddress.IPv6Network("64:ff9b:1:a9fe:a9:fe00::/96")
    carried = nat64.embedded_ipv4s(ipaddress.ip_address("64:ff9b:1:a9fe:a9:fe00:c000:201"), custom)
    assert ipaddress.ip_address("192.0.2.1") in carried  # the configured /96 layout
    assert ipaddress.ip_address("169.254.169.254") in carried  # the /48 layout

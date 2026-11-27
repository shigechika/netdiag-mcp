"""Optional NAT64 prefix for hosts that only have IPv6.

On an IPv6-only host an IPv4 literal cannot be reached directly: the socket
fails with "Network is unreachable" before anything leaves the box. Names work
already, because the network's DNS64 answers with addresses under its NAT64
prefix. ``NETDIAG_NAT64_PREFIX`` gives that prefix to netdiag-mcp, e.g.::

    NETDIAG_NAT64_PREFIX=64:ff9b::/96

With it set, every tool that connects to a target (ping, traceroute, TCP and
TLS checks, HTTP, and dig's resolver) sends an IPv4 literal to the address
synthesized from it (RFC 6052, /96 only). The output still names the IPv4
target and says which address was used. Unset means IPv4 literals are used as
given, as before.

Addresses inside the configured prefix and the well-known prefix 64:ff9b::/96
carry an IPv4 address, so the http_get blocklist checks that embedded address
too: a name whose DNS64 answer points at a NAT64 form of 169.254.169.254 (or of
0.0.0.0) is refused like the IPv4 address itself. Any other prefix, the RFC 8215
local-use 64:ff9b:1::/48 included, is covered only when it is the configured
one, because its layout depends on the network. IPv4 loopback is never
translated.

The variable is read from the process environment only, like NETDIAG_HTTP_AUTH.
"""

from __future__ import annotations

import functools
import ipaddress
import os

ENV_VAR = "NETDIAG_NAT64_PREFIX"
WELL_KNOWN_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")
# IPv4 loopback stays on the host (a local proxy, for instance) and is never
# sent through NAT64.
_LOOPBACK = ipaddress.IPv4Network("127.0.0.0/8")


class Nat64ConfigError(ValueError):
    """NETDIAG_NAT64_PREFIX is set but is not an IPv6 /96 network."""


@functools.lru_cache(maxsize=8)
def _parse(raw: str) -> ipaddress.IPv6Network:
    try:
        net = ipaddress.IPv6Network(raw, strict=True)
    except ValueError as e:
        raise Nat64ConfigError(f"{ENV_VAR} must be an IPv6 network such as 64:ff9b::/96: {e}") from None
    if net.prefixlen != 96:
        raise Nat64ConfigError(f"{ENV_VAR} must be a /96 prefix (got /{net.prefixlen})")
    if (int(net.network_address) >> 56) & 0xFF:
        raise Nat64ConfigError(f"{ENV_VAR} must have bits 64-71 set to zero (RFC 6052)")
    return net


def load_prefix(environ: dict[str, str] | None = None) -> ipaddress.IPv6Network | None:
    """Parse NETDIAG_NAT64_PREFIX. Unset or empty means None; anything malformed raises."""
    raw = (environ if environ is not None else os.environ).get(ENV_VAR, "").strip()
    if not raw:
        return None
    return _parse(raw)


def synthesize(target: str, prefix: ipaddress.IPv6Network | None) -> str:
    """The NAT64 address for an IPv4 literal; any other target (and IPv4 loopback) is returned unchanged."""
    if prefix is None:
        return target
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        return target
    if addr.version != 4 or addr in _LOOPBACK:
        return target
    return str(ipaddress.IPv6Address(int(prefix.network_address) | int(addr)))


def embedded_ipv4(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address, prefix: ipaddress.IPv6Network | None
) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 address under the well-known or the configured /96 prefix stands for.

    Other prefixes (the local-use 64:ff9b:1::/48 or any network-specific one)
    are not read unless configured: their layout depends on the network, and
    reading them with the wrong one gives a different IPv4 address.
    """
    if addr.version != 6:
        return None
    if addr in WELL_KNOWN_PREFIX or (prefix is not None and addr in prefix):
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return None


def status(environ: dict[str, str] | None = None) -> dict:
    """{"prefix": str | None, "error": str | None} for health_check."""
    try:
        prefix = load_prefix(environ)
    except Nat64ConfigError as e:
        return {"prefix": None, "error": str(e)}
    return {"prefix": str(prefix) if prefix else None, "error": None}

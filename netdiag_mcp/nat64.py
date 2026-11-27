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

Addresses inside the configured prefix, the well-known prefix 64:ff9b::/96 and
the local-use prefix 64:ff9b:1::/48 (read with every RFC 6052 layout that fits
in it) carry an IPv4 address, so the http_get blocklist checks that embedded address too: a name
whose DNS64 answer points at a NAT64 form of 169.254.169.254 is refused like
the IPv4 address itself. A DNS64 that uses another network-specific prefix is
covered only when that prefix is set. IPv4 loopback is never translated.

The variable is read from the process environment only, like NETDIAG_HTTP_AUTH.
"""

from __future__ import annotations

import functools
import ipaddress
import os

ENV_VAR = "NETDIAG_NAT64_PREFIX"
WELL_KNOWN_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")
# RFC 8215 local-use prefix; a network may use it with any RFC 6052 length.
LOCAL_USE_PREFIX = ipaddress.IPv6Network("64:ff9b:1::/48")
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


# RFC 6052 address layouts by prefix length: (bit offset, bit count) pieces of
# the IPv4 address, skipping the u-octet (bits 64-71).
_LAYOUTS = {
    48: ((48, 16), (72, 16)),
    56: ((56, 8), (72, 24)),
    64: ((72, 32),),
    96: ((96, 32),),
}


def _decode(value: int, length: int) -> ipaddress.IPv4Address:
    v4 = 0
    for offset, bits in _LAYOUTS[length]:
        v4 = (v4 << bits) | ((value >> (128 - offset - bits)) & ((1 << bits) - 1))
    return ipaddress.IPv4Address(v4)


def embedded_ipv4s(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address, prefix: ipaddress.IPv6Network | None
) -> list[ipaddress.IPv4Address]:
    """The IPv4 addresses an IPv6 address under a NAT64 prefix may stand for.

    The well-known and the configured prefix are /96, so there is one. The
    local-use prefix 64:ff9b:1::/48 may be split into any RFC 6052 length, so
    every layout that fits inside it is returned; a caller looking for a
    blocked address checks them all.
    """
    if addr.version != 6:
        return []
    value = int(addr)
    lengths = []
    if addr in WELL_KNOWN_PREFIX or (prefix is not None and addr in prefix):
        lengths.append(96)
    if addr in LOCAL_USE_PREFIX:
        # Also when the configured prefix lies inside it: the other layouts
        # may still be what a DNS64 elsewhere in the network uses.
        lengths += [length for length in _LAYOUTS if length not in lengths]
    return [_decode(value, length) for length in lengths]


def status(environ: dict[str, str] | None = None) -> dict:
    """{"prefix": str | None, "error": str | None} for health_check."""
    try:
        prefix = load_prefix(environ)
    except Nat64ConfigError as e:
        return {"prefix": None, "error": str(e)}
    return {"prefix": str(prefix) if prefix else None, "error": None}

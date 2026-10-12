"""Optional Authorization header for http_get, scoped by URL prefix.

``NETDIAG_HTTP_AUTH`` holds a JSON object that maps an https URL prefix to the
value of the Authorization header sent to URLs under it, e.g.::

    NETDIAG_HTTP_AUTH='{"https://reports.example.ac.jp/daily/": "Bearer <token>"}'

The header is chosen per request, after every redirect hop, by comparing the
parsed URL (scheme, host, port, path) with each prefix -- never by raw string
prefix, so ``https://reports.example.ac.jp.evil.example/`` or
``https://reports.example.ac.jp@evil.example/`` cannot pick it up. Only https
URLs ever carry it. Header values are never returned, logged or put into an
error message; prefixes are not secret and are reported by health_check.

The variable is read from the process environment only (no config file): on a
host that runs several instances as the same user, a file would be shared by
all of them, while each instance's environment is its own.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from dataclasses import dataclass

ENV_VAR = "NETDIAG_HTTP_AUTH"


class HttpAuthConfigError(ValueError):
    """NETDIAG_HTTP_AUTH is set but malformed. The message never contains a header value."""


@dataclass(frozen=True)
class Rule:
    prefix: str
    host: str
    port: int
    path: str
    value: str


def _has_dot_segment(path: str) -> bool:
    decoded = urllib.parse.unquote(path)
    return any(seg in (".", "..") for seg in decoded.replace("\\", "/").split("/"))


def _parse_prefix(prefix: str) -> tuple[str, int, str]:
    try:
        parts = urllib.parse.urlsplit(prefix)
        hostname = parts.hostname
    except ValueError as e:  # e.g. malformed IPv6 brackets
        raise HttpAuthConfigError(f"{ENV_VAR}: prefix {prefix!r} is not a valid URL") from e
    if parts.scheme != "https":
        raise HttpAuthConfigError(f"{ENV_VAR}: prefix {prefix!r} must start with https://")
    if parts.username is not None or parts.password is not None:
        raise HttpAuthConfigError(f"{ENV_VAR}: prefix {prefix!r} must not contain user info")
    if parts.query or parts.fragment:
        raise HttpAuthConfigError(f"{ENV_VAR}: prefix {prefix!r} must not contain a query or fragment")
    if not hostname:
        raise HttpAuthConfigError(f"{ENV_VAR}: prefix {prefix!r} has no host")
    try:
        port = parts.port or 443
    except ValueError as e:
        raise HttpAuthConfigError(f"{ENV_VAR}: prefix {prefix!r} has an invalid port") from e
    path = parts.path or "/"
    if not path.endswith("/"):
        raise HttpAuthConfigError(f"{ENV_VAR}: prefix {prefix!r} must end with /")
    if _has_dot_segment(path):
        raise HttpAuthConfigError(f"{ENV_VAR}: prefix {prefix!r} must not contain . or .. segments")
    return hostname.lower().rstrip("."), port, path


def load_rules(environ: dict[str, str] | None = None) -> list[Rule]:
    """Parse NETDIAG_HTTP_AUTH. Unset or empty means no rules; anything malformed raises."""
    raw = (environ if environ is not None else os.environ).get(ENV_VAR, "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        # e.msg and the position only; the document itself holds the secrets.
        raise HttpAuthConfigError(f"{ENV_VAR}: not valid JSON ({e.msg} at position {e.pos})") from None
    if not isinstance(data, dict):
        raise HttpAuthConfigError(f"{ENV_VAR}: must be a JSON object mapping URL prefix to header value")
    rules = []
    for prefix, value in data.items():
        if not isinstance(value, str) or not value.strip():
            raise HttpAuthConfigError(f"{ENV_VAR}: value for {prefix!r} must be a non-empty string")
        if any(c in value for c in "\r\n\0"):
            raise HttpAuthConfigError(f"{ENV_VAR}: value for {prefix!r} contains a control character")
        host, port, path = _parse_prefix(prefix)
        rules.append(Rule(prefix=prefix, host=host, port=port, path=path, value=value.strip()))
    # The most specific prefix wins when several match.
    rules.sort(key=lambda r: len(r.path), reverse=True)
    return rules


def header_for(url: str, rules: list[Rule]) -> dict[str, str]:
    """The Authorization header for url, or {} when no rule matches it."""
    if not rules:
        return {}
    try:
        parts = urllib.parse.urlsplit(url)
        hostname = parts.hostname
    except ValueError:
        return {}
    if parts.scheme != "https" or not hostname:
        return {}
    if parts.username is not None or parts.password is not None:
        return {}
    try:
        port = parts.port or 443
    except ValueError:
        return {}
    host = hostname.lower().rstrip(".")
    path = parts.path or "/"
    if _has_dot_segment(path):
        return {}
    for rule in rules:
        if rule.host == host and rule.port == port and path.startswith(rule.path):
            return {"Authorization": rule.value}
    return {}


def status(environ: dict[str, str] | None = None) -> dict:
    """{"prefixes": [...], "error": str | None} for health_check. Never includes a header value."""
    try:
        rules = load_rules(environ)
    except HttpAuthConfigError as e:
        return {"prefixes": [], "error": str(e)}
    return {"prefixes": sorted(r.prefix for r in rules), "error": None}

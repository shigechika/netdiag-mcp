"""Input validation shared by every tool.

Tool arguments are LLM-driven and must be treated as adversarial: nothing
here ever builds a shell string (subprocess calls always pass argv lists),
but sizes/counts/hostnames are still bounds-checked so a single tool call
cannot become an amplification vector (e.g. an unbounded ping count) or a
malformed argv0 for the wrapped binary.
"""

import ipaddress
import re

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


def validate_target(value: str) -> str:
    """Return value unchanged if it is a plausible hostname or IP literal.

    Raises ValueError otherwise. Deliberately permissive about *what* the
    name resolves to (that is the point of the tool) — this only rejects
    input that could not be a real target at all (empty, whitespace,
    shell metacharacters, embedded newlines).
    """
    target = value.strip()
    if not target or len(target) > 253:
        raise ValueError("target must be a non-empty hostname or IP address")
    if any(c.isspace() for c in target):
        raise ValueError("target must not contain whitespace")
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(target):
        raise ValueError(f"not a valid hostname or IP address: {value!r}")
    return target


def validate_port(value: int) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return port


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, int(value)))

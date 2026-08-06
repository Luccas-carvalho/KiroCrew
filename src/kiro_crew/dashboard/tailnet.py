"""Read-only interface to the local Tailscale daemon.

Answers one question for now: *what MagicDNS name does this machine have on its
tailnet?* — so the dashboard can accept its own tailnet origin without the
operator hand-writing ``dashboard.url``. RFC:
``docs/request-for-change/rfc-tailnet-dashboard-access.md`` §4.

Two properties are load-bearing and neither is optional:

**Nothing here raises.** A missing binary, a stopped daemon, a timeout, a
non-zero exit, malformed JSON, an unexpected schema — every one returns ``None``.
The dashboard must start on a host that has never heard of Tailscale, so this
module is a pure enrichment: it either contributes a name or contributes nothing.

**The name is validated before it is returned.** It arrives from a subprocess and
its destination is the CSRF origin allowlist and the DNS-rebinding ``Host``
barrier, so an unvalidated value would be an origin-injection primitive. See
:func:`_valid_magicdns_name`: structure is checked as a strict allowlist, and the
name must additionally sit under the tailnet's own MagicDNS suffix *as the daemon
reports it* — not a suffix hardcoded here, because upstream documents the suffix
as tailnet-specific (its own example is ``userfoo.tailscale.net``, not
``ts.net``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

#: Hard ceiling on a daemon call. Startup path, so this is latency the user
#: waits through — it must be short, and it must be a real timeout rather than a
#: hope, because `tailscale status` blocks while the daemon is starting up.
_CLI_TIMEOUT_SECS = 3.0

#: Where the CLI lives when it is not on ``PATH``. The macOS app ships the binary
#: inside the bundle and does not always symlink it; the Linux packages do put it
#: on ``PATH``, so this list is a fallback, not the primary lookup.
_CLI_FALLBACK_PATHS = (
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "/usr/local/bin/tailscale",
    "/opt/homebrew/bin/tailscale",
)

#: MagicDNS names are DNS labels joined by dots, all lowercase. Deliberately
#: strict: no scheme, no port, no path, no userinfo, no whitespace, no trailing
#: dot (stripped before the match), no uppercase.
_DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_MAGICDNS_RE = re.compile(rf"^{_DNS_LABEL}(?:\.{_DNS_LABEL})+$")


def _cli_path() -> str | None:
    """Locate the ``tailscale`` CLI, or ``None`` if it is not installed."""
    found = shutil.which("tailscale")
    if found:
        return found
    for candidate in _CLI_FALLBACK_PATHS:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _run_json(args: list[str]) -> Any | None:
    """Run the CLI and parse stdout as JSON. ``None`` on ANY failure.

    Deliberately broad: the caller's contract is "a name or nothing", and every
    failure mode here (no binary, daemon down, timeout, non-zero exit, non-JSON
    output) means the same thing to it. Failures are logged at debug so a host
    without Tailscale does not emit noise on every start.
    """
    cli = _cli_path()
    if not cli:
        logger.debug("tailscale CLI not found; skipping tailnet origin derivation")
        return None
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user input
            [cli, *args],
            capture_output=True,
            text=True,
            timeout=_CLI_TIMEOUT_SECS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("tailscale %s failed to run: %s", " ".join(args), exc)
        return None
    if proc.returncode != 0:
        logger.debug(
            "tailscale %s exited %d: %s",
            " ".join(args),
            proc.returncode,
            (proc.stderr or "").strip()[:200],
        )
        return None
    try:
        return json.loads(proc.stdout or "")
    except (json.JSONDecodeError, ValueError) as exc:
        logger.debug("tailscale %s produced non-JSON output: %s", " ".join(args), exc)
        return None


def _valid_magicdns_name(raw: object, magic_dns_suffix: object) -> str | None:
    """Return *raw* as a trusted MagicDNS name, or ``None`` if it is not one.

    Two independent checks, and they defend different things.

    **Structure** is the injection defense. An allowlist, not a denylist: the
    destination is the CSRF origin set and the ``Host`` barrier, so the question
    is not "does this look dangerous" but "is this provably a bare hostname".
    Rejected — a non-string, empty, over 253 bytes, or anything carrying a
    scheme / port / path / credentials / whitespace / uppercase.

    **Suffix self-consistency** is the "is this actually ours" check. The name
    must sit under the tailnet's own MagicDNS suffix *as reported by the same
    status output* (``CurrentTailnet.MagicDNSSuffix``). Checking against the
    daemon's own answer rather than a hardcoded suffix matters: upstream
    documents the suffix as tailnet-specific and its own example is
    ``userfoo.tailscale.net``, not ``ts.net``, so a hardcoded list would reject
    legitimate tailnets and would rot as Tailscale adds suffixes. It also means a
    self-hosted control plane works without a special case. ``CurrentTailnet`` is
    nil when the node is not connected, which lands here as a missing suffix and
    is refused — no tailnet means no origin to add.
    """
    if not isinstance(raw, str) or not isinstance(magic_dns_suffix, str):
        return None
    name = raw.strip().rstrip(".")
    # Upstream documents MagicDNSSuffix as carrying "no surrounding dots", but
    # normalise rather than trust the shape of a value we did not build.
    suffix = magic_dns_suffix.strip().strip(".").lower()
    if not name or not suffix or len(name) > 253:
        return None
    # Cheap structural rejections before the regex, so the reason is obvious in
    # a debug log rather than a bare "did not match".
    if any(ch in name for ch in "/:@?# \t\r\n\\"):
        return None
    if name != name.lower():
        return None
    # Must be a host UNDER the suffix, not the suffix itself and not a name that
    # merely contains it (`desk.tail.ts.net.evil.com` must not pass).
    if not name.endswith(f".{suffix}"):
        return None
    if not _MAGICDNS_RE.match(name):
        return None
    return name


def self_dns_name() -> str | None:
    """This machine's MagicDNS name on its tailnet, or ``None``.

    ``None`` covers every "not applicable" case as well as every failure:
    Tailscale absent, daemon not running, machine not logged in (``CurrentTailnet``
    is nil), MagicDNS disabled for the tailnet, or a name that does not validate
    against the tailnet's own suffix.
    """
    status = _run_json(["status", "--json"])
    if not isinstance(status, dict):
        return None
    self_node = status.get("Self")
    if not isinstance(self_node, dict):
        return None
    # CurrentTailnet is nil when the node is not connected to a tailnet. The
    # legacy top-level MagicDNSSuffix is upstream-deprecated, so it is only a
    # fallback for an older daemon, never the primary read.
    tailnet = status.get("CurrentTailnet")
    suffix: object = None
    if isinstance(tailnet, dict):
        suffix = tailnet.get("MagicDNSSuffix")
    if not isinstance(suffix, str) or not suffix.strip():
        suffix = status.get("MagicDNSSuffix")
    name = _valid_magicdns_name(self_node.get("DNSName"), suffix)
    if name is None:
        logger.debug("tailscale status returned no usable Self.DNSName for this tailnet")
    return name


def tailnet_origin() -> str | None:
    """The HTTPS origin to trust for this machine's tailnet name, or ``None``.

    No port: ``tailscale serve`` fronts the dashboard on 443, so the browser's
    ``Origin`` carries no port component.
    """
    name = self_dns_name()
    return f"https://{name}" if name else None


async def resolve_tailnet_host(enabled: bool) -> str:
    """Async entry point for the startup path: the name, or ``""``.

    Exists so the **blocking subprocess never runs on the event loop**.
    :func:`self_dns_name` shells out with a multi-second timeout, and
    ``tailscale status`` genuinely blocks while the daemon is coming up; running
    that inline would stall every other session and can trip the loop-stall
    watchdog. Offloaded to a thread, and short-circuited before the thread hop
    when the feature is off so a host without Tailscale pays nothing.

    Takes *enabled* as an argument rather than reading config, to keep this
    module free of a config import (and the import cycle that would invite).
    """
    if not enabled:
        return ""
    name: str | None = await asyncio.to_thread(self_dns_name)
    return name or ""

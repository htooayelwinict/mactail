"""Code signature inspection via `codesign`.

Wraps `codesign -dv --verbose=4 <path>` and parses the human-readable output
into a structured `SignatureInfo`. Apple does not publish a stable machine-
readable output, so this is a best-effort parser over the verbose format.

ponytail: v0.2 — single `codesign` invocation, no `spctl` / `stapler` / `notarytool`.
Hardened runtime flag is parsed because it's free in the same output.
Upgrade path: when notarization lookup becomes a real need, add a separate
`is_notarized()` helper that calls `stapler validate` once and caches.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# Sample `codesign -dv --verbose=4` output for reference:
#
# Executable=/usr/bin/true
# Identifier=com.apple.true
# Format=app bundle with Mach-O universal (x86_64)
# CodeDirectory v=20400 size=489 flags=0x10000(runtime) hashes=3+3 location=embedded
# Signature size=4441
# Authority=Software Signing
# Authority=Apple Code Signing Certification Authority
# Authority=Apple Root CA
# Signed Time=Jan 1, 2024 at 00:00:00
# Info.plist=...
# TeamIdentifier=APPLECOMPUTER
# Runtime Version=...
# Sealed Resources version=2 rules=13 files=1
# Internal requirements count=1 size=72
# ...

_AUTH_APPLE_SIGNING = "Software Signing"
_TEAM_ID_RE = re.compile(r"^TeamIdentifier=(.+)$", re.MULTILINE)
_AUTHORITY_RE = re.compile(r"^Authority=(.+)$", re.MULTILINE)
_FLAGS_RE = re.compile(r"^CodeDirectory.*flags=0x([0-9a-f]+)", re.MULTILINE)
_IDENTIFIER_RE = re.compile(r"^Identifier=(.+)$", re.MULTILINE)

# flags bit 0x10000 = runtime hardening
_RUNTIME_HARDENED = 0x10000


@dataclass(frozen=True)
class SignatureInfo:
    """Result of one `codesign` check."""

    path: Path
    is_signed: bool
    team_id: str | None
    signing_id: str | None  # the Identifier= line
    is_apple_signed: bool
    is_hardened_runtime: bool
    error: str | None = None  # non-None if codesign failed or binary missing


def inspect(path: Path) -> SignatureInfo:
    """Run `codesign -dv --verbose=4` against `path` and parse the output.

    Never raises. A missing or unsigned binary returns `is_signed=False` with
    a populated `error` field. A subprocess failure returns `is_signed=False`
    and `error=<reason>`. This is a trust boundary.
    """
    if not path.exists():
        return SignatureInfo(
            path=path,
            is_signed=False,
            team_id=None,
            signing_id=None,
            is_apple_signed=False,
            is_hardened_runtime=False,
            error="file not found",
        )

    try:
        proc = subprocess.run(
            ["codesign", "-dv", "--verbose=4", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return SignatureInfo(
            path=path,
            is_signed=False,
            team_id=None,
            signing_id=None,
            is_apple_signed=False,
            is_hardened_runtime=False,
            error="codesign timed out",
        )
    except FileNotFoundError:
        # `codesign` itself missing (non-macOS test box). Treat as unknown.
        return SignatureInfo(
            path=path,
            is_signed=False,
            team_id=None,
            signing_id=None,
            is_apple_signed=False,
            is_hardened_runtime=False,
            error="codesign binary not found",
        )

    # codesign exit codes:
    #   0  = signed and valid
    #   1  = invalid signature
    #   2  = not signed
    # We treat any non-zero as "not signed" but still parse output if any.
    if proc.returncode not in (0, 1, 2):
        return SignatureInfo(
            path=path,
            is_signed=False,
            team_id=None,
            signing_id=None,
            is_apple_signed=False,
            is_hardened_runtime=False,
            error=f"codesign exited {proc.returncode}: {proc.stderr.strip()[:200]}",
        )

    out = proc.stdout
    team = _match(_TEAM_ID_RE, out)
    auths = _AUTHORITY_RE.findall(out)
    flags_hex = _match(_FLAGS_RE, out)
    identifier = _match(_IDENTIFIER_RE, out)

    flags = int(flags_hex, 16) if flags_hex else 0
    is_signed = proc.returncode == 0 and team is not None
    is_apple = _AUTH_APPLE_SIGNING in auths

    return SignatureInfo(
        path=path,
        is_signed=is_signed,
        team_id=team.strip() if team else None,
        signing_id=identifier.strip() if identifier else None,
        is_apple_signed=is_apple,
        is_hardened_runtime=bool(flags & _RUNTIME_HARDENED),
        error=None if is_signed else (f"codesign rc={proc.returncode}"),
    )


def _match(pattern: re.Pattern[str], text: str) -> str | None:
    m = pattern.search(text)
    return m.group(1) if m else None


# Cached lookup. On a diff with 200 plists pointing at 30 distinct binaries,
# this avoids 170 redundant subprocess calls. Cache is process-local; size
# is bounded by the number of unique binaries in a single diff run.
@lru_cache(maxsize=1024)
def _inspect_cached(path_str: str) -> SignatureInfo:
    return inspect(Path(path_str))


def inspect_cached(path: Path) -> SignatureInfo:
    """Cached version of `inspect()`. Safe to call from rules repeatedly."""
    return _inspect_cached(str(path.resolve()))


def clear_cache() -> None:
    """Drop the cache. Useful for tests; not used in normal flow."""
    _inspect_cached.cache_clear()

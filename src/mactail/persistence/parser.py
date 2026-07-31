"""Parse a launchd plist into a structured PlistSnapshot.

Pure stdlib + pydantic. Never raises on bad input — returns a typed ParseError
so the store/diff layer can decide what to do (skip, warn, hard-fail).

ponytail: v0.1 — extracts a fixed field set; raw_keys captures anything else
so diff can show "field X added" without us enumerating every launchd key.
Upgrade path: when a hunt needs a specific field, add a typed accessor; if
the field set grows past ~20, switch to a sub-model and split parser.
"""

from __future__ import annotations

import hashlib
import plistlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from mactail.persistence.scanner import PlistKind, PlistLocation

_PLIST_BINARY_MAGIC = b"bplist"


class Severity(StrEnum):
    """Finding severity, ordered low < medium < high < critical."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ParseError:
    """A plist that could not be read or parsed.

    Returned alongside PlistSnapshot; never raised. The store layer decides
    whether to record errors in the DB.
    """

    path: Path
    reason: str
    hint: str = ""


class PlistSnapshot(BaseModel):
    """A single parsed plist, normalized for storage and diffing."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: Path
    kind: PlistKind
    content_hash: str  # sha256 hex of canonical bytes
    mtime_ns: int
    size: int

    # Typed accessors for the fields rules care about. Missing -> None.
    label: str | None = None
    program: str | None = None  # first element of ProgramArguments, or Program
    program_args: tuple[str, ...] = ()
    run_at_load: bool = False
    keep_alive: bool = False
    disabled: bool = False
    user_name: str | None = None
    sockets: tuple[tuple[str, str], ...] = ()  # (name, kind)
    environment: tuple[tuple[str, str], ...] = ()
    mach_services: tuple[str, ...] = ()

    # Catch-all so diff can show "field X added/removed" without us modeling
    # every launchd key. Sorted tuple of (key, repr(value)) for stability.
    raw_keys: tuple[str, ...] = Field(default_factory=tuple)
    raw_extras: tuple[tuple[str, str], ...] = Field(default_factory=tuple)


def parse(location: PlistLocation) -> PlistSnapshot | ParseError:
    """Read, canonicalize, and extract fields from one plist location."""
    path = location.path
    try:
        data = plistlib.loads(path.read_bytes())
    except FileNotFoundError:
        return ParseError(path, "file not found", "moved or deleted between scan and parse")
    except PermissionError:
        return ParseError(path, "permission denied", "needs Full Disk Access or sudo")
    except plistlib.InvalidFileException as e:
        return ParseError(path, f"invalid plist: {e}", "not a well-formed plist")
    except Exception as e:
        return ParseError(path, f"unexpected: {type(e).__name__}: {e}", "see --debug")

    if not isinstance(data, Mapping):
        return ParseError(path, "top-level is not a dict", "launchd plists must be <dict>")

    stat = path.stat()
    canonical = _canonical_bytes(data)
    content_hash = hashlib.sha256(canonical).hexdigest()

    return PlistSnapshot(
        path=path,
        kind=location.kind,
        content_hash=content_hash,
        mtime_ns=stat.st_mtime_ns,
        size=stat.st_size,
        label=_str_or_none(data.get("Label")),
        program_args=_as_str_tuple(data.get("ProgramArguments")),
        program=(
            _str_or_none(data.get("Program"))
            or _first(_as_str_tuple(data.get("ProgramArguments")))
        ),
        run_at_load=bool(data.get("RunAtLoad", False)),
        keep_alive=bool(_truthy(data.get("KeepAlive"))),
        disabled=bool(data.get("Disabled", False)),
        user_name=_str_or_none(data.get("UserName")),
        sockets=_sockets(data.get("Sockets")),
        environment=_env(data.get("EnvironmentVariables")),
        mach_services=tuple(sorted(str(k) for k in (data.get("MachServices") or {}))),
        raw_keys=tuple(sorted(str(k) for k in data)),
        raw_extras=_raw_extras(data),
    )


def _canonical_bytes(data: Mapping[str, object]) -> bytes:
    """Return a stable byte representation of `data`.

    Uses plistlib with sort_keys=True so dict order doesn't affect the hash.
    Preserves the input format (binary or XML) when possible.
    """
    return plistlib.dumps(dict(data), sort_keys=True)


def _str_or_none(v: object) -> str | None:
    return v if isinstance(v, str) else None


def _as_str_tuple(v: object) -> tuple[str, ...]:
    if not isinstance(v, list):
        return ()
    return tuple(x for x in v if isinstance(x, str))


def _first(xs: tuple[str, ...]) -> str | None:
    return xs[0] if xs else None


def _truthy(v: object) -> bool:
    """KeepAlive accepts bool or dict; treat non-empty dict as truthy."""
    if isinstance(v, bool):
        return v
    if isinstance(v, Mapping):
        return bool(v)
    return False


def _sockets(v: object) -> tuple[tuple[str, str], ...]:
    """Sockets is a dict of name -> {SockType: ..., SockPath: ...}.

    Returned as sorted (name, kind) pairs where kind is the SockType name
    ('unix', 'tcp', ...) or 'unknown'.
    """
    if not isinstance(v, Mapping):
        return ()
    out: list[tuple[str, str]] = []
    for name, cfg in v.items():
        kind = "unknown"
        if isinstance(cfg, Mapping):
            t = cfg.get("SockType")
            if isinstance(t, str):
                kind = t
        out.append((str(name), kind))
    return tuple(sorted(out))


def _env(v: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(v, Mapping):
        return ()
    return tuple(sorted((str(k), str(val)) for k, val in v.items()))


def _raw_extras(data: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    """Stable repr of every top-level value, for diff evidence.

    Excludes keys we already model typed accessors for, so the extras stay
    focused on the long tail.
    """
    modeled = {
        "Label",
        "Program",
        "ProgramArguments",
        "RunAtLoad",
        "KeepAlive",
        "Disabled",
        "UserName",
        "Sockets",
        "EnvironmentVariables",
        "MachServices",
    }
    out: list[tuple[str, str]] = []
    for k in sorted(data.keys()):
        if k in modeled:
            continue
        out.append((str(k), repr(data[k])))
    return tuple(out)

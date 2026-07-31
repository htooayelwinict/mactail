"""Enumerate launchd plist paths on the local filesystem.

Pure stdlib. Walks known LaunchAgent / LaunchDaemon locations and yields
canonical paths + a `kind` tag. Does NOT read plist contents (parser does that).

ponytail: v0.1 — fixed root set, no symlink-loop detection beyond realpath.
Upgrade path: when a user reports a miss, add a new root to _agent_roots();
when loops hurt, switch to os.walk with a visited set keyed by (dev, inode).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class PlistKind(StrEnum):
    """Origin of a launchd plist file."""

    USER_AGENT = "user_agent"  # ~/Library/LaunchAgents
    SYSTEM_AGENT = "system_agent"  # /Library/LaunchAgents
    SYSTEM_DAEMON = "system_daemon"  # /Library/LaunchDaemons
    APPLE_AGENT = "apple_agent"  # /System/Library/LaunchAgents (opt-in)
    APPLE_DAEMON = "apple_daemon"  # /System/Library/LaunchDaemons (opt-in)


@dataclass(frozen=True)
class PlistLocation:
    """One discovered plist file (not yet read)."""

    path: Path  # realpath, absolute
    kind: PlistKind


def _user_agent_root() -> Path:
    """Return the per-user LaunchAgents root.

    Resolved at call-time so tests can monkeypatch this function (or Path.home)
    without rebinding module-level tuples.
    """
    return Path.home() / "Library" / "LaunchAgents"


def _agent_roots() -> tuple[tuple[Path, PlistKind], ...]:
    """Third-party / user roots. Resolved fresh on every scan() call."""
    return (
        (_user_agent_root(), PlistKind.USER_AGENT),
        (Path("/Library/LaunchAgents"), PlistKind.SYSTEM_AGENT),
        (Path("/Library/LaunchDaemons"), PlistKind.SYSTEM_DAEMON),
    )


_APPLE_ROOTS: tuple[tuple[Path, PlistKind], ...] = (
    (Path("/System/Library/LaunchAgents"), PlistKind.APPLE_AGENT),
    (Path("/System/Library/LaunchDaemons"), PlistKind.APPLE_DAEMON),
)


def scan(*, include_system: bool = False) -> Iterator[PlistLocation]:
    """Yield every plist under the known launchd roots.

    Args:
        include_system: If True, also walk /System/Library/Launch* (Apple-shipped,
            read-only reference). Default False — only third-party / user roots.

    Yields:
        PlistLocation with realpath-resolved absolute path + kind tag.

    Notes:
        - Silent on missing roots (e.g. user has no ~/Library/LaunchAgents).
        - Skips files whose name starts with a dot inside the root.
        - Only yields regular files; symlinks to dirs are not followed.
        - Dedupes by realpath so a symlink in two roots yields one location.
    """
    roots: list[tuple[Path, PlistKind]] = list(_agent_roots())
    if include_system:
        roots.extend(_APPLE_ROOTS)

    seen: set[Path] = set()
    for root, kind in roots:
        if not root.is_dir():
            continue
        for entry in _walk_plists(root):
            real = entry.resolve()
            if real in seen:
                continue
            seen.add(real)
            yield PlistLocation(path=real, kind=kind)


def _walk_plists(root: Path) -> Iterator[Path]:
    """Yield *.plist directly under `root` (non-recursive by design).

    launchd ignores nested plists; subdirs are not honored by launchd itself.
    Keeping it shallow avoids noise and matches Apple's documented behavior.

    Silent on missing root, non-directory, or permission denied.
    """
    try:
        entries = sorted(os.scandir(root), key=lambda e: e.name)
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return
    for entry in entries:
        if not entry.is_file(follow_symlinks=False):
            continue
        if entry.name.startswith("."):
            continue
        if not entry.name.endswith(".plist"):
            continue
        yield Path(entry.path)

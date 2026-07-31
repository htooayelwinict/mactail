"""Tests for persistence.scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from mactail.persistence.scanner import (
    PlistKind,
    PlistLocation,
    _walk_plists,
    scan,
)


def _make_plist(root: Path, name: str) -> Path:
    p = root / name
    p.write_bytes(b"<plist><dict/></plist>")
    return p


def test_walk_plists_finds_only_top_level_plists(tmp_path: Path) -> None:
    root = tmp_path / "LaunchAgents"
    root.mkdir()
    a = _make_plist(root, "a.plist")
    _make_plist(root, "b.txt")  # not a plist
    _make_plist(root, ".hidden.plist")  # dot-prefix ignored
    nested = root / "sub"
    nested.mkdir()
    _make_plist(nested, "c.plist")  # nested, ignored by design

    found = {p.name for p in _walk_plists(root)}
    assert found == {"a.plist"}
    assert a.exists()


def test_walk_plists_empty_root(tmp_path: Path) -> None:
    root = tmp_path / "LaunchAgents"
    root.mkdir()
    assert list(_walk_plists(root)) == []


def test_walk_plists_missing_root(tmp_path: Path) -> None:
    assert list(_walk_plists(tmp_path / "nope")) == []


def test_scan_respects_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Replace scanner's home-relative root with a temp dir.
    fake_user_agents = tmp_path / "user_agents"
    fake_user_agents.mkdir()
    _make_plist(fake_user_agents, "mine.plist")

    # Patch _user_agent_root to return our temp.
    from mactail.persistence import scanner

    monkeypatch.setattr(
        scanner, "_user_agent_root", lambda: fake_user_agents, raising=True
    )

    locations = list(scan(include_system=False))
    # /Library/* won't exist on a test box; user root should yield exactly one.
    user_locs = [loc for loc in locations if loc.kind == PlistKind.USER_AGENT]
    assert len(user_locs) == 1
    loc = user_locs[0]
    assert loc.path.name == "mine.plist"
    assert isinstance(loc, PlistLocation)
    assert loc.path.is_absolute()


def test_scan_dedupes_realpath(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A symlink in a second root that points to a real file in the first is deduped.

    Note: mactail only follows symlinks transparently when the target itself is a
    regular file in a scan root; macOS reports `is_file(follow_symlinks=False)=False`
    for a symlink, so the second occurrence (a symlink) is dropped and the real
    file (regular) is yielded exactly once. This matches the production case
    where the same plist might be linked from /Library into ~/Library.
    """
    real = tmp_path / "user"  # this stands in as the "real" user root
    real.mkdir()
    plist = _make_plist(real, "dup.plist")

    system_root = tmp_path / "system"
    system_root.mkdir()
    system_root.joinpath("dup.plist").symlink_to(plist)  # a symlink in system root

    from mactail.persistence import scanner

    monkeypatch.setattr(scanner, "_user_agent_root", lambda: real)
    # Patch _agent_roots to a fixed tuple so /Library/LaunchAgents is replaced
    # with our symlink-holding system_root.
    monkeypatch.setattr(
        scanner,
        "_agent_roots",
        lambda: (
            (real, scanner.PlistKind.USER_AGENT),
            (system_root, scanner.PlistKind.SYSTEM_AGENT),
        ),
    )

    locations = [loc for loc in scan() if loc.path.name == "dup.plist"]
    assert len(locations) == 1
    assert locations[0].path == plist.resolve()


def test_scan_include_system_default_off() -> None:
    """include_system=False must not enumerate /System/Library/Launch*."""
    locations = list(scan(include_system=False))
    apple_kinds = {PlistKind.APPLE_AGENT, PlistKind.APPLE_DAEMON}
    assert not any(loc.kind in apple_kinds for loc in locations)


def test_scan_include_system_on_yields_apple_when_present() -> None:
    locations = list(scan(include_system=True))
    # On a real Mac this would include Apple roots. On Linux/CI, the roots
    # are simply missing, so we just assert no exception + dedup holds.
    seen_paths = {loc.path for loc in locations}
    assert len(seen_paths) == len(locations)

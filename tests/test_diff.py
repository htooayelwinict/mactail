"""Tests for persistence.diff."""

from __future__ import annotations

import plistlib
from pathlib import Path

from mactail.persistence.diff import diff_snapshots
from mactail.persistence.parser import PlistSnapshot, parse
from mactail.persistence.scanner import PlistKind, PlistLocation


def _snap(tmp_path: Path, name: str, payload: dict) -> PlistSnapshot:
    p = tmp_path / name
    p.write_bytes(plistlib.dumps(payload))
    s = parse(PlistLocation(path=p.resolve(), kind=PlistKind.USER_AGENT))
    assert isinstance(s, PlistSnapshot)
    return s


def test_diff_new_plist(tmp_path: Path) -> None:
    base = _snap(tmp_path, "a.plist", {"Label": "com.test.a"})
    cur = _snap(tmp_path, "b.plist", {"Label": "com.test.b"})
    report = diff_snapshots([cur], [base])
    assert len(report.new) == 1
    assert report.new[0].after is cur
    # new user agent triggers R-NEW-USER-AGENT
    rule_ids = {f.rule_id for f in report.findings}
    assert "R-NEW-USER-AGENT" in rule_ids


def test_diff_changed_plist(tmp_path: Path) -> None:
    a_v1 = _snap(tmp_path, "a.plist", {"Label": "com.test.a", "Disabled": True})
    a_v2 = _snap(tmp_path, "a.plist", {"Label": "com.test.a", "Disabled": False, "RunAtLoad": True})
    report = diff_snapshots([a_v2], [a_v1])
    assert len(report.changed) == 1
    assert report.changed[0].before is a_v1
    assert report.changed[0].after is a_v2


def test_diff_unchanged_plist(tmp_path: Path) -> None:
    a = _snap(tmp_path, "a.plist", {"Label": "com.test.a"})
    report = diff_snapshots([a], [a])
    assert report.new == [] and report.changed == [] and report.removed == []


def test_diff_removed_plist(tmp_path: Path) -> None:
    a = _snap(tmp_path, "a.plist", {"Label": "com.test.a"})
    report = diff_snapshots([], [a])
    assert len(report.removed) == 1
    assert report.removed[0].before is a
    assert report.removed[0].after is None


def test_diff_rules_fire_on_changed(tmp_path: Path) -> None:
    """A 'changed' plist whose new state triggers a rule should produce a finding."""
    a_v1 = _snap(tmp_path, "a.plist", {"Label": "com.test.a", "EnvironmentVariables": {"PATH": "/usr/bin"}})
    a_v2 = _snap(
        tmp_path,
        "a.plist",
        {"Label": "com.test.a", "EnvironmentVariables": {"DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"}},
    )
    report = diff_snapshots([a_v2], [a_v1])
    rule_ids = {f.rule_id for f in report.findings}
    assert "R-ENV-DYLD" in rule_ids


def test_diff_by_severity_counts(tmp_path: Path) -> None:
    cur = _snap(
        tmp_path,
        "x.plist",
        {"Label": "x", "Disabled": True, "KeepAlive": True},
    )
    cur.path.chmod(0o666)
    report = diff_snapshots([cur], [])
    sev = report.by_severity()
    # world-writable => critical; disabled+keepalive => low; new user agent => low
    assert sev["critical"] >= 1
    assert sev["low"] >= 1

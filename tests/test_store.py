"""Tests for persistence.store."""

from __future__ import annotations

import plistlib
from pathlib import Path

from mactail.persistence.parser import PlistSnapshot
from mactail.persistence.scanner import PlistKind
from mactail.persistence.store import Store


def _snap(
    tmp_path: Path,
    name: str,
    label: str = "com.test",
    hash_suffix: str = "",
) -> PlistSnapshot:
    p = tmp_path / name
    p.write_bytes(plistlib.dumps({"Label": label, "Note": hash_suffix or label}))
    stat = p.stat()
    import hashlib

    canonical = plistlib.dumps({"Label": label, "Note": hash_suffix or label}, sort_keys=True)
    return PlistSnapshot(
        path=p.resolve(),
        kind=PlistKind.USER_AGENT,
        content_hash=hashlib.sha256(canonical).hexdigest(),
        mtime_ns=stat.st_mtime_ns,
        size=stat.st_size,
        label=label,
    )


def test_schema_version_recorded(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    with Store(db) as s:
        row = s._db.execute("SELECT version FROM schema_version").fetchone()
        assert row["version"] == 1


def test_baseline_then_current_diff(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    a = _snap(tmp_path, "a.plist", hash_suffix="v1")
    b = _snap(tmp_path, "b.plist", hash_suffix="v1")

    with Store(db) as s:
        rb = s.start_run("baseline")
        assert s.record_baseline(rb, [a, b]) == 2
        s.finish_run(rb)

        # Current: a changed, b same, c is new
        a2 = _snap(tmp_path, "a.plist", hash_suffix="v2")
        c = _snap(tmp_path, "c.plist", hash_suffix="v1")
        rc = s.start_run("current")
        seen, new, changed, _err, removed = s.record_current(rc, [a2, b, c])
        s.finish_run(rc)

        assert seen == 3
        assert new == 1
        assert changed == 1
        assert removed == 0

        # All three are now in current_plists with last_status=seen
        paths = {s.path.name for s in s.current_plists()}
        assert paths == {"a.plist", "b.plist", "c.plist"}


def test_current_marks_removed(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    a = _snap(tmp_path, "a.plist", hash_suffix="v1")
    b = _snap(tmp_path, "b.plist", hash_suffix="v1")

    with Store(db) as s:
        rb = s.start_run("baseline")
        s.record_baseline(rb, [a, b])
        s.finish_run(rb)

        rc = s.start_run("current")
        seen, new, changed, _err, removed = s.record_current(rc, [a])
        s.finish_run(rc)

        assert seen == 1
        assert new == 0
        assert changed == 0
        assert removed == 1

        current = {s.path.name for s in s.current_plists()}
        assert "b.plist" not in current
        assert "a.plist" in current


def test_latest_run_id(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    with Store(db) as s:
        assert s.latest_run_id("baseline") is None
        rid = s.start_run("baseline")
        s.finish_run(rid)
        assert s.latest_run_id("baseline") == rid
        assert s.latest_run_id("current") is None


def test_idempotent_record_current(tmp_path: Path) -> None:
    """Running 'current' twice with the same data should report 0 new, 0 changed."""
    db = tmp_path / "s.db"
    a = _snap(tmp_path, "a.plist", hash_suffix="v1")

    with Store(db) as s:
        rb = s.start_run("baseline")
        s.record_baseline(rb, [a])
        s.finish_run(rb)

        rc1 = s.start_run("current")
        s.record_current(rc1, [a])
        s.finish_run(rc1)

        rc2 = s.start_run("current")
        seen, new, changed, _err, removed = s.record_current(rc2, [a])
        s.finish_run(rc2)

        assert (seen, new, changed, removed) == (1, 0, 0, 0)


def test_history_one_row_per_path_per_run(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    a = _snap(tmp_path, "a.plist", hash_suffix="v1")

    with Store(db) as s:
        rb = s.start_run("baseline")
        s.record_baseline(rb, [a])
        s.finish_run(rb)

        rc = s.start_run("current")
        s.record_current(rc, [a])
        s.finish_run(rc)

        rows = s._db.execute(
            "SELECT run_id, COUNT(*) c FROM plist_history WHERE path = ? GROUP BY run_id",
            (str(a.path),),
        ).fetchall()
        # Two runs -> two history rows for this path
        assert len(rows) == 2


def test_run_snapshots_includes_kind(tmp_path: Path) -> None:
    """Regression: run_snapshots must return PlistSnapshot.kind, not crash on missing column."""
    db = tmp_path / "s.db"
    a = _snap(tmp_path, "a.plist", hash_suffix="v1")

    with Store(db) as s:
        rb = s.start_run("baseline")
        s.record_baseline(rb, [a])
        s.finish_run(rb)

        snaps = s.run_snapshots(rb)
        assert len(snaps) == 1
        assert snaps[0].kind == a.kind
        assert snaps[0].content_hash == a.content_hash


def test_prior_run_id(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    with Store(db) as s:
        assert s.prior_run_id(before_run_id=999) is None
        r1 = s.start_run("baseline")
        s.finish_run(r1)
        r2 = s.start_run("current")
        s.finish_run(r2)
        assert s.prior_run_id(before_run_id=r2) == r1
        assert s.prior_run_id(before_run_id=r1) is None

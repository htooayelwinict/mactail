"""SQLite store for plist snapshots and baseline history.

ponytail: v0.1 — single SQLite file, no migrations beyond v1 schema.
Upgrade path: when schema changes, add a `schema_version` row + a migrate()
function and bump SCHEMA_VERSION. Don't add an ORM.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from mactail.persistence.parser import ParseError, PlistSnapshot

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    finished_at REAL,
    kind TEXT NOT NULL CHECK (kind IN ('baseline', 'current'))
);

CREATE TABLE IF NOT EXISTS plists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    current_hash TEXT,
    first_seen_run INTEGER NOT NULL REFERENCES runs(id),
    last_seen_run INTEGER NOT NULL REFERENCES runs(id),
    last_status TEXT NOT NULL CHECK (last_status IN ('seen', 'missing'))
);

CREATE TABLE IF NOT EXISTS plist_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    content_hash TEXT NOT NULL,
    mtime_ns INTEGER NOT NULL,
    size INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('seen', 'missing')),
    UNIQUE (path, run_id)
);

CREATE INDEX IF NOT EXISTS idx_plists_path ON plists(path);
CREATE INDEX IF NOT EXISTS idx_history_path ON plist_history(path);
CREATE INDEX IF NOT EXISTS idx_history_run ON plist_history(run_id);
"""


@dataclass(frozen=True)
class DiffResult:
    """What changed between a current run and the most recent prior state."""

    new: tuple[PlistSnapshot, ...]
    changed: tuple[tuple[PlistSnapshot, PlistSnapshot], ...]  # (before, after)
    removed: tuple[Path, ...]
    baseline_run_id: int | None
    current_run_id: int


class Store:
    """Thin wrapper around a single SQLite file.

    All methods are explicit (no magic on __exit__). Caller decides when to
    close. This keeps the API obvious and the tests trivial.
    """

    def __init__(self, db_path: Path) -> None:
        self._db = sqlite3.connect(str(db_path))
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._migrate()

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _migrate(self) -> None:
        self._db.executescript(_SCHEMA)
        row = self._db.execute("SELECT version FROM schema_version").fetchone()
        if row is None:
            self._db.execute(
                "INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,)
            )
        elif row["version"] != SCHEMA_VERSION:
            raise RuntimeError(
                f"schema version {row['version']} != expected {SCHEMA_VERSION}; "
                "no migration implemented"
            )
        self._db.commit()

    # ---- run lifecycle -------------------------------------------------

    def start_run(self, kind: str) -> int:
        cur = self._db.execute(
            "INSERT INTO runs (started_at, kind) VALUES (?, ?)",
            (time.time(), kind),
        )
        self._db.commit()
        return int(cur.lastrowid)

    def finish_run(self, run_id: int) -> None:
        self._db.execute(
            "UPDATE runs SET finished_at = ? WHERE id = ?", (time.time(), run_id)
        )
        self._db.commit()

    # ---- writes --------------------------------------------------------

    def record_baseline(
        self, run_id: int, snapshots: Iterable[PlistSnapshot | ParseError]
    ) -> int:
        """Insert every snapshot as the initial baseline. Returns rows written."""
        written = 0
        for snap in snapshots:
            if isinstance(snap, ParseError):
                continue
            self._db.execute(
                """
                INSERT INTO plists
                    (path, kind, current_hash, first_seen_run, last_seen_run, last_status)
                VALUES (?, ?, ?, ?, ?, 'seen')
                """,
                (str(snap.path), snap.kind.value, snap.content_hash, run_id, run_id),
            )
            self._db.execute(
                """
                INSERT INTO plist_history (path, run_id, content_hash, mtime_ns, size, status)
                VALUES (?, ?, ?, ?, ?, 'seen')
                """,
                (
                    str(snap.path),
                    run_id,
                    snap.content_hash,
                    snap.mtime_ns,
                    snap.size,
                ),
            )
            written += 1
        self._db.commit()
        return written

    def record_current(
        self,
        run_id: int,
        snapshots: Iterable[PlistSnapshot | ParseError],
    ) -> tuple[int, int, int, int, int]:
        """Record a 'current' run. Returns (seen, new, changed, parse_errors, removed).

        For each snapshot:
          - existing path, same hash -> mark seen in history, no plist update
          - existing path, new hash  -> update plists.current_hash, append history
          - new path                 -> insert plist + history

        Then, paths present in the last baseline/current run but absent from this
        one are recorded as 'missing' (not deleted) and counted as removed.
        """
        seen_count = 0
        new_count = 0
        changed_count = 0
        parse_errors = 0
        current_paths: set[str] = set()

        for snap in snapshots:
            if isinstance(snap, ParseError):
                parse_errors += 1
                continue
            current_paths.add(str(snap.path))
            row = self._db.execute(
                "SELECT id, current_hash FROM plists WHERE path = ?", (str(snap.path),)
            ).fetchone()

            if row is None:
                self._db.execute(
                    """
                    INSERT INTO plists
                        (path, kind, current_hash, first_seen_run, last_seen_run, last_status)
                    VALUES (?, ?, ?, ?, ?, 'seen')
                    """,
                    (str(snap.path), snap.kind.value, snap.content_hash, run_id, run_id),
                )
                new_count += 1
            else:
                if row["current_hash"] != snap.content_hash:
                    self._db.execute(
                        "UPDATE plists SET current_hash = ?, last_seen_run = ? WHERE id = ?",
                        (snap.content_hash, run_id, row["id"]),
                    )
                    changed_count += 1
                else:
                    self._db.execute(
                        "UPDATE plists SET last_seen_run = ? WHERE id = ?",
                        (run_id, row["id"]),
                    )

            self._db.execute(
                """
                INSERT INTO plist_history (path, run_id, content_hash, mtime_ns, size, status)
                VALUES (?, ?, ?, ?, ?, 'seen')
                """,
                (
                    str(snap.path),
                    run_id,
                    snap.content_hash,
                    snap.mtime_ns,
                    snap.size,
                ),
            )
            seen_count += 1

        # Mark paths not seen this run as 'missing' (but only if previously seen).
        prev_seen = {
            row["path"]
            for row in self._db.execute(
                "SELECT path FROM plists WHERE last_status = 'seen'"
            ).fetchall()
        }
        missing_now = prev_seen - current_paths
        removed_count = 0
        for path in sorted(missing_now):
            self._db.execute(
                "UPDATE plists SET last_status = 'missing' WHERE path = ?", (path,)
            )
            self._db.execute(
                """
                INSERT INTO plist_history (path, run_id, content_hash, mtime_ns, size, status)
                VALUES (?, ?, '', 0, 0, 'missing')
                """,
                (path, run_id),
            )
            removed_count += 1

        self._db.commit()
        return seen_count, new_count, changed_count, parse_errors, removed_count

    # ---- reads ---------------------------------------------------------

    def latest_run_id(self, kind: str) -> int | None:
        row = self._db.execute(
            "SELECT id FROM runs WHERE kind = ? ORDER BY id DESC LIMIT 1", (kind,)
        ).fetchone()
        return int(row["id"]) if row else None

    def current_plists(self) -> list[PlistSnapshot]:
        """Reconstruct the latest seen snapshot for every path with last_status=seen."""
        rows = self._db.execute(
            """
            SELECT h.path, h.content_hash, h.mtime_ns, h.size, p.kind
            FROM plist_history h
            JOIN plists p ON p.path = h.path
            WHERE h.run_id = (
                SELECT MAX(h2.run_id) FROM plist_history h2
                WHERE h2.path = h.path AND h2.status = 'seen'
            )
            AND p.last_status = 'seen'
            ORDER BY h.path
            """
        ).fetchall()
        from pathlib import Path as _P

        from mactail.persistence.parser import PlistKind, PlistSnapshot

        out: list[PlistSnapshot] = []
        for r in rows:
            out.append(
                PlistSnapshot(
                    path=_P(r["path"]),
                    kind=PlistKind(r["kind"]),
                    content_hash=r["content_hash"],
                    mtime_ns=int(r["mtime_ns"]),
                    size=int(r["size"]),
                )
            )
        return out

    def prior_run_id(self, *, before_run_id: int) -> int | None:
        """Return the largest run id strictly less than `before_run_id`, or None."""
        row = self._db.execute(
            "SELECT id FROM runs WHERE id < ? ORDER BY id DESC LIMIT 1", (before_run_id,)
        ).fetchone()
        return int(row["id"]) if row else None

    def run_snapshots(self, run_id: int) -> list[PlistSnapshot]:
        """All seen snapshots for a specific run, in path order."""
        rows = self._db.execute(
            """
            SELECT h.path, h.content_hash, h.mtime_ns, h.size, p.kind
            FROM plist_history h
            JOIN plists p ON p.path = h.path
            WHERE h.run_id = ? AND h.status = 'seen'
            ORDER BY h.path
            """,
            (run_id,),
        ).fetchall()
        from pathlib import Path as _P

        from mactail.persistence.parser import PlistKind as _PK
        from mactail.persistence.parser import PlistSnapshot as _PS

        return [
            _PS(
                path=_P(r["path"]),
                kind=_PK(r["kind"]),
                content_hash=r["content_hash"],
                mtime_ns=int(r["mtime_ns"]),
                size=int(r["size"]),
            )
            for r in rows
        ]

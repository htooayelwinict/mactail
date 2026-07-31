"""Tests for persistence.parser."""

from __future__ import annotations

import plistlib
from pathlib import Path

import pytest

from mactail.persistence.parser import (
    ParseError,
    PlistSnapshot,
    parse,
)
from mactail.persistence.scanner import PlistKind, PlistLocation


def _write_plist(tmp_path: Path, name: str, payload: dict) -> Path:
    p = tmp_path / name
    p.write_bytes(plistlib.dumps(payload))
    return p


def test_parse_minimal_valid(tmp_path: Path) -> None:
    p = _write_plist(tmp_path, "good.plist", {"Label": "com.test.good"})
    loc = PlistLocation(path=p.resolve(), kind=PlistKind.USER_AGENT)
    snap = parse(loc)
    assert isinstance(snap, PlistSnapshot)
    assert snap.label == "com.test.good"
    assert snap.run_at_load is False
    assert snap.keep_alive is False
    assert snap.disabled is False
    assert snap.program is None
    assert snap.program_args == ()
    assert snap.content_hash  # non-empty hex


def test_parse_extracts_program_args(tmp_path: Path) -> None:
    p = _write_plist(
        tmp_path,
        "prog.plist",
        {
            "Label": "com.test.prog",
            "ProgramArguments": ["/usr/bin/true", "--flag", "value"],
            "RunAtLoad": True,
            "KeepAlive": True,
            "Disabled": False,
            "UserName": "root",
        },
    )
    snap = parse(PlistLocation(path=p.resolve(), kind=PlistKind.SYSTEM_DAEMON))
    assert isinstance(snap, PlistSnapshot)
    assert snap.program == "/usr/bin/true"
    assert snap.program_args == ("/usr/bin/true", "--flag", "value")
    assert snap.run_at_load is True
    assert snap.keep_alive is True
    assert snap.user_name == "root"
    assert "Sockets" not in snap.raw_keys


def test_parse_program_field_fallback(tmp_path: Path) -> None:
    """When only `Program` is set, `program` is filled from it."""
    p = _write_plist(tmp_path, "p.plist", {"Label": "x", "Program": "/usr/local/bin/x"})
    snap = parse(PlistLocation(path=p.resolve(), kind=PlistKind.USER_AGENT))
    assert snap.program == "/usr/local/bin/x"
    assert snap.program_args == ()


def test_parse_keepalive_dict_is_truthy(tmp_path: Path) -> None:
    p = _write_plist(tmp_path, "ka.plist", {"Label": "x", "KeepAlive": {"SuccessfulExit": False}})
    snap = parse(PlistLocation(path=p.resolve(), kind=PlistKind.USER_AGENT))
    assert snap.keep_alive is True


def test_parse_sockets_and_mach_services(tmp_path: Path) -> None:
    p = _write_plist(
        tmp_path,
        "sock.plist",
        {
            "Label": "x",
            "Sockets": {"Listeners": {"SockType": "unix", "SockPath": "/tmp/x.sock"}},
            "MachServices": {"x.svc": True, "a.svc": True},
        },
    )
    snap = parse(PlistLocation(path=p.resolve(), kind=PlistKind.USER_AGENT))
    assert snap.sockets == (("Listeners", "unix"),)
    assert snap.mach_services == ("a.svc", "x.svc")  # sorted


def test_parse_environment(tmp_path: Path) -> None:
    p = _write_plist(
        tmp_path,
        "env.plist",
        {"Label": "x", "EnvironmentVariables": {"PATH": "/usr/bin", "FOO": "bar"}},
    )
    snap = parse(PlistLocation(path=p.resolve(), kind=PlistKind.USER_AGENT))
    assert snap.environment == (("FOO", "bar"), ("PATH", "/usr/bin"))


def test_parse_raw_extras_excludes_modeled_fields(tmp_path: Path) -> None:
    p = _write_plist(
        tmp_path,
        "extras.plist",
        {
            "Label": "x",
            "RunAtLoad": True,
            "StartCalendarInterval": {"Hour": 3, "Minute": 0},
            "WatchPaths": ["/tmp/x"],
        },
    )
    snap = parse(PlistLocation(path=p.resolve(), kind=PlistKind.USER_AGENT))
    extras_keys = {k for k, _ in snap.raw_extras}
    assert "Label" not in extras_keys
    assert "RunAtLoad" not in extras_keys
    assert "StartCalendarInterval" in extras_keys
    assert "WatchPaths" in extras_keys


def test_hash_stable_across_dict_reorder(tmp_path: Path) -> None:
    """Same plist content with different key insertion order must hash equal."""
    a = _write_plist(tmp_path, "a.plist", {"Label": "x", "RunAtLoad": True})
    b = _write_plist(tmp_path, "b.plist", {"RunAtLoad": True, "Label": "x"})
    snap_a = parse(PlistLocation(path=a.resolve(), kind=PlistKind.USER_AGENT))
    snap_b = parse(PlistLocation(path=b.resolve(), kind=PlistKind.USER_AGENT))
    assert isinstance(snap_a, PlistSnapshot)
    assert isinstance(snap_b, PlistSnapshot)
    assert snap_a.content_hash == snap_b.content_hash


def test_parse_invalid_plist_returns_error(tmp_path: Path) -> None:
    p = tmp_path / "bad.plist"
    p.write_bytes(b"not a plist at all")
    err = parse(PlistLocation(path=p.resolve(), kind=PlistKind.USER_AGENT))
    assert isinstance(err, ParseError)
    assert "invalid" in err.reason.lower()


def test_parse_top_level_not_dict(tmp_path: Path) -> None:
    p = _write_plist(tmp_path, "arr.plist", ["Label", "com.test"])
    err = parse(PlistLocation(path=p.resolve(), kind=PlistKind.USER_AGENT))
    assert isinstance(err, ParseError)
    assert "dict" in err.reason


def test_parse_missing_file(tmp_path: Path) -> None:
    p = tmp_path / "ghost.plist"
    err = parse(PlistLocation(path=p.resolve(), kind=PlistKind.USER_AGENT))
    assert isinstance(err, ParseError)
    assert "not found" in err.reason


def test_parse_permission_denied(tmp_path: Path) -> None:
    p = _write_plist(tmp_path, "noperm.plist", {"Label": "x"})
    p.chmod(0o000)
    try:
        err = parse(PlistLocation(path=p.resolve(), kind=PlistKind.USER_AGENT))
    finally:
        p.chmod(0o644)
    # root may bypass; accept either outcome but assert shape if ParseError
    if isinstance(err, ParseError):
        assert "permission" in err.reason.lower() or "unexpected" in err.reason.lower()


@pytest.mark.parametrize(
    "payload",
    [
        {"Label": "com.test.a"},
        {"Label": "com.test.b", "ProgramArguments": ["/bin/sh"]},
    ],
)
def test_parse_does_not_raise(tmp_path: Path, payload: dict) -> None:
    """parse() is a trust boundary — it must never raise, only return."""
    p = _write_plist(tmp_path, "x.plist", payload)
    result = parse(PlistLocation(path=p.resolve(), kind=PlistKind.USER_AGENT))
    assert isinstance(result, PlistSnapshot | ParseError)

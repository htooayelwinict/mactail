"""Tests for rules.builtin."""

from __future__ import annotations

import plistlib
from collections.abc import Iterable
from pathlib import Path

import pytest

from mactail.persistence.parser import PlistSnapshot, parse
from mactail.persistence.scanner import PlistKind, PlistLocation
from mactail.rules.builtin import (
    ALL_RULES,
    Finding,
    rule_disabled_kept_alive,
    rule_dyld_env,
    rule_missing_label,
    rule_run_at_load_and_keep_alive_unsigned,
    rule_suspicious_interpreter,
    rule_suspicious_program_path,
    rule_user_agent_running_as_root,
    rule_world_writable,
)


def _snap(tmp_path: Path, name: str, payload: dict, kind: PlistKind = PlistKind.USER_AGENT) -> PlistSnapshot:
    p = tmp_path / name
    p.write_bytes(plistlib.dumps(payload))
    loc = PlistLocation(path=p.resolve(), kind=kind)
    s = parse(loc)
    assert isinstance(s, PlistSnapshot)
    return s


# --- world-writable --------------------------------------------------------


def test_world_writable_triggers(tmp_path: Path) -> None:
    s = _snap(tmp_path, "x.plist", {"Label": "x"})
    s.path.chmod(0o666)
    f = list(rule_world_writable(s))
    assert len(f) == 1
    assert f[0].rule_id == "R-WORLD-WRITABLE"
    assert f[0].severity == "critical"


def test_world_writable_clean(tmp_path: Path) -> None:
    s = _snap(tmp_path, "x.plist", {"Label": "x"})
    s.path.chmod(0o644)
    assert list(rule_world_writable(s)) == []


# --- program in /tmp ------------------------------------------------------


def test_suspicious_program_path_triggers(tmp_path: Path) -> None:
    s = _snap(tmp_path, "x.plist", {"Label": "x", "ProgramArguments": ["/tmp/.x/agent"]})
    f = list(rule_suspicious_program_path(s))
    assert len(f) == 1 and f[0].rule_id == "R-PROG-TMP"


def test_suspicious_program_path_clean(tmp_path: Path) -> None:
    s = _snap(tmp_path, "x.plist", {"Label": "x", "ProgramArguments": ["/usr/local/bin/legit"]})
    assert list(rule_suspicious_program_path(s)) == []


# --- suspicious interpreter -----------------------------------------------


def test_suspicious_interpreter_triggers(tmp_path: Path) -> None:
    s = _snap(tmp_path, "x.plist", {"Label": "x", "ProgramArguments": ["/bin/bash", "-c", "x"]})
    f = list(rule_suspicious_interpreter(s))
    assert len(f) == 1 and f[0].rule_id == "R-PROG-INTERPRETER"


def test_suspicious_interpreter_clean(tmp_path: Path) -> None:
    s = _snap(tmp_path, "x.plist", {"Label": "x", "ProgramArguments": ["/usr/bin/true"]})
    assert list(rule_suspicious_interpreter(s)) == []


# --- run-at-load + keep-alive --------------------------------------------


def test_run_and_keepalive_triggers(tmp_path: Path) -> None:
    s = _snap(tmp_path, "x.plist", {"Label": "x", "RunAtLoad": True, "KeepAlive": True})
    f = list(rule_run_at_load_and_keep_alive_unsigned(s))
    assert len(f) == 1 and f[0].severity == "medium"


def test_run_and_keepalive_off(tmp_path: Path) -> None:
    s = _snap(tmp_path, "x.plist", {"Label": "x", "RunAtLoad": True})
    assert list(rule_run_at_load_and_keep_alive_unsigned(s)) == []


# --- dyld env ------------------------------------------------------------


def test_dyld_env_triggers(tmp_path: Path) -> None:
    s = _snap(
        tmp_path,
        "x.plist",
        {"Label": "x", "EnvironmentVariables": {"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"}},
    )
    f = list(rule_dyld_env(s))
    assert len(f) == 1 and f[0].rule_id == "R-ENV-DYLD"


def test_dyld_env_clean(tmp_path: Path) -> None:
    s = _snap(
        tmp_path,
        "x.plist",
        {"Label": "x", "EnvironmentVariables": {"PATH": "/usr/bin"}},
    )
    assert list(rule_dyld_env(s)) == []


# --- user agent as root --------------------------------------------------


def test_user_agent_root_triggers(tmp_path: Path) -> None:
    s = _snap(
        tmp_path,
        "x.plist",
        {"Label": "x", "UserName": "root"},
        kind=PlistKind.USER_AGENT,
    )
    f = list(rule_user_agent_running_as_root(s))
    assert len(f) == 1 and f[0].rule_id == "R-USERAGENT-ROOT"


def test_system_agent_root_ok(tmp_path: Path) -> None:
    """SYSTEM_AGENT with UserName=root is normal; should not flag."""
    s = _snap(
        tmp_path,
        "x.plist",
        {"Label": "x", "UserName": "root"},
        kind=PlistKind.SYSTEM_AGENT,
    )
    assert list(rule_user_agent_running_as_root(s)) == []


# --- missing label --------------------------------------------------------


def test_missing_label_triggers(tmp_path: Path) -> None:
    s = _snap(tmp_path, "x.plist", {"ProgramArguments": ["/bin/true"]})
    f = list(rule_missing_label(s))
    assert len(f) == 1 and f[0].rule_id == "R-NO-LABEL"


def test_missing_label_clean(tmp_path: Path) -> None:
    s = _snap(tmp_path, "x.plist", {"Label": "com.test.x"})
    assert list(rule_missing_label(s)) == []


# --- contradictory keep-alive + disabled ---------------------------------


def test_disabled_keepalive_triggers(tmp_path: Path) -> None:
    s = _snap(tmp_path, "x.plist", {"Label": "x", "Disabled": True, "KeepAlive": True})
    f = list(rule_disabled_kept_alive(s))
    assert len(f) == 1 and f[0].rule_id == "R-DISABLED-KEEPALIVE"


def test_disabled_keepalive_clean(tmp_path: Path) -> None:
    s = _snap(tmp_path, "x.plist", {"Label": "x", "Disabled": True, "KeepAlive": False})
    assert list(rule_disabled_kept_alive(s)) == []


# --- ALL_RULES shape ------------------------------------------------------


def test_all_rules_iterable_and_pure() -> None:
    """Every rule must be a callable taking a PlistSnapshot, returning Iterable[Finding]."""
    s = _snap(Path("/tmp"), "y.plist", {"Label": "x"})  # parsed on a /tmp file is fine
    for rule in ALL_RULES:
        out = rule(s)
        assert isinstance(out, Iterable)
        for f in out:
            assert isinstance(f, Finding)
            assert f.severity in {"low", "medium", "high", "critical"}
            assert f.rule_id
            assert f.path


@pytest.mark.parametrize("rule", ALL_RULES)
def test_rules_dont_raise_on_minimal_snapshot(rule, tmp_path: Path) -> None:
    s = _snap(tmp_path, "x.plist", {})
    # Rules are pure: must not raise on a valid but minimal plist.
    list(rule(s))

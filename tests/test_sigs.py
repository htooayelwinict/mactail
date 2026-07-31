"""Tests for persistence.sigs."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from mactail.persistence import sigs
from mactail.persistence.sigs import SignatureInfo, inspect, inspect_cached

# Canonical codesign -dv --verbose=4 outputs for mocking.
APPLE_OUTPUT = """Executable=/usr/bin/true
Identifier=com.apple.true
Format=Mach-O universal (x86_64)
CodeDirectory v=20400 size=489 flags=0x10000(runtime) hashes=3+3 location=embedded
Authority=Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
Signed Time=Jan 1, 2024 at 00:00:00
Info.plist=not bound
TeamIdentifier=APPLECOMPUTER
Runtime Version=14.0.0
"""

THIRD_PARTY_OUTPUT = """Executable=/usr/local/bin/third
Identifier=com.example.third
Format=Mach-O 64-bit
CodeDirectory v=20400 size=232 flags=0x10000(runtime) hashes=2+2 location=embedded
Authority=Developer ID Application: Example Corp (ABCDE12345)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Signed Time=Feb 1, 2024 at 00:00:00
TeamIdentifier=ABCDE12345
"""

UNSIGNED_OUTPUT = """Executable=/tmp/unsigned
Identifier=??
Format=Mach-O 64-bit
CodeDirectory v=20400 size=0 flags=0x0 hashes=0+0 location=embedded
"""


def _mock_codesign(output: str, rc: int = 0):
    return patch(
        "subprocess.run",
        return_value=subprocess.CompletedProcess(args=[], returncode=rc, stdout=output, stderr=""),
    )


# --- inspect ---------------------------------------------------------------


def test_inspect_apple_signed(tmp_path: Path) -> None:
    p = tmp_path / "true"
    p.write_bytes(b"")
    with _mock_codesign(APPLE_OUTPUT, rc=0):
        info = inspect(p)
    assert isinstance(info, SignatureInfo)
    assert info.is_signed is True
    assert info.is_apple_signed is True
    assert info.team_id == "APPLECOMPUTER"
    assert info.signing_id == "com.apple.true"
    assert info.is_hardened_runtime is True
    assert info.error is None


def test_inspect_third_party_signed(tmp_path: Path) -> None:
    p = tmp_path / "third"
    p.write_bytes(b"")
    with _mock_codesign(THIRD_PARTY_OUTPUT, rc=0):
        info = inspect(p)
    assert info.is_signed is True
    assert info.is_apple_signed is False
    assert info.team_id == "ABCDE12345"
    assert info.error is None


def test_inspect_unsigned(tmp_path: Path) -> None:
    p = tmp_path / "u"
    p.write_bytes(b"")
    with _mock_codesign(UNSIGNED_OUTPUT, rc=2):
        info = inspect(p)
    assert info.is_signed is False
    assert info.is_apple_signed is False
    assert info.team_id is None
    assert info.error is not None
    assert "rc=2" in info.error


def test_inspect_missing_file(tmp_path: Path) -> None:
    info = inspect(tmp_path / "ghost")
    assert info.is_signed is False
    assert info.error == "file not found"


def test_inspect_codesign_missing(tmp_path: Path) -> None:
    """When `codesign` binary itself is missing (non-macOS), return unknown cleanly."""
    p = tmp_path / "x"
    p.write_bytes(b"")
    with patch("subprocess.run", side_effect=FileNotFoundError):
        info = inspect(p)
    assert info.is_signed is False
    assert info.error == "codesign binary not found"


def test_inspect_timeout(tmp_path: Path) -> None:
    p = tmp_path / "x"
    p.write_bytes(b"")
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=[], timeout=10)):
        info = inspect(p)
    assert info.is_signed is False
    assert "timed out" in info.error


def test_inspect_nonzero_unknown_rc(tmp_path: Path) -> None:
    p = tmp_path / "x"
    p.write_bytes(b"")
    with _mock_codesign("", rc=99):
        info = inspect(p)
    assert info.is_signed is False
    assert "exited 99" in info.error


# --- caching ---------------------------------------------------------------


def test_inspect_cached_hits_subprocess_once(tmp_path: Path) -> None:
    p = tmp_path / "true"
    p.write_bytes(b"")
    sigs.clear_cache()
    with _mock_codesign(APPLE_OUTPUT, rc=0) as m:
        a = inspect_cached(p)
        b = inspect_cached(p)
        c = inspect_cached(p)
    assert a is b is c
    assert m.call_count == 1


def test_inspect_cached_distinct_paths(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.write_bytes(b"")
    b.write_bytes(b"")
    sigs.clear_cache()
    with _mock_codesign(APPLE_OUTPUT, rc=0) as m:
        inspect_cached(a)
        inspect_cached(b)
    assert m.call_count == 2


# --- Apple detection edge cases --------------------------------------------


def test_is_apple_signed_requires_software_signing_authority(tmp_path: Path) -> None:
    """A team id starting with 'apple' is NOT enough — authority must include Software Signing."""
    fake = """Identifier=com.evil.apple-impersonator
Authority=Apple Code Signing Certification Authority
TeamIdentifier=APPLECOMPUTER
"""
    p = tmp_path / "fake"
    p.write_bytes(b"")
    with _mock_codesign(fake, rc=0):
        info = inspect(p)
    # Has Apple CA in chain but NOT 'Software Signing' (the platform-level authority).
    # is_apple_signed should be False because the topmost authority is missing.
    assert info.team_id == "APPLECOMPUTER"
    assert info.is_apple_signed is False


def test_hardened_runtime_flag_parsing(tmp_path: Path) -> None:
    """No runtime flag bit set -> is_hardened_runtime=False."""
    no_runtime = """Identifier=com.test.x
Authority=Software Signing
TeamIdentifier=APPLECOMPUTER
CodeDirectory v=20400 size=100 flags=0x0 hashes=1+1 location=embedded
"""
    p = tmp_path / "nrt"
    p.write_bytes(b"")
    with _mock_codesign(no_runtime, rc=0):
        info = inspect(p)
    assert info.is_hardened_runtime is False
    assert info.is_apple_signed is True

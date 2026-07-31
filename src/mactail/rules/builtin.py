"""Built-in rules for classifying plist risk.

Each rule is a small pure function: snapshot in, list[Finding] out. The
diff layer calls them per-snapshot and aggregates. Rules never touch the
store; that keeps them trivially testable and easy to add.

ponytail: v0.1 — 8 hand-written rules, no YAML loader, no MITRE STIX import.
Upgrade path: when rule count > 20 or users want custom rules, move rule
defs to YAML and add a `rules: Rule` protocol + a registry.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass

from mactail.persistence.parser import PlistSnapshot
from mactail.persistence.scanner import PlistKind

# A short list of well-known directories a Program/ProgramArgument pointing
# to is suspicious from. Not exhaustive — these are the obvious /tmp-like spots.
_SUSPICIOUS_PROGRAM_DIRS: tuple[str, ...] = (
    "/tmp/",
    "/var/tmp/",
    "/private/tmp/",
    "/private/var/folders/",  # per-user temp on macOS
)

# Shells / interpreters we treat as elevated risk when invoked by a launchd job.
_SUSPICIOUS_INTERPRETERS: tuple[str, ...] = (
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "/usr/bin/osascript",
    "/usr/bin/curl",
    "/usr/bin/wget",
    "/usr/bin/nc",
)

# Environment variable names that are basically never legitimately set in a
# launchd plist. Their presence is a strong persistence/abuse indicator.
_SUSPICIOUS_ENV_VARS: frozenset[str] = frozenset(
    {"DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "DYLD_LIBRARY_PATH"}
)


@dataclass(frozen=True)
class Finding:
    """One rule hit on one plist."""

    severity: str  # "low" | "medium" | "high" | "critical"
    rule_id: str  # e.g. "R-WORLD-WRITABLE"
    path: str  # str(path) for serialization friendliness
    evidence: str  # one-line human-readable why
    mitre: str  # MITRE ATT&CK technique id, e.g. "T1543.001"
    recommendation: str  # what to do about it


# ---- rule helpers ---------------------------------------------------------


def _is_world_writable(path) -> bool:
    """True if the plist file mode grants write to 'other'."""
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return bool(mode & stat.S_IWOTH)


def _program_paths(snap: PlistSnapshot) -> tuple[str, ...]:
    """All program paths mentioned by the plist (Program + ProgramArguments)."""
    out: list[str] = []
    if snap.program:
        out.append(snap.program)
    out.extend(snap.program_args)
    return tuple(out)


# ---- individual rules -----------------------------------------------------


def rule_world_writable(snap: PlistSnapshot) -> Iterable[Finding]:
    if not _is_world_writable(snap.path):
        return ()
    return (
        Finding(
            severity="critical",
            rule_id="R-WORLD-WRITABLE",
            path=str(snap.path),
            evidence=f"{snap.path} is world-writable",
            mitre="T1543.001",
            recommendation="chmod 644 the file and audit who had write access",
        ),
    )


def rule_suspicious_program_path(snap: PlistSnapshot) -> Iterable[Finding]:
    hits = [
        p for p in _program_paths(snap) if any(p.startswith(d) for d in _SUSPICIOUS_PROGRAM_DIRS)
    ]
    if not hits:
        return ()
    return (
        Finding(
            severity="high",
            rule_id="R-PROG-TMP",
            path=str(snap.path),
            evidence=f"Program points at temp dir: {hits[0]}",
            mitre="T1543.001",
            recommendation="inspect the binary; temp-dir launchd targets are a top persistence pattern",
        ),
    )


def rule_suspicious_interpreter(snap: PlistSnapshot) -> Iterable[Finding]:
    hits = [
        p for p in _program_paths(snap)
        if any(p == i or p.endswith("/" + os.path.basename(i)) for i in _SUSPICIOUS_INTERPRETERS)
    ]
    if not hits:
        return ()
    return (
        Finding(
            severity="medium",
            rule_id="R-PROG-INTERPRETER",
            path=str(snap.path),
            evidence=f"Program invokes interpreter/network tool: {hits[0]}",
            mitre="T1059.004",  # Unix Shell
            recommendation="review the script; shells/nc/curl launched by launchd are rare in legit software",
        ),
    )


def rule_run_at_load_and_keep_alive_unsigned(snap: PlistSnapshot) -> Iterable[Finding]:
    if not (snap.run_at_load and snap.keep_alive):
        return ()
    if not snap.path.exists():
        return ()
    # We don't have signature info here yet; treat the combination alone as
    # medium (v0.1). A signature check upgrades to high when sigs land.
    return (
        Finding(
            severity="medium",
            rule_id="R-RUN-KEEPALIVE",
            path=str(snap.path),
            evidence="RunAtLoad=true AND KeepAlive=true",
            mitre="T1543.001",
            recommendation="confirm the agent is from a known vendor; will upgrade to high if unsigned",
        ),
    )


def rule_dyld_env(snap: PlistSnapshot) -> Iterable[Finding]:
    hits = [k for k, _ in snap.environment if k in _SUSPICIOUS_ENV_VARS]
    if not hits:
        return ()
    return (
        Finding(
            severity="critical",
            rule_id="R-ENV-DYLD",
            path=str(snap.path),
            evidence=f"suspicious env var: {hits[0]}",
            mitre="T1574.006",  # Dynamic Linker Hijacking
            recommendation="quarantine immediately; DYLD/LD_PRELOAD in launchd is a hijack indicator",
        ),
    )


def rule_user_agent_running_as_root(snap: PlistSnapshot) -> Iterable[Finding]:
    """An agent under a user dir with UserName=root is a strong anomaly."""
    if snap.kind not in (PlistKind.USER_AGENT, PlistKind.SYSTEM_AGENT):
        return ()
    if snap.user_name != "root":
        return ()
    if snap.kind == PlistKind.SYSTEM_AGENT:
        # SYSTEM_AGENT with UserName=root is normal for many Apple agents.
        return ()
    return (
        Finding(
            severity="high",
            rule_id="R-USERAGENT-ROOT",
            path=str(snap.path),
            evidence=f"per-user agent declares UserName=root ({snap.label or 'no label'})",
            mitre="T1548.003",  # Sudo and SUID
            recommendation="a per-user agent should not run as root; review the plist source",
        ),
    )


def rule_missing_label(snap: PlistSnapshot) -> Iterable[Finding]:
    if snap.label is None or not snap.label.strip():
        return (
            Finding(
                severity="low",
                rule_id="R-NO-LABEL",
                path=str(snap.path),
                evidence="plist has no Label",
                mitre="",
                recommendation="launchd may refuse to load plists without a Label; investigate provenance",
            ),
        )
    return ()


def rule_disabled_kept_alive(snap: PlistSnapshot) -> Iterable[Finding]:
    """Disabled=true + KeepAlive=true is contradictory and suspicious if new."""
    if snap.disabled and snap.keep_alive:
        return (
            Finding(
                severity="low",
                rule_id="R-DISABLED-KEEPALIVE",
                path=str(snap.path),
                evidence="Disabled=true AND KeepAlive=true (contradictory)",
                mitre="",
                recommendation="verify intent; one of these is likely wrong, possibly to mask persistence",
            ),
        )
    return ()


ALL_RULES = (
    rule_world_writable,
    rule_suspicious_program_path,
    rule_suspicious_interpreter,
    rule_run_at_load_and_keep_alive_unsigned,
    rule_dyld_env,
    rule_user_agent_running_as_root,
    rule_missing_label,
    rule_disabled_kept_alive,
)

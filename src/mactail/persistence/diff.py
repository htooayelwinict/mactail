"""Compute a diff between a current run and a prior baseline, with findings.

ponytail: v0.1 — diff is in-memory and recomputed on every call (cheap: a few
hundred plists). When datasets grow past ~10k or rules become expensive, push
the diff into SQL with a single JOIN.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from mactail.persistence.parser import PlistSnapshot
from mactail.rules.builtin import ALL_RULES, Finding
from mactail.rules.builtin import Finding as _Finding


@dataclass(frozen=True)
class PlistDiff:
    """One changed plist with before/after snapshots."""

    before: PlistSnapshot | None  # None if new
    after: PlistSnapshot | None  # None if removed
    findings: tuple[Finding, ...] = ()


@dataclass
class DiffReport:
    """Full diff result: new/changed/removed + flat findings list."""

    new: list[PlistDiff] = field(default_factory=list)
    changed: list[PlistDiff] = field(default_factory=list)
    removed: list[PlistDiff] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {s: 0 for s in ("critical", "high", "medium", "low")}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


def diff_snapshots(
    current: Iterable[PlistSnapshot],
    baseline: Iterable[PlistSnapshot],
) -> DiffReport:
    """Pairwise diff: classify each current snapshot and surface findings."""
    base_by_path: dict[Path, PlistSnapshot] = {s.path: s for s in baseline}
    cur_by_path: dict[Path, PlistSnapshot] = {s.path: s for s in current}

    report = DiffReport()

    for path, cur in cur_by_path.items():
        base = base_by_path.get(path)
        if base is None:
            findings = _apply_rules(cur) + _new_path_overrides(cur)
            report.new.append(PlistDiff(before=None, after=cur, findings=tuple(findings)))
        elif base.content_hash != cur.content_hash:
            findings = _apply_rules(cur)
            report.changed.append(PlistDiff(before=base, after=cur, findings=tuple(findings)))

    for path, base in base_by_path.items():
        if path not in cur_by_path:
            report.removed.append(PlistDiff(before=base, after=None))

    report.findings = [f for d in (*report.new, *report.changed) for f in d.findings]
    return report


def _apply_rules(snap: PlistSnapshot) -> list[_Finding]:
    out: list[_Finding] = []
    for rule in ALL_RULES:
        out.extend(rule(snap))
    return out


def _new_path_overrides(snap: PlistSnapshot) -> list[_Finding]:
    """Severity lifts for newly observed plists in sensitive locations.

    A brand-new per-user LaunchAgent is itself a signal even if the plist
    looks clean — the rule set should reflect that.
    """
    from mactail.persistence.scanner import PlistKind
    from mactail.rules.builtin import Finding as F

    extras: list[F] = []
    if snap.kind == PlistKind.USER_AGENT:
        extras.append(
            F(
                severity="low",
                rule_id="R-NEW-USER-AGENT",
                path=str(snap.path),
                evidence=f"new user LaunchAgent: {snap.label or 'no label'}",
                mitre="T1543.001",
                recommendation="verify this agent was intentionally installed",
            )
        )
    return extras

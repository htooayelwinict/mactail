"""Typer app for mactail."""

from __future__ import annotations

import json
import os
from pathlib import Path

import typer

from mactail import __version__
from mactail.persistence.diff import DiffReport, diff_snapshots
from mactail.persistence.parser import ParseError, PlistKind, PlistSnapshot, parse
from mactail.persistence.scanner import PlistLocation, scan
from mactail.persistence.store import Store

app = typer.Typer(
    name="mactail",
    help="Local-first macOS launchd persistence baselining & threat hunting.",
    no_args_is_help=True,
    add_completion=False,
)


def _default_db() -> Path:
    base = os.environ.get("MACTAIL_HOME") or os.path.join(
        os.environ.get("HOME", str(Path.home())), ".local", "share", "mactail"
    )
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p / "state.db"


def _version(value: bool) -> None:
    if value:
        typer.echo(f"mactail {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """mactail root callback."""


def _scan_and_parse(include_system: bool) -> tuple[list[PlistSnapshot], list[ParseError]]:
    snaps: list[PlistSnapshot] = []
    errors: list[ParseError] = []
    for loc in scan(include_system=include_system):
        result = parse(loc)
        if isinstance(result, ParseError):
            errors.append(result)
        else:
            snaps.append(result)
    return snaps, errors


@app.command()
def baseline(
    db: Path = typer.Option(
        None, "--db", help="SQLite state file (default: ~/.local/share/mactail/state.db)"
    ),
    include_system: bool = typer.Option(
        False, "--include-system", help="Also walk /System/Library/Launch* (read-only reference)"
    ),
) -> None:
    """Snapshot current launchd plists into the local store (first run baseline)."""
    db = db or _default_db()
    snaps, errors = _scan_and_parse(include_system)
    with Store(db) as s:
        rid = s.start_run("baseline")
        written = s.record_baseline(rid, snaps)
        s.finish_run(rid)
    typer.echo(f"baseline: wrote {written} plists, {len(errors)} parse errors -> {db}")
    for e in errors:
        typer.echo(f"  ! {e.path}: {e.reason}")


@app.command()
def diff(
    db: Path = typer.Option(
        None, "--db", help="SQLite state file (default: ~/.local/share/mactail/state.db)"
    ),
    include_system: bool = typer.Option(
        False, "--include-system", help="Also walk /System/Library/Launch* (read-only reference)"
    ),
    fmt: str = typer.Option(
        "markdown", "--format", help="Output format: markdown | json"
    ),
    min_severity: str = typer.Option(
        "low", "--min-severity", help="Drop findings below this severity (low|medium|high|critical)"
    ),
) -> None:
    """Diff current state against the most recent prior state."""
    db = db or _default_db()
    if not db.exists():
        typer.echo(f"no state file at {db}; run `mactail baseline` first", err=True)
        raise typer.Exit(code=1)

    snaps, errors = _scan_and_parse(include_system)
    with Store(db) as s:
        rid = s.start_run("current")
        s.record_current(rid, snaps)
        s.finish_run(rid)
        prior_id = s.prior_run_id(before_run_id=rid)
        if prior_id is None:
            typer.echo("no prior run; nothing to diff against", err=True)
            raise typer.Exit(code=1)
        baseline_models = s.run_snapshots(prior_id)

    report = diff_snapshots(snaps, baseline_models)

    sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    cutoff = sev_order.get(min_severity, 0)
    report.findings = [f for f in report.findings if sev_order.get(f.severity, 0) >= cutoff]

    if fmt == "json":
        _print_json(report, errors)
    else:
        _print_markdown(report, errors)


def _print_json(report: DiffReport, errors: list[ParseError]) -> None:
    payload = {
        "summary": {
            "new": len(report.new),
            "changed": len(report.changed),
            "removed": len(report.removed),
            "by_severity": report.by_severity(),
        },
        "findings": [f.__dict__ for f in report.findings],
        "parse_errors": [{"path": str(e.path), "reason": e.reason} for e in errors],
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


def _print_markdown(report: DiffReport, errors: list[ParseError]) -> None:
    sev_emoji = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]"}
    sev = report.by_severity()
    typer.echo("# mactail diff")
    typer.echo("")
    typer.echo(
        f"**new={len(report.new)} changed={len(report.changed)} removed={len(report.removed)} "
        f"critical={sev['critical']} high={sev['high']} medium={sev['medium']} low={sev['low']}**"
    )
    typer.echo("")

    if report.new:
        typer.echo("## New")
        for d in report.new:
            if d.after is None:
                continue
            typer.echo(f"- `{d.after.path}` (label: `{d.after.label or '-'}`)")
            for f in d.findings:
                tag = sev_emoji.get(f.severity, f"[{f.severity.upper()}]")
                typer.echo(f"  - {tag} **{f.rule_id}**: {f.evidence}")
        typer.echo("")

    if report.changed:
        typer.echo("## Changed")
        for d in report.changed:
            if d.after is None:
                continue
            typer.echo(f"- `{d.after.path}`")
            for f in d.findings:
                tag = sev_emoji.get(f.severity, f"[{f.severity.upper()}]")
                typer.echo(f"  - {tag} **{f.rule_id}**: {f.evidence}")
        typer.echo("")

    if report.removed:
        typer.echo("## Removed")
        for d in report.removed:
            if d.before is None:
                continue
            typer.echo(f"- `{d.before.path}`")
        typer.echo("")

    if errors:
        typer.echo("## Parse errors")
        for e in errors:
            typer.echo(f"- `{e.path}`: {e.reason}")


@app.command()
def show(
    path: str = typer.Argument(..., help="Path to a plist file to inspect"),
) -> None:
    """Show canonical contents of a single plist."""
    p = Path(path).resolve()
    loc = PlistLocation(path=p, kind=PlistKind.USER_AGENT)
    snap = parse(loc)
    if isinstance(snap, ParseError):
        typer.echo(f"error: {snap.reason}", err=True)
        raise typer.Exit(code=1)
    typer.echo(json.dumps(snap.model_dump(mode="json"), indent=2, default=str))


if __name__ == "__main__":
    app()

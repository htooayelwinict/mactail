# mactail

Local-first macOS launchd persistence baselining and threat hunting.

Snapshots every LaunchAgent / LaunchDaemon plist, diffs against a baseline,
flags suspicious persistence with evidence and rule IDs, and inspects
code signatures via `codesign` to classify Apple-signed vs unsigned binaries.

## Install (editable, dev)

```bash
uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python -e ".[dev]"
```

## Usage

```bash
# First run: create baseline
mactail baseline

# Subsequent runs: diff against baseline (markdown or JSON)
mactail diff
mactail diff --format json
mactail diff --min-severity medium

# Include Apple-shipped /System/Library/Launch* (read-only reference)
mactail diff --include-system

# Show canonical parsed contents of a single plist
mactail show ~/Library/LaunchAgents/com.example.plist

# Use a custom state file
mactail baseline --db ./my-state.db
```

## Built-in rules

| Rule ID | Severity | Description |
|---|---|---|
| `R-WORLD-WRITABLE` | critical | plist file is world-writable |
| `R-PROG-TMP` | high | Program points at /tmp or similar |
| `R-PROG-INTERPRETER` | medium | Program invokes sh/bash/curl/nc/osascript |
| `R-RUN-KEEPALIVE` | medium | RunAtLoad+KeepAlive, binary not found for sig check |
| `R-RUN-KEEPALIVE-UNSIGNED` | high/critical | RunAtLoad+KeepAlive, binary non-Apple signed or unsigned |
| `R-ENV-DYLD` | critical | DYLD_INSERT_LIBRARIES / LD_PRELOAD in EnvironmentVariables |
| `R-USERAGENT-ROOT` | high | per-user agent declares UserName=root |
| `R-NO-LABEL` | low | plist has no Label key |
| `R-DISABLED-KEEPALIVE` | low | Disabled=true AND KeepAlive=true (contradictory) |
| `R-NEW-USER-AGENT` | low | new user LaunchAgent not in baseline |

## Status

v0.2 (alpha). macOS 12+. Local-only. No network calls.
Pure stdlib (plistlib, sqlite3, subprocess calls to `codesign`).
Pydantic v2 for data modeling; Typer CLI.

See `src/mactail/rules/builtin.py` and `src/mactail/persistence/sigs.py`
for the rule engine and code signature inspection.
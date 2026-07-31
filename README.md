# mactail

Local-first macOS launchd persistence baselining and threat hunting.

Snapshots every LaunchAgent / LaunchDaemon plist, diffs against a baseline, and
flags suspicious persistence with evidence and rule IDs.

## Install (editable, dev)

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# First run: create baseline
mactail baseline

# Subsequent runs: diff against baseline
mactail diff

# Show a single plist (canonical)
mactail show ~/Library/LaunchAgents/com.example.plist

# JSON output for piping
mactail diff --format json
```

## Status

v0.1 (alpha). macOS 12+. Local-only. No network calls.

See `src/mactail/rules/builtin.py` for the built-in rule set.

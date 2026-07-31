<p align="center">
  <b style="font-size:1.5em">m a c t a i l</b><br/>
  <sub>Local-first macOS launchd persistence baselining &amp; threat hunting.</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12+" />
  <img src="https://img.shields.io/badge/macOS-12.0+-000000?style=for-the-badge&logo=apple" alt="macOS 12+" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT" />
  <img src="https://img.shields.io/badge/version-0.2-blueviolet?style=for-the-badge" alt="v0.2" />
  <img src="https://github.com/htooayelwinict/mactail/actions/workflows/ci.yml/badge.svg?style=for-the-badge" alt="CI" />
</p>

---

**mactail** snapshots every `LaunchAgent` and `LaunchDaemon` plist on your Mac, diffs against a saved baseline, and flags suspicious persistence with evidence and rule IDs. It inspects code signatures via `codesign` to classify Apple-signed vs unsigned binaries — all locally, with zero network calls.

```bash
mactail baseline    # snapshot your system
mactail diff        # see what changed since then
```

---

## ✨ Features

- **Baseline + Diff** — snapshot all launchd plists, then diff against the baseline to detect new or modified persistence
- **Code signature inspection** — calls `codesign` to classify Apple-signed, third-party signed, and unsigned binaries
- **Rule engine** — 10 built-in rules covering world-writable plists, DYLD injection, KeepAlive abuse, root in user agents, and more
- **Severity grading** — `low` → `medium` → `high` → `critical` with matching and filtering
- **Output formats** — human-readable Markdown (default) or `--format json` for pipelines
- **Custom state file** — `--db ./my-state.db` to maintain multiple baselines
- **System plists** — `--include-system` to diff against Apple-shipped `/System/Library/Launch*` as a read-only reference
- **Zero network calls** — everything runs locally; no telemetry, no cloud, no phoning home

---

## 🚀 Install

### End users (pipx)

```bash
pipx install mactail
mactail --help
```

### Developers (editable)

```bash
git clone https://github.com/htooayelwinict/mactail.git
cd mactail

uv venv --python 3.13 .venv
uv pip install --python .venv/bin/python -e ".[dev]"
```

Or with `make`:

```bash
make install   # creates .venv with python3.12, installs in editable mode
```

**Requirements:** Python 3.12+, macOS 12+ (Monterey or later).

---

## 📖 Usage

```bash
# Create initial baseline (run once)
mactail baseline

# Diff against baseline (human-readable markdown)
mactail diff

# JSON output for scripting / SIEM ingestion
mactail diff --format json

# Filter by severity
mactail diff --min-severity medium

# Include Apple-shipped system plists as reference
mactail diff --include-system

# Inspect a single plist
mactail show ~/Library/LaunchAgents/com.example.plist

# Use a custom state database
mactail baseline --db ./my-state.db
mactail diff --db ./my-state.db
```

---

## 🔍 Built-in Rules

| Rule ID | Severity | What it detects |
|---|---|---|
| `R-WORLD-WRITABLE` | 🔴 critical | Plist file has world-writable permissions |
| `R-ENV-DYLD` | 🔴 critical | `DYLD_INSERT_LIBRARIES` or `LD_PRELOAD` in EnvironmentVariables |
| `R-PROG-TMP` | 🟠 high | Program path points at `/tmp` or similar |
| `R-RUN-KEEPALIVE-UNSIGNED` | 🟠 high / critical | RunAtLoad+KeepAlive, binary is non-Apple signed or unsigned |
| `R-USERAGENT-ROOT` | 🟠 high | Per-user agent declares `UserName=root` |
| `R-PROG-INTERPRETER` | 🟡 medium | Program invokes `sh`, `bash`, `curl`, `nc`, or `osascript` |
| `R-RUN-KEEPALIVE` | 🟡 medium | RunAtLoad+KeepAlive, binary not found for signature check |
| `R-NO-LABEL` | 🔵 low | Plist has no `Label` key |
| `R-DISABLED-KEEPALIVE` | 🔵 low | `Disabled=true` AND `KeepAlive=true` (contradictory config) |
| `R-NEW-USER-AGENT` | 🔵 low | New user LaunchAgent not present in baseline |

---

## 🏗️ Project Structure

```
mactail/
├── pyproject.toml                  # Metadata, deps, tool config
├── Makefile                        # install / test / lint / run / clean
├── .github/workflows/ci.yml       # CI: lint + tests on Python 3.12 & 3.13
│
├── src/mactail/
│   ├── __init__.py
│   ├── __main__.py                 # python -m mactail
│   ├── cli/
│   │   └── app.py                  # Typer CLI (baseline, diff, show)
│   ├── persistence/
│   │   ├── scanner.py              # Enumerate LaunchAgents/Daemons
│   │   ├── parser.py               # Parse plist → dict
│   │   ├── store.py                # SQLite state storage
│   │   ├── diff.py                 # Diff engine (added/removed/changed)
│   │   └── sigs.py                 # Code signature inspection (codesign)
│   └── rules/
│       ├── __init__.py             # Rule protocol + severity enum
│       └── builtin.py              # 10 built-in detection rules
│
└── tests/
    ├── conftest.py                 # Shared fixtures
    ├── test_cli.py
    ├── test_diff.py
    ├── test_parser.py
    ├── test_rules.py
    ├── test_scanner.py
    ├── test_sigs.py
    └── test_store.py               # 76 tests total
```

---

## 🧪 Development

```bash
# Run tests
make test
# or: .venv/bin/pytest -v

# Lint
make lint
# or: .venv/bin/ruff check .

# Clean caches
make clean
```

### CI

Runs on every push and PR. Two matrices: Python 3.12 and 3.13. Steps:

1. `ruff check .` — lint
2. `pytest -v` — 76 tests, zero tolerance for failures

---

## 📦 Tech Stack

| Layer | Technology |
|-------|-----------|
| CLI | Typer |
| Data modeling | Pydantic v2 |
| State storage | SQLite (stdlib `sqlite3`) |
| Plist parsing | `plistlib` (stdlib) |
| Code signing | `subprocess` → `codesign` |
| Build | Hatchling |
| Lint | Ruff |
| Tests | pytest + pytest-cov |

---

## 🔒 Security

- **Local-only** — no network calls, no telemetry, no cloud
- **Read-only inspection** — `mactail diff` and `mactail show` never modify system files
- **Stdlib persistence** — SQLite via `sqlite3`, plists via `plistlib`; no third-party database drivers
- **codesign subprocess** — only reads signature data; never modifies signatures

---

## 📝 License

[MIT](LICENSE)

---

<p align="center">
  <sub>macOS persistence hunting, one plist at a time.</sub>
</p>

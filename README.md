<p align="center">
  <img src="https://raw.githubusercontent.com/htooayelwinict/mactail/main/docs/logo.svg" width="120" alt="mactail" />
</p>

<p align="center">
  <b style="font-size:1.5em">m a c t a i l</b><br/>
  <sub>Local-first macOS launchd persistence baselining &amp; threat hunting.</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12+" />
  <img src="https://img.shields.io/badge/macOS-12.0+-000000?style=for-the-badge&logo=apple" alt="macOS 12+" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT" />
  <img src="https://img.shields.io/pypi/v/mactail?style=for-the-badge&color=blueviolet" alt="PyPI" />
  <img src="https://github.com/htooayelwinict/mactail/actions/workflows/ci.yml/badge.svg?style=for-the-badge" alt="CI" />
</p>

---

**mactail** snapshots every `LaunchAgent` and `LaunchDaemon` plist on your Mac, diffs against a saved baseline, and flags suspicious persistence with evidence and rule IDs. It inspects code signatures via `codesign` to classify Apple-signed vs unsigned binaries — all locally, with zero network calls.

```bash
mactail baseline    # snapshot your system
mactail diff        # see what changed since then
```

---

## 📑 Contents

- [Install](#-install)
- [Quickstart (60 seconds)](#-quickstart-60-seconds)
- [How it works](#-how-it-works)
- [Walkthroughs](#-walkthroughs)
  - [First-time setup on a clean Mac](#first-time-setup-on-a-clean-mac)
  - [Daily check routine](#daily-check-routine)
  - [Investigating a finding](#investigating-a-finding)
  - [Multiple machines / shared baseline](#multiple-machines--shared-baseline)
- [Recipes](#-recipes)
- [Built-in rules reference](#-built-in-rules-reference)
- [Output formats](#-output-formats)
- [Where things live](#-where-things-live)
- [FAQ](#-faq)
- [Development](#-development)
- [Project structure](#-project-structure)
- [Security & license](#-security--license)

---

## 🚀 Install

Pick one. All put a `mactail` command on your `$PATH`.

### Option A — `uv` (recommended)

```bash
uv tool install mactail
mactail --help
```

Update later:

```bash
uv tool upgrade mactail
```

### Option B — `pipx`

```bash
pipx install mactail
mactail --help
```

### Option C — `pip` (user site)

```bash
python3 -m pip install --user mactail
mactail --help
```

### Option D — From a local clone (developer)

```bash
git clone https://github.com/htooayelwinict/mactail.git
cd mactail
make install   # creates .venv and installs in editable mode
.venv/bin/mactail --help
```

**Requirements:** Python 3.12+, macOS 12+ (Monterey or later). Apple Silicon and Intel both work.

---

## ⚡ Quickstart (60 seconds)

```bash
# 1. Snapshot the system you trust (right after a clean install or known-good state)
mactail baseline

# 2. Time passes. You install stuff, malware shows up, who knows. Check what changed.
mactail diff

# 3. Read the output. Anything in [CRITICAL] or [HIGH] deserves a look.
```

That's the whole loop. Everything else in this README is detail.

---

## 🔍 How it works

```
                  ┌──────────────────────┐
   your Mac  ──▶  │  mactail scan/parse  │  reads every plist under
                  │  (read-only)         │  /Library/LaunchDaemons
                  └──────────┬───────────┘  /Library/LaunchAgents
                             │              ~/Library/LaunchAgents
                             ▼
                  ┌──────────────────────┐
                  │  SQLite state file   │  default: ~/.local/share/mactail/state.db
                  │  (your snapshots)    │  one row per plist, full history
                  └──────────┬───────────┘
                             │
                             ▼  on `mactail diff`
                  ┌──────────────────────┐
                  │  diff + rule engine  │  10 built-in detectors
                  │  (codesign + plist)  │  → Markdown or JSON findings
                  └──────────────────────┘
```

- **No network.** Nothing leaves the machine.
- **No root needed** for user agents. Daemons under `/Library/LaunchDaemons` may require `sudo` to read.
- **Idempotent.** Running `mactail baseline` again is a no-op for unchanged plists and a no-op for an empty state file.
- **Reversible.** Delete the state file to wipe history.

---

## 🧭 Walkthroughs

### First-time setup on a clean Mac

Right after a fresh install — before you add apps, browsers, or run any third-party installer — capture a known-good baseline.

```bash
mactail baseline
# baseline: wrote 87 plists, 0 parse errors -> ~/.local/share/mactail/state.db
```

You should see a number in the dozens (system daemons + a handful of user agents). 0 plists means something is wrong; 500+ means you already have a lot of third-party persistence.

Save the database somewhere safe if you want to compare against it later from a different machine:

```bash
cp ~/.local/share/mactail/state.db ~/Dropbox/mactail-baseline-$(hostname).db
```

### Daily check routine

After installing software, applying updates, or just at the end of the work day:

```bash
mactail diff
```

Sample output:

```
# mactail diff

**new=1 changed=0 removed=0 critical=0 high=1 medium=0 low=0**

## New
- `~/Library/LaunchAgents/com.shady.updater.plist` (label: `com.shady.updater`)
  - [HIGH] **R-RUN-KEEPALIVE-UNSIGNED**: RunAtLoad=true KeepAlive=true; binary is unsigned
```

A clean run prints `new=0 changed=0 removed=0` and no findings. If you see anything in `## New` or `## Changed` that you didn't intentionally install, treat it as suspicious.

### Investigating a finding

Three steps: read the rule, inspect the plist, verify the binary.

```bash
# 1. What is this rule checking? See the table below, or run with --format json for full evidence.
mactail diff --format json | jq '.findings[] | select(.rule_id=="R-RUN-KEEPALIVE-UNSIGNED")'

# 2. Look at the plist itself.
mactail show ~/Library/LaunchAgents/com.shady.updater.plist

# 3. Check the binary it points at.
codesign -dv --verbose=4 /path/to/suspicious/binary 2>&1 | head -20
file /path/to/suspicious/binary
```

If it's malware: `launchctl unload ~/Library/LaunchAgents/com.shady.updater.plist`, then delete the plist and the binary. Then re-run `mactail diff` to confirm `removed=1`.

### Multiple machines / shared baseline

Use a separate state file per machine, or sync a known-good baseline to many machines.

```bash
# On machine A (the "known clean" one):
mactail baseline --db ./team-baseline.db
scp ./team-baseline.db mac2:/tmp/

# On machine B:
mactail diff --db /tmp/team-baseline.db   # shows everything that differs from A
```

For fleet-scale, point the env var at a shared path:

```bash
export MACTAIL_HOME=/Volumes/IR/mactail
mactail baseline
```

---

## 🧂 Recipes

### Only see high/critical findings

```bash
mactail diff --min-severity high
```

### Pipe to a SIEM / grep

```bash
mactail diff --format json | curl -X POST -H 'Content-Type: application/json' -d @- https://siem.example.com/ingest
```

### Watch one user agent over time

```bash
mactail baseline --db ./watch.db
# later...
mactail diff --db ./watch.db --include-system
```

### Include Apple's shipped system plists for context

```bash
mactail diff --include-system
```

These are read-only and never written to your state file.

### Reset state and start over

```bash
rm ~/.local/share/mactail/state.db
mactail baseline
```

### Run inside CI

```yaml
# .github/workflows/persistence-audit.yml
- run: pipx run mactail diff --format json > diff.json
```

---

## 🔎 Built-in rules reference

| Rule ID | Severity | What it detects |
|---|---|---|
| `R-WORLD-WRITABLE` | 🔴 critical | Plist file has world-writable permissions |
| `R-ENV-DYLD` | 🔴 critical | `DYLD_INSERT_LIBRARIES` or `LD_PRELOAD` in `EnvironmentVariables` |
| `R-PROG-TMP` | 🟠 high | Program path points at `/tmp` or similar |
| `R-RUN-KEEPALIVE-UNSIGNED` | 🟠 high / critical | `RunAtLoad=true` + `KeepAlive=true`, binary is non-Apple signed or unsigned |
| `R-USERAGENT-ROOT` | 🟠 high | Per-user agent declares `UserName=root` |
| `R-PROG-INTERPRETER` | 🟡 medium | Program invokes `sh`, `bash`, `curl`, `nc`, or `osascript` |
| `R-RUN-KEEPALIVE` | 🟡 medium | `RunAtLoad=true` + `KeepAlive=true`, binary not found for signature check |
| `R-NO-LABEL` | 🔵 low | Plist has no `Label` key |
| `R-DISABLED-KEEPALIVE` | 🔵 low | `Disabled=true` AND `KeepAlive=true` (contradictory config) |
| `R-NEW-USER-AGENT` | 🔵 low | New user LaunchAgent not present in baseline |

Severity cutoffs: `--min-severity low|medium|high|critical`.

---

## 📤 Output formats

### Markdown (default, human-readable)

Section per category (`## New`, `## Changed`, `## Removed`), one bullet per plist, indented finding lines with `[SEVERITY]` tags.

### JSON (machine-readable)

```bash
mactail diff --format json
```

Shape:

```json
{
  "summary": { "new": 1, "changed": 0, "removed": 0, "by_severity": { "critical": 0, "high": 1, "medium": 0, "low": 0 } },
  "findings": [
    {
      "rule_id": "R-RUN-KEEPALIVE-UNSIGNED",
      "severity": "high",
      "evidence": "RunAtLoad=true KeepAlive=true; binary is unsigned",
      "path": "~/Library/LaunchAgents/com.shady.updater.plist"
    }
  ],
  "parse_errors": []
}
```

---

## 📁 Where things live

| Thing | Location |
|---|---|
| State database | `~/.local/share/mactail/state.db` (override with `--db` or `MACTAIL_HOME`) |
| User agents scanned | `~/Library/LaunchAgents/` |
| System agents | `/Library/LaunchAgents/` |
| System daemons | `/Library/LaunchDaemons/` (read-only with `sudo`) |
| System reference (opt-in) | `/System/Library/LaunchAgents/`, `/System/Library/LaunchDaemons/` |

---

## ❓ FAQ

**Does it modify my system?**
No. `baseline` and `diff` only read. `show` only reads. The only file written is the state DB you point it at.

**Does it phone home?**
No. Zero network calls. `codesign` is the only subprocess, and it only reads signature metadata.

**Do I need root?**
No for user agents and `/Library/LaunchAgents`. Yes for `/Library/LaunchDaemons` if you want full coverage: `sudo mactail baseline`.

**How big does the DB get?**
Roughly 1 KB per plist per run. 100 plists across 1000 runs ≈ 100 MB. Prune with `rm state.db` and re-baseline.

**What if a plist won't parse?**
You see `! path: reason` after `baseline` and a `## Parse errors` section after `diff`. The plist is skipped, not crashed on.

**Is this a replacement for a real EDR?**
No. It's a focused, auditable, local-first baselining tool. Use it alongside, not instead of, commercial tooling.

---

## 🧪 Development

```bash
git clone https://github.com/htooayelwinict/mactail.git
cd mactail
make install   # .venv with Python 3.12+, editable install
make test      # 76 tests
make lint      # ruff
make run       # mactail --help via the venv
```

### CI

GitHub Actions runs `ruff check .` and `pytest -v` on Python 3.12 and 3.13 for every push and PR.

### Release

Bump `version` in `pyproject.toml`, push a tag. The `publish.yml` workflow builds and uploads to PyPI via [trusted publishing](https://docs.pypi.org/trusted-publishers/).

```bash
git tag v0.2.0
git push --tags
```

---

## 🏗️ Project structure

```
mactail/
├── pyproject.toml                  # Metadata, deps, tool config
├── Makefile                        # install / test / lint / run / clean
├── .github/workflows/
│   ├── ci.yml                      # Lint + tests on 3.12 & 3.13
│   └── publish.yml                 # Trusted publishing to PyPI
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
└── tests/                          # 76 tests
```

---

## 🔒 Security & license

- **Local-only** — no network calls, no telemetry, no cloud
- **Read-only inspection** — `mactail diff` and `mactail show` never modify system files
- **Stdlib persistence** — SQLite via `sqlite3`, plists via `plistlib`; no third-party database drivers
- **codesign subprocess** — only reads signature data; never modifies signatures

[MIT](LICENSE)

---

<p align="center">
  <sub>macOS persistence hunting, one plist at a time.</sub>
</p>

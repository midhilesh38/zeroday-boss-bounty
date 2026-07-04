# BOSS Differential Security Auditor

A **read-only** differential security auditing framework. It collects a
structured snapshot of a clean Debian 13 baseline and a modified target
system (BOSS OS), diffs them, and ranks every difference for a human
researcher to manually investigate.

Built for CTF / bug-bounty style manual security research. **It never
exploits anything, never modifies the host, and never generates load.**
Every finding is an **investigation candidate** for manual verification —
never an automatic claim of a vulnerability.

Fully offline: no network access, no paid APIs, no cloud services, no
database, no Docker. Everything runs from one Python script.

## Quick start

```bash
pip install -r requirements.txt

# On a clean Debian 13 machine:
python3 boss_auditor.py scan-baseline

# On the BOSS OS machine (copy profiles/baseline_debian13.json over first):
python3 boss_auditor.py scan-target

# Back on one machine with both profiles present:
python3 boss_auditor.py compare
```

`compare` is the single command that matters: it loads both profiles, runs
the differential engine, classifies and ranks every difference, prints the
top 20 to the terminal, saves `output/diff_results.json`, and generates
`output/report.md`, `output/report.html`, and `output/report.json`.

Total run time for `compare` itself is sub-second (pure Python, no I/O to
the target machines). The two `scan-*` commands are the only steps that
touch the live system, and complete in well under a minute each.

## Commands

| Command | What it does |
|---|---|
| `list-plugins` | Show all registered collector plugins (sanity check before scanning) |
| `scan-baseline` | Scan the current host, save as the Debian 13 baseline profile |
| `scan-target` | Scan the current host, save as the BOSS OS target profile |
| `compare` | Diff + classify + rank + report, all in one step (see below) |
| `report` | Regenerate Markdown/HTML/JSON reports from the last `compare`, without recomputing |
| `top20` | Print the top 20 findings from the last `compare` |

## Pipeline (Phases 3-7)

**Phase 3 — Differential Engine** (`src/boss_auditor/comparison/engine.py`)
Generic, type-aware diff between two `SystemProfile` JSON snapshots.
Dict-of-scalars sections (packages, sysctl, users, sshd directives, PAM
files, file permissions) get key-level new/removed/modified diffing,
recursing into nested dicts. List-of-string sections (SUID/SGID
inventories, running services, process signatures, APT repos) are
diffed as sets, so re-ordering never produces noise. Fully covered by
`tests/test_comparison_engine.py`.

**Phase 4 — Security Intelligence** (`src/boss_auditor/comparison/intelligence.py`)
A transparent, fully offline, rule-based classifier — no ML, no network
call, no paid API. Every difference gets a confidence score (0-100), a
categorical risk level (Critical/High/Medium/Low), a plain-language
explanation of *why it matters* and its *possible impact*, concrete
manual verification steps and commands, CWE mapping where genuinely
applicable, a suggested fix, and a `likely_false_positive` flag. There
are dedicated classifiers for packages, services, SUID/SGID binaries,
sysctl, PAM, sshd_config, users/groups, file permissions, and processes
— the exact focus list from the spec — plus a generic fallback for
anything else. **Nothing in this codebase calls a finding a
"vulnerability"** — enforced by a dedicated test
(`test_no_finding_ever_uses_the_word_vulnerability`).

**Phase 5 — Smart Prioritization** (`src/boss_auditor/comparison/prioritization.py`)
A single, auditable formula turns risk level + confidence + structural
signals (privilege impact, attack surface, persistence, new/removed vs.
modified) into one priority score, then buckets it into a 5-level star
rating (★ to ★★★★★). Likely-false-positive findings are dampened (not
hidden) so they don't crowd out real signal. See the module docstring
for the exact weights — it's deliberately simple enough to explain to a
judge in one sentence per factor.

**Phase 6 — Reports** (`src/boss_auditor/reporting/`)
Three formats generated from the same data: `report.md` (plain
Markdown), `report.html` (self-contained, no CDN/external resources —
opens correctly with zero network access), and `report.json` (every
finding, not just the top 20, for tooling/further analysis). Each
report includes an executive summary, a risk/star/section breakdown,
and full detail for the top 20 findings: evidence (baseline vs.
target), why it matters, manual verification steps and commands, and a
suggested fix.

**Phase 7 — Terminal UI** (`boss_auditor.py`)
The Rich/Typer CLI described above.

## Project layout

```
boss_auditor.py          <- entry point (python3 boss_auditor.py compare)
requirements.txt
config/settings.yaml     <- optional plugin enable/disable, log level
profiles/                <- scan output lands here (baseline_debian13.json, target_bossos.json)
output/                  <- diff_results.json + the three report formats
docs/ARCHITECTURE.md
src/boss_auditor/        <- the actual package (src-layout, see note below)
  core/                  <- config, logging, models, safety allow-list, process runner
  plugins/collectors/    <- 9 read-only collector plugins
  comparison/            <- Phase 3 engine, Phase 4 intelligence, Phase 5 prioritization
  reporting/             <- Phase 6 report renderers
  tests/                 <- 34 tests covering safety, plugins, diffing, and classification
```

*Why `src/boss_auditor/` instead of just `boss_auditor/` at the root?*
So the root-level entry script can be named exactly `boss_auditor.py` as
required, without colliding with a same-named package directory.
`boss_auditor.py` adds `src/` to `sys.path` at startup — everything else
works exactly as if the package were at the top level.

## Safety model

Every collector plugin routes external commands through
`core/safety.py`: a **default-deny, allow-list-only** validator. Only a
curated set of binaries are permitted, and only in read-only
sub-command/flag forms (`systemctl status`, not `restart`; `iptables -L`,
not `-A`). Violations raise `UnsafeOperationError`, which the plugin
runner treats as an isolated per-plugin failure — it never crashes the
overall scan, and it never silently executes something outside the
allow-list. See `docs/ARCHITECTURE.md` for the reasoning.

## Collectors (9 total)

`system_info`, `installed_packages`, `services`, `suid_sgid`, `sysctl`,
`pam`, `ssh_config`, `users_groups`, `file_permissions`, `processes` —
covering every focus area from the spec. Run `python3 boss_auditor.py
list-plugins` to see them all with their enabled/disabled state.

## Running the tests

```bash
python3 -m pytest
```

34 tests covering: the safety allow-list (including that dangerous flags
are actually rejected, not just documented), plugin discovery/execution
and failure isolation, the differential engine's diff semantics, and the
intelligence layer's classification rules (including a hard check that no
finding is ever phrased as a confirmed vulnerability).

## What's intentionally out of scope

Per the competition timeline, the web dashboard, a database layer, and
Docker packaging were explicitly skipped — everything runs from one
Python script with no infrastructure to stand up.

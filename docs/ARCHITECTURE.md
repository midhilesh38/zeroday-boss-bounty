# Architecture — Phases 1-7

```
boss_auditor.py                       <- Phase 7 entry point (src-layout bootstrap + Typer CLI)
config/settings.yaml                  <- plugin enable/disable, log level
profiles/                             <- scan output (baseline_debian13.json, target_bossos.json)
output/                               <- diff_results.json, report.md, report.html, report.json

src/boss_auditor/
  core/
    constants.py      # shared vocabulary + the safety contract, in prose
    exceptions.py      # exception hierarchy
    safety.py           # default-deny command allow-list (the guardrail)
    process.py         # the ONLY sanctioned way to shell out
    models.py           # Pydantic domain models: PluginResult, SystemProfile,
                         #   ChangeType, RiskLevel, StarRating, RiskScore, Finding
    config.py           # YAML -> AppConfig (pydantic)
    logging.py          # Rich-based logging setup
    profile_store.py    # save/load SystemProfile as JSON
  plugins/
    base.py             # CollectorPlugin ABC
    registry.py          # discovery + concurrent execution -> SystemProfile
    collectors/
      system_info.py, packages.py, services.py, suid_sgid.py, sysctl.py,
      pam.py, ssh_config.py, users_groups.py, file_permissions.py, processes.py
  comparison/
    engine.py            # Phase 3: generic type-aware differ -> RawDifference list
    prioritization.py    # Phase 5: priority score + star rating formula
    intelligence.py       # Phase 4: per-section rule-based classifiers -> Finding list
    diff_store.py          # save/load diff_results.json
  reporting/
    summary.py            # shared aggregation (counts by risk/star/section)
    markdown_report.py     # Phase 6: .md renderer
    html_report.py          # Phase 6: self-contained .html renderer (no CDN)
    json_export.py          # Phase 6: .json renderer (every finding, not just top 20)
    __init__.py              # generate_all() orchestrator
  cli.py                   # legacy Phase 1 package-internal CLI (scan/list-plugins);
                            # boss_auditor.py at the project root is the real Phase 7 entry point
  tests/                    # 34 tests
```

## Data flow

```
scan-baseline / scan-target
        |
        v
profiles/*.json  (SystemProfile: identity + per-section PluginResult.data)
        |
        v  compare_profiles()            [Phase 3]
list[RawDifference]  (section, path, change_type, baseline_value, target_value)
        |
        v  build_findings()               [Phase 4 classify + Phase 5 rank, one pass]
list[Finding]  (sorted by priority_score desc)
        |
        +--> output/diff_results.json     (save_diff_results)
        |
        +--> output/report.{md,html,json} (generate_all)
        |
        +--> terminal top-20 table (Rich)
```

## Why a hard-coded allow-list instead of a blocklist? (core/safety.py)

A blocklist has to anticipate every dangerous invocation in advance, which
is exactly the kind of thing that's easy to bypass. An allow-list flips
the failure mode: an unrecognized command fails closed instead of
silently running. Adding a genuinely useful new read-only command costs
one line in `core/safety.py` — small, deliberate friction for a much
stronger guarantee. The validator distinguishes "flag-style" allow-lists
(e.g. `dpkg -l`, `iptables -L` — every dash-prefixed token must be
approved) from "subcommand-style" ones (e.g. `systemctl status`, `docker
ps` — only the first token is a subcommand, the rest are arguments like
unit/container names).

## Why the differential engine treats dicts and lists differently (comparison/engine.py)

Collector plugins produce two shapes: identifier-keyed mappings (package
name -> version/status, username -> account fields, sysctl key -> value)
and flat lists of strings (SUID paths, running service names, process
signatures). Mappings get key-level new/removed/modified diffing,
recursing into nested dicts. Lists get treated as sets, because ordering
and duplicates in something like a process list carry no security
meaning and would otherwise generate diff noise on every run.

## Why prioritization is a transparent formula, not a model (comparison/prioritization.py)

`priority_score = risk_weight(risk_level) * (confidence/100) + deviation_bonus
                  + privilege_bonus + attack_surface_bonus + persistence_bonus`,
then dampened if `likely_false_positive`. Every term is a small integer a
person can trace by hand. This matters for a competition context: a judge
(or the researcher, at 2am before a deadline) can read
`comparison/prioritization.py` top to bottom and know exactly why finding
#1 outranked finding #2 — no black box, nothing to "trust."

## Why Phase 4 classification is rule-based rather than a single generic template

A single generic "this field changed" template would be technically
correct but not useful — a researcher scanning 200+ raw differences needs
the tool to already know that a new SUID binary is categorically more
urgent than a new package, and that `PermitRootLogin yes` is a much
sharper signal than `PermitRootLogin` merely being *present*. Each
section classifier encodes exactly one team's worth of "what would an
experienced Debian security reviewer flag first" — see
`comparison/intelligence.py` module docstring and the curated keyword/
directive tables at the top of that file for the full rule set.

## Plugin result states

| Status            | Meaning                                                    |
|-------------------|-------------------------------------------------------------|
| `ok`              | Collected successfully                                      |
| `partial`         | Reserved for plugins that collect some but not all sub-data  |
| `failed`          | Plugin raised an exception (missing binary, permission, etc) |
| `skipped_unsafe`  | Plugin tried to run a command outside the allow-list         |
| `not_applicable`  | Reserved for plugins that don't apply to a given system       |

A `failed` or `skipped_unsafe` result for one plugin never aborts the rest
of the scan. A section that failed on either side is excluded from
diffing entirely (rather than reported as "everything removed"), and
instead surfaces as a single "Collection Coverage Gap" finding so the
researcher knows that section wasn't actually compared.

## Known simplifications (given the competition timeline)

- No web dashboard, no database, no Docker — everything is one script
  plus JSON files on disk, per the explicit scope cut.
- Version-drift classification (packages, e.g.) doesn't parse semantic
  versions to detect "downgrade vs. upgrade" — it flags the difference
  and lets the researcher judge direction, to avoid overclaiming.
- Process-list diffing intentionally excludes PID/PPID and full argv
  (only user+comm are captured) to keep the signal-to-noise ratio usable
  across two independent scans; this is documented in
  `plugins/collectors/processes.py` and reflected in the low default
  confidence/likely-false-positive bias in its classifier.

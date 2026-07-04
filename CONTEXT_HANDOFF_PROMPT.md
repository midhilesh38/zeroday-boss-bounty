# CONTEXT HANDOFF PROMPT — TEAM ZERODAY BOSS OS BUG BOUNTY 2026
### Paste this entire block into a new Claude/ChatGPT chat if your current session runs out

---

I'm competing in a Linux security bug bounty competition called "BOSS OS Bug Bounty Programme 2026" 
organized by CDAC/NRCFOSS in India, July 7-8 2026 in Chennai. Here is my full context so you can 
help me immediately without needing to re-explain everything.

## COMPETITION DETAILS

- Target: BOSS GNU/Linux 11.0 (Indian government Debian-based OS, made by CDAC)
- Duration: 36 hours, across 11 venues nationally
- Format: find and report security vulnerabilities, submit via SSM portal
- Problem Statements (PS): 10 categories + "Others"
  - PS-01 Kernel and System Call Security
  - PS-02 Authentication, Access Control, and Privilege Management
  - PS-03 Package Management and Software Supply Chain
  - PS-04 Network Stack, Services, and Firewall
  - PS-05 Boot Process, GRUB, and Secure Boot
  - PS-06 Desktop Environment and GUI Layer
  - PS-07 File System, Permissions, and Storage
  - PS-08 Logging, Auditing, and Monitoring
  - PS-09 Cryptographic Implementation and Configuration
  - PS-10 Containerisation, Virtualisation, and Namespace Security
- Scoring: Critical=10pts/₹10,000, High=8pts/₹5,000, Medium=5pts/₹2,000, Low=2pts
- Prizes: 1st ₹1,00,000, 2nd ₹75,000, 3rd ₹50,000 + CVE recognition
- Rules: read-only testing only, no DoS, no real system attacks, responsible disclosure required

## MY TEAM — "Team ZeroDay"

- **Midhilesh (me)**: Complete beginner in cybersecurity, "vibe coder" — I direct AI to write 
  scripts/tools rather than coding myself. I use Kali Linux (already installed via VirtualBox) 
  as my attack machine. My assigned domains: PS-02, PS-07, PS-08.
- **Mageshwaran**: Knows basic Python/C coding. Assigned domains: PS-03, PS-04, PS-09.
- **Darshini**: Has theoretical kernel knowledge (no hands-on practice yet). Assigned domain: PS-01.

All three of us started from beginner level and have been preparing since around July 1st, 2026.

## MY GITHUB REPO (everything is backed up here)

`https://github.com/midhilesh38/zeroday-boss-bounty`

Contains:
- `boss_scanner_v2.py` — custom Python scanner I built, verified findings only (low false 
  positives), covers PS-02/07/08 specifically. Checks: /etc/shadow readability, empty passwords, 
  NOPASSWD sudo, SSH root login/password auth config, account lockout policy, PAM nullok, 
  password expiry, world-writable files/SUID binaries, cron permissions, auditd/rsyslog status, 
  auth.log existence, log file permissions, journald persistence, logrotate config.
- `boss_audit_scanner.py` — second scanner covering PS-02/04/07/09/10 (network, crypto, 
  containers) — checks firewall status, listening ports, SSH ciphers, TLS cert key sizes, 
  Docker socket permissions, SUID binaries, world-writable files, PAM config.
- `src/boss_auditor/` + `boss_auditor.py` — the most advanced tool: "BOSS Differential Security 
  Auditor". Scans a clean Debian baseline AND BOSS OS target, then DIFFS them to find anything 
  CDAC changed/added/removed. Commands: `scan-baseline`, `scan-target`, `compare`, `report`, 
  `top20`, `list-plugins`. Outputs star-rated findings (★ to ★★★★★) with confidence scores 
  (0-100), CWE mappings, never claims "vulnerability" — only "investigation candidate". Tested 
  successfully 3x with injected bugs (fake UID-0 backdoor account, world-writable /etc/sudoers.d, 
  SSH PermitRootLogin change) — correctly identified all as Critical/High with 75-95% confidence, 
  correctly flagged process/service snapshot noise as likely false positives. Runs in ~2-6 seconds.
- `chain_report_template.txt` — pre-written CRITICAL severity bug report template that chains 
  4 vulnerabilities together (no account lockout + password never expires + no auth logging + 
  no auditd = complete undetectable system compromise). Ready to fill in with real BOSS OS 
  evidence and submit.
- `AI_PROMPT_LIBRARY.md` — 8 portable prompts for verifying findings, writing reports, chaining 
  bugs, etc. — usable with any AI with zero prior context needed.
- `COMPETITION_START_CHECKLIST.md` — minute-by-minute first-60-minutes competition day plan.
- 3 PDF guides (one per team member) — full beginner-friendly guides with tool installation, 
  7-day prep plans, cheat sheets, bug report templates.

## KEY RESEARCH FINDINGS (OSINT on official bosslinux.in)

1. **Publicly documented default credential**: BOSS live-boot uses `username: boss password: live` 
   — must test this immediately on competition day, could be an instant CRITICAL if unchanged.
2. **BOSS Linux is historically Debian-based with version lag**: BOSS 10 "Pragya" = Debian 12 
   (Bookworm), BOSS 9 "Urja" = Debian 11, BOSS 8 "Unnati" = Debian 10. My differential auditor's 
   practice baseline was built on Debian 13 (Trixie) — if BOSS OS 11.0 actually tracks Debian 12, 
   there may be a version mismatch affecting the differential comparison accuracy. Need to verify 
   `/etc/os-release` on the actual BOSS OS 11.0 VM first thing on competition day.
3. Official security repo pattern: `deb http://packages.bosslinux.in/security-updates <codename> 
   main contrib non-free` — worth checking if BOSS OS 11.0 has this configured correctly.
4. BOSS ships Synaptic Package Manager by default.

## MY PRACTICE ENVIRONMENT

- VirtualBox with Kali Linux (pre-installed) as attack machine
- Debian 13 "Trixie" VM named "BOSS-Practice" as practice target (simulates BOSS OS)
- Successfully practiced: manual security checks, LinPEAS, Lynis, Hydra password testing, 
  journalctl log analysis, all 3 custom tools above
- Found and verified 4+ real bugs on practice Debian VM (auditd missing, auth.log missing, 
  PASS_MAX_DAYS=99999, no account lockout) — confirmed via manual verification, not just 
  scanner output

## MY STRATEGY

- **Plan A**: Run all 3 scanners first (differential auditor → scanner v2 → multi-domain scanner), 
  cross-reference findings, verify manually, write reports as I go (not batched at the end)
- **Plan B**: Hunt BOSS-specific custom packages/services (things generic tools won't know about) 
  — check `dpkg -l | grep -i boss`, look for CDAC-specific services, try default credentials
- **Plan C**: If bugs are scarce, focus on REPORT QUALITY over quantity — CVSS scores, CWE numbers, 
  government-specific impact language, chained vulnerability narratives
- Bug chaining is my highest-leverage skill — combining multiple MEDIUM findings into one CRITICAL 
  narrative multiplies points

## WHAT I NEED HELP WITH NOW

[DESCRIBE YOUR CURRENT QUESTION/TASK HERE]

---

Please continue helping me as if you already knew all of this. Don't ask me to re-explain the 
competition rules or my team setup — just help with the specific task above.

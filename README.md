# Team ZeroDay — BOSS OS Bug Bounty 2026 Toolkit

Everything our team needs for the competition, in one place.

---

## How to get everything (do this first, on your laptop)

```bash
git clone https://github.com/midhilesh38/zeroday-boss-bounty.git
cd zeroday-boss-bounty
pip install -r requirements.txt --break-system-packages
```

That's it — you now have every tool, template, and guide on your machine.

---

## What's inside

| File | What it's for | Who should use it |
|---|---|---|
| `midhilesh_guide (1).pdf` | Midhilesh's full guide — PS-02, PS-07, PS-08 | Midhilesh |
| `darshini_kernel_guide.pdf` | Darshini's full guide — PS-01 | Darshini |
| `mageshwaran_kernel_guide.pdf` | Mageshwaran's full guide — PS-03, PS-04, PS-09 | Mageshwaran |
| `boss_scanner_v2.py` | Fast scanner, verified findings, PS-02/07/08 | Midhilesh (primary) |
| `boss_audit_scanner.py` | Broader scanner, PS-02/04/07/09/10 | Anyone, especially Mageshwaran |
| `src/boss_auditor/` + `boss_auditor.py` | Differential auditor — compares BOSS OS vs clean Debian, finds custom changes | Everyone, run first |
| `chain_report_template.txt` | Pre-written CRITICAL bug report chaining 4 vulns together | Reference when writing reports |
| `AI_PROMPT_LIBRARY.md` | Copy-paste prompts for any AI if verifying findings or writing reports | Everyone, backup tool |
| `COMPETITION_START_CHECKLIST.md` | Minute-by-minute plan for first hour of competition | Everyone, read before competition |
| `CONTEXT_HANDOFF_PROMPT.md` | Paste into a new AI chat if your current one runs out of messages | Everyone |

---

## How to run the tools (on the actual BOSS OS VM, competition day)

**Step 1 — Differential auditor (run this first, on your own clean Debian VM, BEFORE competition):**
```bash
python3 boss_auditor.py scan-baseline
```

**Step 2 — On competition day, on BOSS OS itself:**
```bash
python3 boss_auditor.py scan-target
python3 boss_auditor.py compare
python3 boss_auditor.py top20
```

**Step 3 — Run the scanners:**
```bash
sudo python3 boss_scanner_v2.py
sudo python3 boss_audit_scanner.py --top 15
```

**Step 4 — Cross-check all outputs, verify manually, then write reports.**

---

## If you're stuck and need AI help mid-competition

1. Open `AI_PROMPT_LIBRARY.md`
2. Copy the prompt that matches your situation (verify a finding, write a report, chain bugs, etc.)
3. Fill in your actual findings/evidence
4. Paste into any AI chat (Claude, ChatGPT, whatever isn't rate-limited)

If your main AI chat runs out of messages entirely, use `CONTEXT_HANDOFF_PROMPT.md` in a new chat first.

---

## Before competition day — everyone should

- [ ] `git clone` this repo on your laptop
- [ ] Read your own PDF guide fully
- [ ] Test that `boss_auditor.py`, `boss_scanner_v2.py`, `boss_audit_scanner.py` all run on your practice VM
- [ ] Read `COMPETITION_START_CHECKLIST.md`
- [ ] Know your assigned Problem Statements cold

---

**Team ZeroDay · BOSS OS Bug Bounty 2026 · July 7-8 · Chennai · Let's win this 🏆**

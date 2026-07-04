# Competition Start Checklist — First 60 Minutes

> Team ZeroDay · BOSS OS Bug Bounty 2026 · July 7-8, Chennai

---

## Minute 0-5 — Setup

- [ ] Connect laptop to venue WiFi/network
- [ ] Get BOSS OS VM (download or provided)
- [ ] Load into VirtualBox
- [ ] Boot BOSS OS
- [ ] Note the IP:
```bash
ip addr show
```

---

## Minute 5-8 — Try the known default credential FIRST

```bash
ssh boss@<BOSS_IP>
# password: live
```

> This is a **publicly documented** default credential from the official BOSS Linux live-boot docs. If it works — instant CRITICAL finding. Screenshot immediately.

---

## Minute 8-10 — Check OS identity

```bash
cat /etc/os-release
uname -a
```

Confirms exact BOSS version + Debian base (12 or 13) — tells you which baseline VM to compare against.

| BOSS historically tracks | Debian base |
|---|---|
| BOSS 10 "Pragya" | Debian 12 (Bookworm) |
| BOSS 9 "Urja" | Debian 11 (Bullseye) |
| BOSS 8 "Unnati" | Debian 10 (Buster) |

If BOSS 11.0 follows the pattern, verify before trusting differential comparisons.

---

## Minute 10-12 — Get your tools ready

```bash
git clone https://github.com/midhilesh38/zeroday-boss-bounty.git
cd zeroday-boss-bounty
pip install -r requirements.txt --break-system-packages
```

---

## Minute 12-15 — Run differential auditor (primary tool)

```bash
python3 boss_auditor.py scan-target
python3 boss_auditor.py compare
```

> Requires a matching baseline profile (`baseline_debian13.json` or equivalent). If BOSS is Debian-12-based and your baseline is Debian 13, note the mismatch — rely more heavily on the manual scanners below.

---

## Minute 15-18 — Run scanner v2

```bash
sudo python3 boss_scanner_v2.py
```

Covers: PS-02, PS-07, PS-08

---

## Minute 18-20 — Run multi-domain scanner

```bash
sudo python3 boss_audit_scanner.py --top 15
```

Covers: PS-02, PS-04, PS-07, PS-09, PS-10

---

## Minute 20-30 — Cross-reference all 3 tool outputs

- [ ] Cross off obvious false positives (process/service snapshot noise)
- [ ] Highlight anything flagged by **2+ tools** — high confidence signal
- [ ] Pick **top 5 candidates** to verify first

---

## Minute 30-45 — Manual verification of top candidates

- [ ] Run the exact verification command each tool suggests
- [ ] Screenshot every piece of proof
- [ ] Do NOT trust severity labels blindly — confirm the actual impact

---

## Minute 45-60 — Write and submit first reports

- [ ] Use the bug report template (`chain_report_template.txt` as reference format)
- [ ] Submit as you go — don't batch everything for the end
- [ ] One report per confirmed bug

---

## After Minute 60

Settle into the 36-hour rhythm:

```
Hour 1-3:    Verify + chain findings together
Hour 3-10:   Deep manual investigation on top findings
Hour 10-20:  Hunt for BOSS-specific customizations
Hour 20-30:  Report writing + polish
Hour 30-34:  Fill gaps, re-check missed areas
Hour 34-36:  Final review + submit everything
```

---

## Golden Rule

**Do not skip ahead.** Credential check first, OS identity second — every later step depends on those two facts.

---

**Team ZeroDay · BOSS OS Bug Bounty 2026 · Go win it! 🏆**

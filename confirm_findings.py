#!/usr/bin/env python3
"""
confirm_findings.py

Reads diff_results.json (output of boss_auditor.py compare) and attempts
LIVE re-verification of specific finding types by actually running the
check again on THIS machine right now — not just trusting the label
that was assigned during classification.

This closes the gap between "the tool flagged this" and "this is
actually true right now, verified with fresh evidence."

Every finding still ends in one of three states:
    CONFIRMED           - freshly verified, evidence collected right now
    NEEDS_MANUAL_CHECK  - no automated re-verification exists for this
                          finding type; a human must check it
    LIKELY_FALSE_POS    - live re-check contradicts the original finding

This tool NEVER says "vulnerability" or "confirmed vulnerability" --
only "confirmed" as in "confirmed to still be true right now."
The human researcher still decides what to report and how to phrase it.

Usage:
    python3 confirm_findings.py                      # uses output/diff_results.json
    python3 confirm_findings.py --input other.json    # custom path
    python3 confirm_findings.py --json out.json       # also save results as JSON
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone


# --------------------------------------------------------------------------
# Colors
# --------------------------------------------------------------------------
RED    = '\033[91m'; YELLOW = '\033[93m'; GREEN = '\033[92m'
BLUE   = '\033[94m'; CYAN   = '\033[96m'; BOLD  = '\033[1m'
RESET  = '\033[0m'


def run(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, shell=isinstance(cmd, str),
                            capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except Exception:
        return "", 1


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class ConfirmationResult:
    finding_id: str
    title: str
    original_risk: str
    status: str              # CONFIRMED / NEEDS_MANUAL_CHECK / LIKELY_FALSE_POS
    live_evidence: str
    note: str


# --------------------------------------------------------------------------
# Per-finding-type live re-verifiers
# --------------------------------------------------------------------------
# Each verifier looks at a finding's section/path/title and, if it knows
# how to re-check that specific thing live, does so and returns a
# ConfirmationResult. If it doesn't recognize the finding type, return None
# so the orchestrator falls back to NEEDS_MANUAL_CHECK.

def verify_new_uid0_account(finding):
    """Section: users_groups, title contains 'New UID 0 account'"""
    title = finding.get("title", "")
    if "UID 0 account" not in title:
        return None

    # Extract username from title: "New UID 0 account: <name>"
    try:
        username = title.split(":")[-1].strip()
    except Exception:
        return None

    out, rc = run(["getent", "passwd", username])
    if rc == 0 and out:
        parts = out.split(":")
        if len(parts) > 2 and parts[2] == "0":
            return ConfirmationResult(
                finding_id=finding.get("finding_id", ""),
                title=title,
                original_risk=finding.get("risk_level", ""),
                status="CONFIRMED",
                live_evidence=f"getent passwd {username}\n{out}\n"
                               f"UID field = 0, confirmed root-equivalent RIGHT NOW.",
                note="Account still exists with UID 0 at time of this check."
            )
        else:
            return ConfirmationResult(
                finding_id=finding.get("finding_id", ""),
                title=title,
                original_risk=finding.get("risk_level", ""),
                status="LIKELY_FALSE_POS",
                live_evidence=f"getent passwd {username}\n{out}\n"
                               f"UID is NOT 0 currently.",
                note="Account exists but UID no longer matches original finding."
            )
    else:
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="LIKELY_FALSE_POS",
            live_evidence=f"getent passwd {username}\n(no such account found)",
            note="Account no longer exists -- may have been fixed, or was transient."
        )


def verify_world_writable_path(finding):
    """Section: file_permissions, title contains 'world-writable'"""
    title = finding.get("title", "")
    if "world-writable" not in title.lower():
        return None

    path = finding.get("path", "") or finding.get("evidence", {}).get("path", "")
    # try to extract a path from the title if not in structured fields
    if not path:
        for token in title.split():
            if token.startswith("/"):
                path = token.rstrip(":")
                break
    if not path:
        return None

    out, rc = run(["stat", "-c", "%a %U %G", path])
    if rc != 0:
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="NEEDS_MANUAL_CHECK",
            live_evidence=f"stat {path} -> could not stat (path may not exist here)",
            note="Path not found on this machine -- verify path resolution manually."
        )

    perm_str = out.split()[0] if out else ""
    is_world_writable_now = len(perm_str) == 3 and int(perm_str[-1]) & 0o2

    if is_world_writable_now:
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="CONFIRMED",
            live_evidence=f"stat -c '%a %U %G' {path}\n{out}\n"
                           f"World-writable bit is SET right now.",
            note="Path is still world-writable at time of this check."
        )
    else:
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="LIKELY_FALSE_POS",
            live_evidence=f"stat -c '%a %U %G' {path}\n{out}\n"
                           f"World-writable bit is NOT set now.",
            note="Permissions have changed since the scan, or original finding was transient."
        )


def verify_sshd_directive(finding):
    """Section: ssh_config, title contains 'New sshd_config directive'"""
    title = finding.get("title", "")
    if "sshd_config directive" not in title:
        return None

    try:
        directive = title.split(":")[-1].strip()
    except Exception:
        return None

    out, rc = run(["sshd", "-T"])
    if rc != 0 or not out:
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="NEEDS_MANUAL_CHECK",
            live_evidence="`sshd -T` failed or returned nothing "
                          "(may need root, or sshd not installed here).",
            note="Could not query effective sshd configuration live."
        )

    directive_lower = directive.lower()
    matching_lines = [l for l in out.splitlines() if l.lower().startswith(directive_lower)]
    if matching_lines:
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="CONFIRMED",
            live_evidence=f"sshd -T | grep -i {directive}\n" + "\n".join(matching_lines),
            note="Directive confirmed present in the EFFECTIVE running sshd config right now."
        )
    else:
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="NEEDS_MANUAL_CHECK",
            live_evidence=f"sshd -T output did not contain a line for '{directive}'",
            note="Directive not found in effective config -- may use a different keyword casing."
        )


def verify_auditd_missing(finding):
    """Title contains 'auditd' and ('not installed' or 'not running')"""
    title = finding.get("title", "")
    if "auditd" not in title.lower():
        return None

    active_out, _ = run(["systemctl", "is-active", "auditd"])
    installed_out, _ = run("dpkg -l auditd 2>/dev/null | grep '^ii'")

    if active_out.strip() == "active":
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="LIKELY_FALSE_POS",
            live_evidence=f"systemctl is-active auditd -> active",
            note="auditd IS running right now -- original finding may be stale."
        )
    else:
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="CONFIRMED",
            live_evidence=f"systemctl is-active auditd -> {active_out or '(inactive/not found)'}\n"
                          f"dpkg -l auditd -> {installed_out or '(not installed)'}",
            note="auditd is confirmed not active right now."
        )


def verify_no_firewall(finding):
    """Title contains 'firewall' and 'no active'"""
    title = finding.get("title", "")
    if "firewall" not in title.lower():
        return None

    nft_out, _ = run(["nft", "list", "ruleset"])
    ipt_out, _ = run(["iptables", "-L", "-n"])

    has_nft_rules = bool(nft_out.strip())
    has_ipt_rules = len(ipt_out.strip().splitlines()) > 8 if ipt_out else False

    if not has_nft_rules and not has_ipt_rules:
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="CONFIRMED",
            live_evidence=f"nft list ruleset -> empty\n"
                          f"iptables -L -n -> {len(ipt_out.splitlines()) if ipt_out else 0} lines "
                          f"(no substantial rules)",
            note="No active firewall ruleset confirmed right now."
        )
    else:
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="LIKELY_FALSE_POS",
            live_evidence=f"nft rules present: {has_nft_rules}, iptables rules present: {has_ipt_rules}",
            note="Firewall rules ARE present now -- original finding may be stale."
        )


def verify_empty_password_account(finding):
    """Title contains 'empty password'"""
    title = finding.get("title", "")
    if "empty password" not in title.lower():
        return None

    out, rc = run(["cat", "/etc/shadow"])
    if rc != 0:
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="NEEDS_MANUAL_CHECK",
            live_evidence="Cannot read /etc/shadow (need root).",
            note="Re-run this analyzer with sudo to verify live."
        )

    empty_accounts = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) > 1 and parts[1] == "":
            empty_accounts.append(parts[0])

    if empty_accounts:
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="CONFIRMED",
            live_evidence=f"Accounts with empty password field right now: {', '.join(empty_accounts)}",
            note="Confirmed live against /etc/shadow."
        )
    else:
        return ConfirmationResult(
            finding_id=finding.get("finding_id", ""),
            title=title,
            original_risk=finding.get("risk_level", ""),
            status="LIKELY_FALSE_POS",
            live_evidence="No accounts with empty password field found right now.",
            note="May have been fixed since original scan."
        )


# List of all verifiers -- the orchestrator tries each until one matches
VERIFIERS = [
    verify_new_uid0_account,
    verify_world_writable_path,
    verify_sshd_directive,
    verify_auditd_missing,
    verify_no_firewall,
    verify_empty_password_account,
]


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def load_findings(path):
    with open(path) as f:
        data = json.load(f)
    # diff_results.json structure may nest findings under a key -- handle
    # both a bare list and a dict with a "findings" key defensively.
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings", data.get("results", []))
    return []


def confirm_all(findings):
    results = []
    for f in findings:
        result = None
        for verifier in VERIFIERS:
            try:
                result = verifier(f)
            except Exception as e:
                result = None
            if result is not None:
                break

        if result is None:
            result = ConfirmationResult(
                finding_id=f.get("finding_id", f.get("id", "unknown")),
                title=f.get("title", "Untitled finding"),
                original_risk=f.get("risk_level", f.get("severity", "unknown")),
                status="NEEDS_MANUAL_CHECK",
                live_evidence="No automated live re-verification exists for this finding type.",
                note="Verify by hand using the original finding's suggested verification commands."
            )
        results.append(result)
    return results


def status_color(status):
    return {
        "CONFIRMED": GREEN + BOLD,
        "NEEDS_MANUAL_CHECK": YELLOW + BOLD,
        "LIKELY_FALSE_POS": RED + BOLD,
    }.get(status, RESET)


def print_results(results):
    confirmed = [r for r in results if r.status == "CONFIRMED"]
    needs_check = [r for r in results if r.status == "NEEDS_MANUAL_CHECK"]
    false_pos = [r for r in results if r.status == "LIKELY_FALSE_POS"]

    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  FINDING CONFIRMATION ANALYZER -- LIVE RE-VERIFICATION{RESET}")
    print(f"{BOLD}{'='*70}{RESET}\n")

    print(f"{GREEN}{BOLD}  CONFIRMED right now      : {len(confirmed)}{RESET}")
    print(f"{YELLOW}{BOLD}  NEEDS MANUAL CHECK       : {len(needs_check)}{RESET}")
    print(f"{RED}{BOLD}  LIKELY FALSE POSITIVE NOW : {len(false_pos)}{RESET}")
    print(f"{BOLD}{'='*70}{RESET}\n")

    for group_name, group in [
        ("CONFIRMED -- these are verified true right now, prioritize writing reports for these", confirmed),
        ("NEEDS MANUAL CHECK -- no automated re-check exists, verify by hand", needs_check),
        ("LIKELY FALSE POSITIVE NOW -- re-check contradicted the original finding", false_pos),
    ]:
        if not group:
            continue
        print(f"\n{BOLD}--- {group_name} ---{RESET}\n")
        for r in group:
            col = status_color(r.status)
            print(f"{col}[{r.status}]{RESET} {r.title}")
            print(f"    Original risk label: {r.original_risk}")
            print(f"    Live evidence:")
            for line in r.live_evidence.splitlines():
                print(f"      {line}")
            print(f"    Note: {r.note}\n")

    print(f"{BOLD}{'='*70}{RESET}")
    print("Reminder: 'CONFIRMED' means the underlying fact is verified true")
    print("RIGHT NOW on this machine -- it does not mean 'confirmed vulnerability'.")
    print("You still decide severity, impact, and whether to report it.")
    print(f"{BOLD}{'='*70}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Live re-verification analyzer for boss_auditor.py findings")
    parser.add_argument("--input", default="output/diff_results.json",
                         help="Path to diff_results.json (default: output/diff_results.json)")
    parser.add_argument("--json", metavar="FILE",
                         help="Also write confirmation results as JSON to this file")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"{RED}[!] Input file not found: {args.input}{RESET}", file=sys.stderr)
        print(f"    Run 'python3 boss_auditor.py compare' first to generate it.",
              file=sys.stderr)
        sys.exit(1)

    if os.geteuid() != 0:
        print(f"{YELLOW}[!] Not running as root -- some live checks "
              f"(shadow file, sudoers) will be limited. "
              f"Re-run with sudo for full coverage.{RESET}\n", file=sys.stderr)

    findings = load_findings(args.input)
    if not findings:
        print(f"{YELLOW}[!] No findings found in {args.input}{RESET}")
        sys.exit(0)

    results = confirm_all(findings)
    print_results(results)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(
                {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "source_file": args.input,
                    "results": [asdict(r) for r in results],
                },
                f,
                indent=2,
            )
        print(f"[+] JSON written to {args.json}")


if __name__ == "__main__":
    main()

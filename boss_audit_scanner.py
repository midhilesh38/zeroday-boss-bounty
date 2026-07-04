#!/usr/bin/env python3
"""
boss_audit_scanner.py

Standalone, read-only audit scanner for the BOSS OS Bug Bounty (Debian Trixie
based) environment. Designed to run INSIDE the officially provided VM only.

It performs non-destructive checks across five domains mapped to the
programme's problem statements:

    PS-02  Authentication, Access Control, and Privilege Management
    PS-04  Network Stack, Services, and Firewall
    PS-07  File System, Permissions, and Storage
    PS-09  Cryptographic Implementation and Configuration
    PS-10  Containerisation, Virtualisation, and Namespace Security

Every check is READ-ONLY: it inspects configuration, permissions, and running
state, and never modifies the system, exploits anything, or sends network
traffic to remote hosts. It is meant to surface CANDIDATES for you to
manually confirm -- not to auto-generate a verdict.

Usage:
    sudo python3 boss_audit_scanner.py                 # run all checks
    sudo python3 boss_audit_scanner.py --ps PS-02 PS-10 # only specific PS
    sudo python3 boss_audit_scanner.py --json out.json  # also save JSON
    sudo python3 boss_audit_scanner.py --top 3           # print top 3 by
                                                          # severity guess

Output is intentionally verbose and structured so you can paste an
individual finding into an AI chat and ask: "give me manual steps to
confirm this, and tell me what would make it a false positive."

Only use this against systems you own or are explicitly authorized to test
(e.g. the officially provided BOSS OS bug-bounty VM).
"""

import argparse
import grp
import json
import os
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    ps_category: str
    domain: str
    title: str
    severity_guess: str          # critical / high / medium / low / info
    evidence: str
    why_it_matters: str
    suggested_next_step: str
    check_id: str
    confidence: str = "candidate"  # always "candidate" -- never "confirmed"

    def sort_key(self):
        return SEVERITY_ORDER.get(self.severity_guess, 0)


class Report:
    def __init__(self):
        self.findings: list[Finding] = []
        self.errors: list[str] = []

    def add(self, finding: Finding):
        self.findings.append(finding)

    def add_error(self, msg: str):
        self.errors.append(msg)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def run(cmd, timeout=5):
    """Run a local, read-only shell command and return stdout (or '')."""
    try:
        result = subprocess.run(
            cmd, shell=isinstance(cmd, str), capture_output=True,
            text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""


def file_exists(path):
    return os.path.exists(path)


def is_world_writable(path):
    try:
        st = os.stat(path)
        return bool(st.st_mode & stat.S_IWOTH)
    except FileNotFoundError:
        return False


def perms_octal(path):
    try:
        return oct(os.stat(path).st_mode & 0o777)
    except FileNotFoundError:
        return None


# --------------------------------------------------------------------------
# PS-02: Authentication, Access Control, Privilege Management
# --------------------------------------------------------------------------

def check_ps02(report: Report):
    domain = "Authentication & Access Control"

    # 1. World-writable sudoers or sudoers.d entries
    for path in ["/etc/sudoers"] + [
        os.path.join("/etc/sudoers.d", f)
        for f in (os.listdir("/etc/sudoers.d") if os.path.isdir("/etc/sudoers.d") else [])
    ]:
        if file_exists(path) and is_world_writable(path):
            report.add(Finding(
                ps_category="PS-02",
                domain=domain,
                title=f"World-writable sudoers file: {path}",
                severity_guess="critical",
                evidence=f"Permissions: {perms_octal(path)}",
                why_it_matters="A world-writable sudoers entry lets any local user "
                                "grant themselves root privileges by editing the file.",
                suggested_next_step="Confirm by editing the file as a low-priv user "
                                     "in a test session; check if 'sudo -l' reflects the change.",
                check_id="ps02-sudoers-world-writable",
            ))

    # 2. Check for NOPASSWD entries in sudoers (broad privilege grants)
    sudoers_content = run(["cat", "/etc/sudoers"]) if os.access("/etc/sudoers", os.R_OK) else ""
    if "NOPASSWD" in sudoers_content:
        matches = [l for l in sudoers_content.splitlines() if "NOPASSWD" in l and not l.strip().startswith("#")]
        if matches:
            report.add(Finding(
                ps_category="PS-02",
                domain=domain,
                title="NOPASSWD sudo entries present",
                severity_guess="medium",
                evidence="\n".join(matches[:10]),
                why_it_matters="NOPASSWD entries allow privilege escalation without "
                                "re-authentication; scope and necessity should be verified.",
                suggested_next_step="Check whether the granted command(s) can be abused "
                                     "to spawn a shell or write to sensitive files "
                                     "(see GTFOBins-style privesc patterns).",
                check_id="ps02-sudo-nopasswd",
            ))

    # 3. SUID/SGID binaries outside standard allowlist
    suid_output = run(["find", "/", "-xdev", "-perm", "-4000", "-type", "f"], timeout=20)
    if suid_output:
        binaries = suid_output.splitlines()
        report.add(Finding(
            ps_category="PS-02",
            domain=domain,
            title=f"{len(binaries)} SUID binaries found on root filesystem",
            severity_guess="info",
            evidence="\n".join(binaries[:25]) + ("\n... (truncated)" if len(binaries) > 25 else ""),
            why_it_matters="SUID binaries run with owner (often root) privileges. "
                            "Non-standard or custom SUID binaries are common privesc vectors.",
            suggested_next_step="Cross-reference this list against a known-good Debian "
                                 "Trixie baseline; investigate any binary that isn't "
                                 "part of the base install or that has an unusual path.",
            check_id="ps02-suid-binaries",
        ))

    # 4. PAM configuration weaknesses (e.g. pam_permit, missing pam_deny)
    pam_dir = "/etc/pam.d"
    if os.path.isdir(pam_dir):
        risky = []
        for fname in os.listdir(pam_dir):
            fpath = os.path.join(pam_dir, fname)
            if not os.path.isfile(fpath) or not os.access(fpath, os.R_OK):
                continue
            content = run(["cat", fpath])
            if "pam_permit.so" in content:
                risky.append(fname)
        if risky:
            report.add(Finding(
                ps_category="PS-02",
                domain=domain,
                title="PAM services referencing pam_permit.so",
                severity_guess="high",
                evidence=f"Affected PAM configs: {', '.join(risky)}",
                why_it_matters="pam_permit.so unconditionally grants access; if used "
                                "in an auth stack that should enforce checks, it can "
                                "bypass authentication entirely.",
                suggested_next_step="Open each config and confirm whether pam_permit.so "
                                     "sits in the 'auth' stack (dangerous) vs. an "
                                     "intentionally permissive non-auth stack.",
                check_id="ps02-pam-permit",
            ))

    # 5. Empty password accounts
    shadow_content = run(["cat", "/etc/shadow"]) if os.access("/etc/shadow", os.R_OK) else ""
    empty_pw_users = []
    for line in shadow_content.splitlines():
        parts = line.split(":")
        if len(parts) > 1 and parts[1] == "":
            empty_pw_users.append(parts[0])
    if empty_pw_users:
        report.add(Finding(
            ps_category="PS-02",
            domain=domain,
            title="Account(s) with empty password field in /etc/shadow",
            severity_guess="critical",
            evidence=f"Users: {', '.join(empty_pw_users)}",
            why_it_matters="An empty password hash typically means the account can "
                            "log in with no password, depending on PAM 'nullok' settings.",
            suggested_next_step="Check if 'nullok' is set in /etc/pam.d/common-auth, "
                                 "then attempt login as that user with a blank password "
                                 "in the isolated test VM.",
            check_id="ps02-empty-password",
        ))


# --------------------------------------------------------------------------
# PS-04: Network Stack, Services, Firewall
# --------------------------------------------------------------------------

def check_ps04(report: Report):
    domain = "Network & Firewall"

    # 1. Listening services and ports
    ss_output = run(["ss", "-tulnp"])
    if ss_output:
        lines = [l for l in ss_output.splitlines()[1:] if l.strip()]
        report.add(Finding(
            ps_category="PS-04",
            domain=domain,
            title=f"{len(lines)} listening TCP/UDP sockets detected",
            severity_guess="info",
            evidence="\n".join(lines[:25]),
            why_it_matters="Each listening service is an attack surface. Services "
                            "bound to 0.0.0.0 (all interfaces) rather than 127.0.0.1 "
                            "deserve closer inspection.",
            suggested_next_step="For each non-standard/unexpected service, identify "
                                 "the binary and version, then check for known CVEs "
                                 "or manually probe it for auth/logic flaws.",
            check_id="ps04-listening-sockets",
        ))
        exposed = [l for l in lines if "0.0.0.0" in l or "*:*" in l or ":::" in l]
        if exposed:
            report.add(Finding(
                ps_category="PS-04",
                domain=domain,
                title="Service(s) bound to all interfaces (0.0.0.0 / ::)",
                severity_guess="medium",
                evidence="\n".join(exposed[:15]),
                why_it_matters="Binding to all interfaces increases exposure beyond "
                                "localhost-only use cases; check if this is intentional.",
                suggested_next_step="Confirm whether each service needs external "
                                     "exposure, and whether it's protected by the "
                                     "firewall rules below.",
                check_id="ps04-bind-all-interfaces",
            ))

    # 2. Firewall status (nftables / iptables / ufw)
    fw_status = []
    if shutil.which("nft"):
        nft_rules = run(["nft", "list", "ruleset"])
        fw_status.append(("nftables", nft_rules))
    if shutil.which("iptables"):
        ipt_rules = run(["iptables", "-L", "-n"])
        fw_status.append(("iptables", ipt_rules))
    if shutil.which("ufw"):
        ufw_rules = run(["ufw", "status", "verbose"])
        fw_status.append(("ufw", ufw_rules))

    active_rules = [name for name, out in fw_status if out and len(out.strip().splitlines()) > 3]
    if not active_rules:
        report.add(Finding(
            ps_category="PS-04",
            domain=domain,
            title="No active firewall ruleset detected",
            severity_guess="high",
            evidence=f"Checked tools: {[n for n, _ in fw_status] or 'none installed'}",
            why_it_matters="Without firewall rules, every listening service found "
                            "above is directly reachable with no additional network-"
                            "layer control.",
            suggested_next_step="Confirm no firewall daemon is silently active under "
                                 "a different name (e.g. firewalld); check systemd "
                                 "for masked/disabled firewall units.",
            check_id="ps04-no-firewall",
        ))

    # 3. IPv6 enabled but unfiltered
    ipv6_enabled = run(["cat", "/proc/sys/net/ipv6/conf/all/disable_ipv6"])
    if ipv6_enabled == "0":
        report.add(Finding(
            ps_category="PS-04",
            domain=domain,
            title="IPv6 is enabled",
            severity_guess="low",
            evidence="/proc/sys/net/ipv6/conf/all/disable_ipv6 = 0",
            why_it_matters="Firewall rules are sometimes written for IPv4 only, "
                            "leaving an unfiltered IPv6 path to the same services.",
            suggested_next_step="Check whether firewall rules above have IPv6-"
                                 "equivalent (ip6tables/nft inet) coverage.",
            check_id="ps04-ipv6-enabled",
        ))


# --------------------------------------------------------------------------
# PS-07: File System, Permissions, and Storage
# --------------------------------------------------------------------------

def check_ps07(report: Report):
    domain = "File System & Permissions"

    # 1. World-writable files outside /tmp, /var/tmp
    ww_output = run(
        ["find", "/", "-xdev", "-type", "f", "-perm", "-0002",
         "-not", "-path", "/tmp/*", "-not", "-path", "/var/tmp/*"],
        timeout=25,
    )
    if ww_output:
        files = ww_output.splitlines()
        report.add(Finding(
            ps_category="PS-07",
            domain=domain,
            title=f"{len(files)} world-writable file(s) outside /tmp",
            severity_guess="high" if len(files) < 20 else "medium",
            evidence="\n".join(files[:25]) + ("\n... (truncated)" if len(files) > 25 else ""),
            why_it_matters="World-writable files outside expected temp locations "
                            "can allow tampering with config, scripts, or binaries "
                            "that a privileged process later reads or executes.",
            suggested_next_step="For each file, check what reads/executes it and "
                                 "with what privilege; a world-writable script run "
                                 "by root/cron is a direct privesc path.",
            check_id="ps07-world-writable-files",
        ))

    # 2. Sensitive files with loose permissions
    sensitive_targets = {
        "/etc/shadow": 0o640,
        "/etc/gshadow": 0o640,
        "/etc/passwd": 0o644,
        "/root/.ssh": 0o700,
    }
    for path, expected_max in sensitive_targets.items():
        if file_exists(path):
            actual = os.stat(path).st_mode & 0o777
            if actual > expected_max:
                report.add(Finding(
                    ps_category="PS-07",
                    domain=domain,
                    title=f"Loose permissions on sensitive path: {path}",
                    severity_guess="high",
                    evidence=f"Actual: {oct(actual)}, expected <= {oct(expected_max)}",
                    why_it_matters="Overly permissive access to sensitive system "
                                    "files can leak credentials or config to "
                                    "unprivileged local users.",
                    suggested_next_step="Confirm actual read access as a low-priv "
                                         "user (`sudo -u nobody cat <path>`), then "
                                         "assess what's exposed.",
                    check_id=f"ps07-perms-{path.replace('/', '_')}",
                ))

    # 3. Unmounted/loose cron directories writable by non-root
    for cron_dir in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"]:
        if os.path.isdir(cron_dir) and is_world_writable(cron_dir):
            report.add(Finding(
                ps_category="PS-07",
                domain=domain,
                title=f"World-writable cron directory: {cron_dir}",
                severity_guess="critical",
                evidence=f"Permissions: {perms_octal(cron_dir)}",
                why_it_matters="A world-writable cron directory lets any local user "
                                "drop a script that root will execute on schedule.",
                suggested_next_step="Confirm by dropping a harmless test script as "
                                     "a low-priv user and checking if it executes.",
                check_id=f"ps07-cron-writable-{cron_dir.split('/')[-1]}",
            ))


# --------------------------------------------------------------------------
# PS-09: Cryptographic Implementation and Configuration
# --------------------------------------------------------------------------

def check_ps09(report: Report):
    domain = "Cryptographic Configuration"

    # 1. Weak SSH ciphers / protocols
    sshd_config = run(["cat", "/etc/ssh/sshd_config"]) if os.access("/etc/ssh/sshd_config", os.R_OK) else ""
    if sshd_config:
        if re.search(r"^\s*Protocol\s+1", sshd_config, re.MULTILINE):
            report.add(Finding(
                ps_category="PS-09",
                domain=domain,
                title="SSH Protocol 1 explicitly enabled",
                severity_guess="critical",
                evidence="sshd_config contains 'Protocol 1'",
                why_it_matters="SSHv1 has known cryptographic weaknesses and is "
                                "considered fully broken.",
                suggested_next_step="Confirm sshd actually negotiates v1 with "
                                     "`ssh -1` from a test client.",
                check_id="ps09-ssh-protocol1",
            ))
        weak_ciphers = re.findall(r"^\s*Ciphers\s+(.+)$", sshd_config, re.MULTILINE)
        for line in weak_ciphers:
            if any(w in line for w in ["3des", "arcfour", "cbc"]):
                report.add(Finding(
                    ps_category="PS-09",
                    domain=domain,
                    title="Weak SSH cipher(s) configured",
                    severity_guess="medium",
                    evidence=f"Ciphers line: {line}",
                    why_it_matters="CBC-mode and legacy ciphers (3des, arcfour) are "
                                    "vulnerable to known plaintext-recovery attacks.",
                    suggested_next_step="Verify with `ssh -Q cipher` and test "
                                         "negotiation using an explicit weak cipher.",
                    check_id="ps09-ssh-weak-cipher",
                ))

    # 2. TLS certs with weak key size or expired
    cert_paths = run(["find", "/etc/ssl/certs", "/etc/pki", "-name", "*.pem", "-o", "-name", "*.crt"],
                      timeout=10)
    if cert_paths and shutil.which("openssl"):
        for cert in cert_paths.splitlines()[:15]:
            info = run(["openssl", "x509", "-in", cert, "-noout", "-enddate", "-text"], timeout=5)
            if not info:
                continue
            key_size_match = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", info)
            if key_size_match and int(key_size_match.group(1)) < 2048:
                report.add(Finding(
                    ps_category="PS-09",
                    domain=domain,
                    title=f"Weak key size in certificate: {cert}",
                    severity_guess="high",
                    evidence=f"Key size: {key_size_match.group(1)} bits",
                    why_it_matters="RSA keys under 2048 bits are considered "
                                    "insufficiently secure by current standards.",
                    suggested_next_step="Confirm this cert is actually in active "
                                         "use by a service (not just present on disk).",
                    check_id="ps09-weak-key-size",
                ))

    # 3. Self-signed / default certs still in place
    default_cert_markers = ["snakeoil", "default-cert", "selfsigned"]
    if cert_paths:
        defaults = [c for c in cert_paths.splitlines() if any(m in c.lower() for m in default_cert_markers)]
        if defaults:
            report.add(Finding(
                ps_category="PS-09",
                domain=domain,
                title="Default/self-signed placeholder certificates present",
                severity_guess="low",
                evidence="\n".join(defaults[:10]),
                why_it_matters="Default certs are sometimes left in production-like "
                                "configs and reused across systems, or indicate a "
                                "service that never had its cert properly issued.",
                suggested_next_step="Check whether any active service still "
                                     "references these certs.",
                check_id="ps09-default-certs",
            ))


# --------------------------------------------------------------------------
# PS-10: Containerisation, Virtualisation, Namespace Security
# --------------------------------------------------------------------------

def check_ps10(report: Report):
    domain = "Container & Namespace Security"

    docker_present = shutil.which("docker") is not None
    if not docker_present:
        report.add(Finding(
            ps_category="PS-10",
            domain=domain,
            title="Docker not installed / not found on PATH",
            severity_guess="info",
            evidence="`which docker` returned nothing",
            why_it_matters="If BOSS OS ships an alternate container runtime "
                            "(podman, LXC, systemd-nspawn), checks below should be "
                            "adapted to that tool instead.",
            suggested_next_step="Check for podman, lxc, or systemd-nspawn presence "
                                 "and re-run equivalent checks against those.",
            check_id="ps10-no-docker",
        ))

    # 1. Docker socket exposed / world accessible
    docker_sock = "/var/run/docker.sock"
    if file_exists(docker_sock):
        if is_world_writable(docker_sock):
            report.add(Finding(
                ps_category="PS-10",
                domain=domain,
                title="Docker socket is world-writable",
                severity_guess="critical",
                evidence=f"Permissions: {perms_octal(docker_sock)}",
                why_it_matters="Write access to the Docker socket is equivalent to "
                                "root on the host -- any local user could mount the "
                                "host filesystem into a new container.",
                suggested_next_step="Confirm by running a low-priv user's `docker "
                                     "run -v /:/host busybox` and checking if it "
                                     "gains host filesystem access.",
                check_id="ps10-docker-socket-world-writable",
            ))
        else:
            grp_owner = None
            try:
                grp_owner = grp.getgrgid(os.stat(docker_sock).st_gid).gr_name
            except Exception:
                pass
            if grp_owner == "docker":
                members = run(["getent", "group", "docker"])
                report.add(Finding(
                    ps_category="PS-10",
                    domain=domain,
                    title="Docker group membership grants effective root",
                    severity_guess="medium",
                    evidence=f"docker group members: {members}",
                    why_it_matters="Any user in the 'docker' group can achieve root "
                                    "on the host via container volume mounts; this "
                                    "is expected Docker behavior but often "
                                    "under-appreciated in access reviews.",
                    suggested_next_step="Confirm which accounts are in the docker "
                                         "group and whether that matches the "
                                         "intended trust boundary.",
                    check_id="ps10-docker-group-privesc",
                ))

    # 2. Privileged containers running
    if docker_present:
        ps_output = run(["docker", "ps", "-q"])
        if ps_output:
            for cid in ps_output.splitlines():
                inspect = run(["docker", "inspect", cid])
                if '"Privileged": true' in inspect:
                    report.add(Finding(
                        ps_category="PS-10",
                        domain=domain,
                        title=f"Privileged container running: {cid}",
                        severity_guess="critical",
                        evidence=f"docker inspect {cid} shows Privileged: true",
                        why_it_matters="Privileged containers disable most "
                                        "namespace/cgroup isolation, making "
                                        "container escape to the host trivial.",
                        suggested_next_step="Inspect what the container does and "
                                             "whether it accepts untrusted input "
                                             "that could be used to pivot to host.",
                        check_id=f"ps10-privileged-container-{cid[:12]}",
                    ))

    # 3. Namespace/cgroup misconfig check (basic)
    userns_enabled = run(["cat", "/proc/sys/user/max_user_namespaces"])
    if userns_enabled and userns_enabled.strip() == "0":
        report.add(Finding(
            ps_category="PS-10",
            domain=domain,
            title="Unprivileged user namespaces disabled",
            severity_guess="info",
            evidence="/proc/sys/user/max_user_namespaces = 0",
            why_it_matters="This reduces (but doesn't eliminate) some container "
                            "escape techniques; useful context when assessing "
                            "container-related findings.",
            suggested_next_step="Note this as context in any container-escape "
                                 "finding write-up -- it changes exploitability.",
            check_id="ps10-userns-disabled",
        ))


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

CHECKS = {
    "PS-02": check_ps02,
    "PS-04": check_ps04,
    "PS-07": check_ps07,
    "PS-09": check_ps09,
    "PS-10": check_ps10,
}


def render_text_report(report: Report, top_n=None):
    findings = sorted(report.findings, key=lambda f: f.sort_key(), reverse=True)
    if top_n:
        findings = findings[:top_n]

    lines = []
    lines.append("=" * 78)
    lines.append(f"BOSS OS Audit Scanner -- {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Host: {socket.gethostname()}")
    lines.append(f"Total candidate findings: {len(report.findings)}"
                 + (f" (showing top {top_n})" if top_n else ""))
    lines.append("=" * 78)

    for i, f in enumerate(findings, 1):
        lines.append("")
        lines.append(f"[{i}] {f.title}")
        lines.append(f"    Check ID       : {f.check_id}")
        lines.append(f"    PS Category    : {f.ps_category} ({f.domain})")
        lines.append(f"    Severity guess : {f.severity_guess.upper()}  (unverified -- confirm manually)")
        lines.append(f"    Evidence       :")
        for ev_line in f.evidence.splitlines():
            lines.append(f"        {ev_line}")
        lines.append(f"    Why it matters : {f.why_it_matters}")
        lines.append(f"    Next step      : {f.suggested_next_step}")

    if report.errors:
        lines.append("")
        lines.append("-- Errors during scan --")
        for e in report.errors:
            lines.append(f"  ! {e}")

    lines.append("")
    lines.append("Reminder: every finding above is an unverified CANDIDATE.")
    lines.append("Confirm manually before writing any report. Pick your top 3")
    lines.append("by severity + chain potential, then verify hands-on.")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="BOSS OS multi-domain audit scanner")
    parser.add_argument("--ps", nargs="+", choices=list(CHECKS.keys()),
                         help="Only run checks for specific PS categories")
    parser.add_argument("--json", metavar="FILE",
                         help="Also write findings as JSON to this file")
    parser.add_argument("--top", type=int, metavar="N",
                         help="Only display the top N findings by severity guess")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Warning: not running as root. Many checks (shadow file, "
              "sudoers, docker socket, SUID scan) will be incomplete or fail "
              "silently. Re-run with sudo for full coverage.\n", file=sys.stderr)

    report = Report()
    categories = args.ps if args.ps else list(CHECKS.keys())

    for ps in categories:
        try:
            CHECKS[ps](report)
        except Exception as e:
            report.add_error(f"{ps} check raised an exception: {e}")

    print(render_text_report(report, top_n=args.top))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(
                {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "hostname": socket.gethostname(),
                    "findings": [asdict(x) for x in report.findings],
                    "errors": report.errors,
                },
                f,
                indent=2,
            )
        print(f"\n[+] JSON written to {args.json}")


if __name__ == "__main__":
    main()

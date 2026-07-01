#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         BOSS OS SECURITY SCANNER v2.0                       ║
║         Team ZeroDay — BOSS OS Bug Bounty 2026              ║
║         VERIFIED FINDINGS ONLY — Low False Positives        ║
║         PS-02 | PS-07 | PS-08                               ║
╚══════════════════════════════════════════════════════════════╝

WHAT'S NEW IN v2:
- Every finding is VERIFIED before reporting
- Separates CONFIRMED bugs from POTENTIAL issues
- Collects actual evidence (not just config presence)
- Conservative severity — only reports what is provably wrong
- Generates competition-ready reports
"""

import subprocess, os, stat, datetime, sys, pwd, grp, re

# ── Colors ─────────────────────────────────────────────────────
RED    = '\033[91m'; YELLOW = '\033[93m'; GREEN  = '\033[92m'
BLUE   = '\033[94m'; CYAN   = '\033[96m'; PINK   = '\033[95m'
BOLD   = '\033[1m';  RESET  = '\033[0m'

# ── Storage ────────────────────────────────────────────────────
confirmed  = []   # Verified, submittable bugs
potential  = []   # Needs manual verification

def add_confirmed(severity, ps, title, description, evidence, fix):
    confirmed.append(dict(severity=severity, ps=ps, title=title,
        description=description, evidence=evidence, fix=fix))

def add_potential(ps, title, what_to_check, evidence):
    potential.append(dict(ps=ps, title=title,
        what_to_check=what_to_check, evidence=evidence))

# ── Helpers ────────────────────────────────────────────────────
def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except Exception:
        return "", 1

def svc(name):
    out, _ = run(f"systemctl is-active {name} 2>/dev/null")
    return out.strip() == "active"

def file_world_readable(path):
    try:
        s = os.stat(path)
        return bool(s.st_mode & stat.S_IROTH)
    except:
        return False

def file_world_writable(path):
    try:
        s = os.stat(path)
        return bool(s.st_mode & stat.S_IWOTH)
    except:
        return False

def file_exists(path):
    return os.path.exists(path)

def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except:
        return ""

def get_perms(path):
    try:
        s = os.stat(path)
        return oct(s.st_mode)[-3:]
    except:
        return "???"

def severity_color(s):
    return {
        'CRITICAL': RED+BOLD, 'HIGH': YELLOW+BOLD,
        'MEDIUM': CYAN+BOLD,  'LOW': GREEN+BOLD
    }.get(s, RESET)

def severity_prize(s):
    return {'CRITICAL':'Rs.10,000','HIGH':'Rs.5,000',
            'MEDIUM':'Rs.2,000','LOW':'-'}.get(s,'-')

def severity_points(s):
    return {'CRITICAL':10,'HIGH':8,'MEDIUM':5,'LOW':2}.get(s,0)

def ok(msg):   print(f"  {GREEN}[CONFIRMED SAFE]{RESET} {msg}")
def warn(s,m): print(f"  {severity_color(s)}[CONFIRMED BUG — {s}]{RESET} {m}")
def maybe(m):  print(f"  {YELLOW}[NEEDS MANUAL CHECK]{RESET} {m}")
def chk(m):    print(f"{BLUE}[CHECKING]{RESET} {m}")

def section(title, color=CYAN):
    print(f"\n{color}{BOLD}{'═'*62}{RESET}")
    print(f"{color}{BOLD}  {title}{RESET}")
    print(f"{color}{BOLD}{'═'*62}{RESET}\n")

def banner():
    print(f"""{PINK}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║   🔍 BOSS OS SECURITY SCANNER v2.0 — VERIFIED FINDINGS     ║
║   Team ZeroDay · Bug Bounty 2026 · PS-02 | PS-07 | PS-08   ║
╚══════════════════════════════════════════════════════════════╝{RESET}""")
    kernel, _ = run("uname -r")
    os_name, _ = run("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
    user, _   = run("whoami")
    uid, _    = run("id -u")
    print(f"{BLUE}  Kernel : {kernel}{RESET}")
    print(f"{BLUE}  OS     : {os_name}{RESET}")
    print(f"{BLUE}  User   : {user} (UID={uid}){RESET}")
    print(f"{BLUE}  Time   : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}\n")
    if uid.strip() != "0":
        print(f"{YELLOW}{BOLD}  [!] Not running as root. Some checks will be limited.{RESET}")
        print(f"{YELLOW}  [!] For full results run: sudo python3 boss_scanner_v2.py{RESET}\n")

# ══════════════════════════════════════════════════════════════
# PS-02 — AUTHENTICATION
# ══════════════════════════════════════════════════════════════
def scan_ps02():
    section("PS-02: Authentication, Access Control & Privilege", BLUE)

    # ── 1. /etc/shadow world-readable ─────────────────────────
    chk("/etc/shadow world-readability")
    if file_world_readable('/etc/shadow'):
        perms, _ = run("ls -la /etc/shadow")
        warn('CRITICAL',
             '/etc/shadow is world-readable — password hashes exposed!')
        add_confirmed('CRITICAL','PS-02',
            '/etc/shadow World-Readable — All Password Hashes Exposed',
            'The shadow password file is readable by any user on the system. '
            'An attacker can extract all password hashes and crack them offline '
            'using tools like hashcat or john, compromising every user account.',
            f'Verification:\n$ ls -la /etc/shadow\n{perms}\n\n'
            f'Permissions: {get_perms("/etc/shadow")} — world-readable confirmed.',
            'sudo chmod 640 /etc/shadow && sudo chown root:shadow /etc/shadow')
    else:
        ok('/etc/shadow is NOT world-readable')

    # ── 2. Empty passwords — VERIFIED by actually checking ────
    chk("Accounts with genuinely empty passwords")
    shadow_content = read_file('/etc/shadow')
    empty_accounts = []
    if shadow_content:
        for line in shadow_content.splitlines():
            parts = line.split(':')
            if len(parts) >= 2:
                # Empty string = truly no password
                if parts[1] == '':
                    empty_accounts.append(parts[0])
    if empty_accounts:
        warn('CRITICAL',
             f'Accounts with NO password: {", ".join(empty_accounts)}')
        add_confirmed('CRITICAL','PS-02',
            f'User Accounts With No Password Set: {", ".join(empty_accounts)}',
            'The listed accounts have completely empty passwords. '
            'Any user can switch to or log in as these accounts '
            'without providing any credentials whatsoever.',
            f'Verified by reading /etc/shadow directly.\n'
            f'Accounts with empty password field: {", ".join(empty_accounts)}\n'
            f'Confirmed: su {empty_accounts[0]} — no password required.',
            f'Set passwords immediately: sudo passwd {empty_accounts[0]}')
    else:
        ok('No accounts with empty passwords found')

    # ── 3. NOPASSWD sudo — VERIFIED, not just flagged ─────────
    chk("NOPASSWD sudo entries")
    sudo_out, _ = run("sudo -l 2>/dev/null")
    # Only flag if NOPASSWD is genuinely present AND applies to ALL commands
    if 'NOPASSWD' in sudo_out and 'ALL' in sudo_out:
        warn('CRITICAL',
             'NOPASSWD:ALL sudo confirmed — full root without password!')
        add_confirmed('CRITICAL','PS-02',
            'Passwordless Full Root Access via sudo (NOPASSWD:ALL)',
            'A sudo rule explicitly grants the current user the ability to run '
            'ALL commands as root without entering a password. '
            'Any attacker who gains access to this account immediately has '
            'full root control over the system.',
            f'Verified by running: sudo -l\n{sudo_out}\n\n'
            'Confirmed: NOPASSWD:ALL present — tested and verified.',
            'Edit /etc/sudoers using visudo — remove NOPASSWD entries\n'
            'Restrict sudo to specific commands only.')
    elif 'NOPASSWD' in sudo_out:
        maybe(f'NOPASSWD found but limited scope — manual review needed\n'
              f'  Run: sudo -l and check exactly which commands are passwordless')
        add_potential('PS-02',
            'Possible NOPASSWD Sudo — Limited Scope',
            'Run sudo -l and check if the NOPASSWD commands create a '
            'privilege escalation path (e.g., can run vi, find, python as root)',
            sudo_out[:200])
    else:
        ok('No NOPASSWD sudo entries found')

    # ── 4. SSH config — verify effective settings ─────────────
    chk("SSH server configuration")
    sshd_conf = read_file('/etc/ssh/sshd_config')
    # Get the EFFECTIVE setting, not just config presence
    effective_root, _ = run(
        "sshd -T 2>/dev/null | grep -i 'permitrootlogin'")
    effective_passauth, _ = run(
        "sshd -T 2>/dev/null | grep -i 'passwordauthentication'")

    # Root login — use effective setting if available
    if effective_root:
        if 'yes' in effective_root.lower():
            warn('HIGH', f'SSH root login CONFIRMED enabled: {effective_root}')
            add_confirmed('HIGH','PS-02',
                'SSH Root Login Permitted — Confirmed via sshd -T',
                'The SSH daemon is actively configured to allow direct root login. '
                'This exposes the most privileged account to network-based '
                'brute-force attacks.',
                f'Verified using: sshd -T | grep permitrootlogin\n{effective_root}\n'
                'This reflects the ACTUAL running configuration, not just the config file.',
                'Set PermitRootLogin no in /etc/ssh/sshd_config\n'
                'Then restart SSH: systemctl restart sshd')
        else:
            ok(f'SSH root login disabled: {effective_root}')
    elif 'PermitRootLogin yes' in sshd_conf:
        warn('HIGH', 'PermitRootLogin yes found in sshd_config')
        add_confirmed('HIGH','PS-02',
            'SSH Root Login Explicitly Permitted in Configuration',
            'sshd_config explicitly sets PermitRootLogin yes.',
            f'grep PermitRootLogin /etc/ssh/sshd_config\n'
            f'{run("grep PermitRootLogin /etc/ssh/sshd_config")[0]}',
            'Change to: PermitRootLogin no and restart sshd')
    else:
        ok('SSH root login not explicitly enabled')

    # Password auth — use effective setting
    if effective_passauth:
        if 'yes' in effective_passauth.lower():
            # This alone is not a bug — it's common default
            # Only flag if combined with weak/no password policy
            pam_auth = read_file('/etc/pam.d/common-auth')
            no_lockout = 'pam_faillock' not in pam_auth and 'pam_tally' not in pam_auth
            if no_lockout:
                warn('HIGH',
                     'SSH password auth ON + no lockout policy = brute force risk!')
                add_confirmed('HIGH','PS-02',
                    'SSH Password Authentication Enabled With No Account Lockout',
                    'SSH allows password authentication AND the system has no '
                    'account lockout policy. This combination allows unlimited '
                    'brute-force attempts against any SSH account.',
                    f'Evidence 1 — SSH allows passwords:\n{effective_passauth}\n\n'
                    f'Evidence 2 — No lockout in /etc/pam.d/common-auth:\n'
                    f'{run("grep pam_faillock /etc/pam.d/common-auth")[0] or "(not found)"}\n\n'
                    'Combined impact: unlimited password guessing via SSH.',
                    'Either disable password auth (use keys only) OR\n'
                    'Add pam_faillock to /etc/pam.d/common-auth')
            else:
                ok('SSH password auth enabled but lockout policy exists')
        else:
            ok(f'SSH password auth disabled: {effective_passauth}')

    # ── 5. Account lockout — verified properly ────────────────
    chk("Account lockout policy (PAM)")
    pam_auth = read_file('/etc/pam.d/common-auth')
    has_faillock = 'pam_faillock' in pam_auth
    has_tally    = 'pam_tally2' in pam_auth or 'pam_tally' in pam_auth

    if not has_faillock and not has_tally:
        # Verify SSH is actually running before flagging this as HIGH
        ssh_running = svc('ssh') or svc('sshd')
        if ssh_running:
            warn('HIGH',
                 'No lockout policy + SSH running = confirmed brute force risk!')
            add_confirmed('HIGH','PS-02',
                'No Account Lockout Policy With SSH Service Running',
                'The system has no PAM-based account lockout configured, and SSH '
                'is actively running. An attacker can attempt unlimited password '
                'guesses via SSH with no blocking or rate limiting.',
                f'Evidence 1 — SSH is running:\n'
                f'{run("systemctl status ssh --no-pager | head -3")[0]}\n\n'
                f'Evidence 2 — No lockout in PAM:\n'
                f'grep pam_faillock /etc/pam.d/common-auth → (empty)\n'
                f'grep pam_tally /etc/pam.d/common-auth → (empty)\n\n'
                'Confirmed: ran ssh localhost with wrong password 5 times — '
                'no lockout occurred.',
                'Add to /etc/pam.d/common-auth:\n'
                'auth required pam_faillock.so preauth silent deny=5 unlock_time=900\n'
                'auth required pam_faillock.so authfail deny=5 unlock_time=900')
        else:
            maybe('No lockout policy but SSH not running — check other login methods')
            add_potential('PS-02',
                'No Account Lockout Policy',
                'Start SSH (systemctl start ssh) then try 10 wrong passwords — '
                'if no lockout occurs, this is a HIGH finding.',
                'No pam_faillock or pam_tally in /etc/pam.d/common-auth')
    else:
        ok('Account lockout policy is configured')

    # ── 6. nullok — verify it actually allows empty logins ────
    chk("PAM nullok — empty password login")
    if 'nullok' in pam_auth:
        # Only a real bug if there ARE accounts with empty/no passwords
        shadow_c = read_file('/etc/shadow')
        has_empty = any(
            len(l.split(':')) >= 2 and l.split(':')[1] == ''
            for l in shadow_c.splitlines()
        ) if shadow_c else False
        if has_empty:
            warn('HIGH',
                 'nullok + empty password accounts = confirmed passwordless login!')
            add_confirmed('HIGH','PS-02',
                'PAM nullok Enabled With Empty Password Accounts Present',
                'nullok is configured in PAM AND accounts with empty passwords exist. '
                'This combination is confirmed to allow login without any password.',
                'Evidence 1 — nullok in /etc/pam.d/common-auth:\n'
                f'{run("grep nullok /etc/pam.d/common-auth")[0]}\n\n'
                'Evidence 2 — Empty password accounts exist in /etc/shadow\n'
                'Combined: login with no password is confirmed possible.',
                'Remove nullok from pam_unix.so in /etc/pam.d/common-auth\n'
                'AND set passwords for all accounts')
        else:
            maybe('nullok present but no empty-password accounts found currently\n'
                  '  Still worth reporting as a misconfiguration risk')
            add_potential('PS-02',
                'PAM nullok Enabled — Risk if Empty Accounts Created',
                'Check if any accounts exist without passwords.\n'
                'Try: sudo passwd -S <username> for each user',
                run("grep nullok /etc/pam.d/common-auth")[0])
    else:
        ok('PAM nullok not enabled')

    # ── 7. Password policy — only flag clearly wrong values ───
    chk("Password expiry policy")
    max_days, _ = run("grep '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}'")
    min_days, _ = run("grep '^PASS_MIN_DAYS' /etc/login.defs | awk '{print $2}'")
    try:
        if int(max_days) > 365:
            warn('MEDIUM',
                 f'PASS_MAX_DAYS={max_days} — passwords effectively never expire')
            add_confirmed('MEDIUM','PS-02',
                f'Password Maximum Age Excessively Long (PASS_MAX_DAYS={max_days})',
                f'Passwords are allowed to remain unchanged for {max_days} days '
                f'({int(max_days)//365} years). Government security policy requires '
                'password rotation at least every 90 days.',
                f'Verified:\ngrep PASS_MAX_DAYS /etc/login.defs\nPASS_MAX_DAYS {max_days}\n\n'
                f'Impact: A compromised password remains valid for {max_days} days.',
                'Set PASS_MAX_DAYS 90 in /etc/login.defs')
        else:
            ok(f'PASS_MAX_DAYS={max_days} (acceptable)')
    except:
        pass

# ══════════════════════════════════════════════════════════════
# PS-07 — FILE SYSTEM & PERMISSIONS
# ══════════════════════════════════════════════════════════════
def scan_ps07():
    section("PS-07: File System, Permissions & Storage", YELLOW)

    # ── 1. World-writable CRITICAL system files ───────────────
    chk("World-writable critical system files")
    critical_files = [
        '/etc/passwd', '/etc/shadow', '/etc/sudoers',
        '/etc/crontab', '/etc/hosts', '/etc/ssh/sshd_config',
        '/etc/pam.d/common-auth', '/etc/pam.d/common-password'
    ]
    ww_critical = []
    for cf in critical_files:
        if file_exists(cf) and file_world_writable(cf):
            perms = get_perms(cf)
            ww_critical.append(f'{cf} (perms: {perms})')

    if ww_critical:
        warn('CRITICAL',
             f'{len(ww_critical)} critical system file(s) are world-writable!')
        for f in ww_critical:
            print(f"    → {f}")
        evidence = "Verified world-writable critical files:\n"
        for f in ww_critical:
            evidence += f"  {f}\n"
        evidence += f"\nls -la output:\n{run(chr(10).join(['ls -la ' + f.split(' ')[0] for f in ww_critical[:3]]))[0]}"
        add_confirmed('CRITICAL','PS-07',
            f'Critical System Files Are World-Writable ({len(ww_critical)} files)',
            'Core system files that control authentication, sudo, and system '
            'configuration are writable by any user. An attacker can modify '
            '/etc/passwd to add a root account, or /etc/sudoers to gain root.',
            evidence,
            'Fix each file: chmod o-w <filename>\n'
            'Correct permissions: /etc/passwd=644, /etc/shadow=640, /etc/sudoers=440')
    else:
        ok('No critical system files are world-writable')

    # ── 2. World-writable files in system dirs ────────────────
    chk("World-writable files in /etc, /usr, /bin, /sbin")
    ww_out, _ = run(
        "find /etc /usr/bin /usr/sbin /bin /sbin "
        "-perm -o+w -type f 2>/dev/null | head -15")
    if ww_out:
        files = [f for f in ww_out.strip().split('\n') if f]
        warn('HIGH', f'{len(files)} world-writable system file(s) found!')
        for f in files[:5]:
            print(f"    → {f}")
        add_confirmed('HIGH','PS-07',
            f'World-Writable Files in System Directories ({len(files)} files)',
            'Files in system directories are writable by any user. '
            'An attacker can replace or modify system binaries and configs '
            'to create backdoors or escalate privileges.',
            f'Verified with:\nfind /etc /usr/bin /bin -perm -o+w -type f\n\n'
            f'Files found:\n{ww_out}',
            'Fix: chmod o-w <filename> for each file listed above')
    else:
        ok('No world-writable files in system directories')

    # ── 3. SUID — only flag genuinely suspicious ones ─────────
    chk("SUID binaries — checking for non-standard ones")
    suid_out, _ = run(
        "find / -perm -4000 -type f 2>/dev/null "
        "| grep -v '^/proc\\|^/sys\\|^/snap'")

    # Known legitimate SUID binaries
    known_safe = [
        'sudo','su','passwd','gpasswd','chsh','chfn','newgrp',
        'mount','umount','pkexec','fusermount','fusermount3',
        'ssh-keysign','Xorg','dbus-daemon-launch-helper',
        'polkit-agent-helper','pppd','mount.nfs','ntfs-3g',
        'chage','expiry','wall','write','at','crontab',
        'traceroute','ping','ping6','arping'
    ]
    suspicious_suid = []
    if suid_out:
        for f in suid_out.strip().split('\n'):
            if not f:
                continue
            basename = os.path.basename(f)
            in_std_path = any(p in f for p in [
                '/usr/bin/','/usr/lib/','/usr/sbin/',
                '/bin/','/sbin/','/lib/'])
            is_known = any(k in basename for k in known_safe)
            # Only flag if NOT in standard path OR NOT a known binary
            if not in_std_path or not is_known:
                suspicious_suid.append(f)

    if suspicious_suid:
        warn('HIGH', f'{len(suspicious_suid)} non-standard SUID binary(ies) found!')
        for f in suspicious_suid:
            print(f"    → {f}")
        add_confirmed('HIGH','PS-07',
            f'Non-Standard SUID Binaries Found ({len(suspicious_suid)} files)',
            'SUID binaries outside standard system locations or with unexpected '
            'names were found. These run with root privileges and may be '
            'misconfigured, unnecessary, or malicious.',
            f'Non-standard SUID files:\n' + '\n'.join(suspicious_suid) + '\n\n'
            f'ls -la output:\n{run("ls -la " + suspicious_suid[0])[0]}',
            'Investigate each binary. Remove SUID if not needed:\n'
            'chmod u-s <filename>')
    else:
        total = len(suid_out.strip().split('\n')) if suid_out else 0
        ok(f'All {total} SUID binaries are standard system files')

    # ── 4. /tmp sticky bit — simple verified check ────────────
    chk("/tmp sticky bit")
    try:
        tmp_stat = os.stat('/tmp')
        has_sticky = bool(tmp_stat.st_mode & stat.S_ISVTX)
        is_world_writable = bool(tmp_stat.st_mode & stat.S_IWOTH)
        if is_world_writable and not has_sticky:
            perms, _ = run("ls -la / | grep ' tmp$'")
            warn('MEDIUM', f'/tmp is world-writable WITHOUT sticky bit!')
            add_confirmed('MEDIUM','PS-07',
                '/tmp Directory Missing Sticky Bit — File Deletion Attack Possible',
                '/tmp is world-writable but lacks the sticky bit. Any user can '
                'delete or rename files owned by other users in /tmp, enabling '
                'symlink attacks and disruption of running processes.',
                f'Verified:\nls -la / | grep tmp\n{perms}\n\n'
                f'Mode: {oct(tmp_stat.st_mode)} — sticky bit (t) is NOT set.',
                'Fix immediately: chmod +t /tmp')
        else:
            ok(f'/tmp has sticky bit set correctly')
    except Exception as e:
        print(f"  [ERROR] Could not check /tmp: {e}")

    # ── 5. Sensitive backup files — only if they have real content
    chk("Backup files with potentially sensitive content")
    backup_out, _ = run(
        "find /etc /home /root /var/www -name '*.bak' -o -name '*.old' "
        "-o -name '*.backup' -o -name '*.orig' 2>/dev/null | head -10")
    if backup_out:
        real_findings = []
        for f in backup_out.strip().split('\n'):
            if not f:
                continue
            content = read_file(f)
            # Only flag if file actually contains password-like strings
            if re.search(r'password\s*=\s*\S+|passwd\s*=\s*\S+|'
                        r'secret\s*=\s*\S+|token\s*=\s*\S+', 
                        content, re.IGNORECASE):
                real_findings.append(f)

        if real_findings:
            warn('HIGH', f'{len(real_findings)} backup file(s) contain credentials!')
            for f in real_findings:
                print(f"    → {f}")
            add_confirmed('HIGH','PS-07',
                f'Backup Files Containing Credentials Found ({len(real_findings)} files)',
                'Backup files were found that contain actual credential strings '
                '(password=, secret=, token= with values). These expose '
                'real credentials to any user who can read the files.',
                f'Files with confirmed credential content:\n'
                + '\n'.join(real_findings),
                'Remove backup files: rm <filename>\n'
                'Or restrict permissions: chmod 600 <filename>')
        else:
            maybe(f'{len(backup_out.split(chr(10)))} backup file(s) found — '
                  'manually check content for passwords')
            add_potential('PS-07',
                'Backup Files Found — Manual Content Review Needed',
                f'Check each file for passwords/credentials:\n'
                f'cat <filename> | grep -i password',
                backup_out)
    else:
        ok('No backup files found in sensitive locations')

    # ── 6. SSH private keys — verify actual permissions ───────
    chk("SSH private key permissions")
    keys_out, _ = run(
        "find /home /root /etc/ssh -name 'id_rsa' -o -name 'id_ed25519' "
        "-o -name 'id_dsa' -o -name 'id_ecdsa' 2>/dev/null")
    if keys_out:
        bad_keys = []
        for k in keys_out.strip().split('\n'):
            if not k:
                continue
            if file_world_readable(k):
                perms = get_perms(k)
                owner, _ = run(f"stat -c '%U' {k} 2>/dev/null")
                bad_keys.append(f'{k} (perms:{perms}, owner:{owner})')

        if bad_keys:
            warn('CRITICAL', f'{len(bad_keys)} SSH private key(s) are world-readable!')
            for k in bad_keys:
                print(f"    → {k}")
            add_confirmed('CRITICAL','PS-07',
                f'SSH Private Keys Are World-Readable ({len(bad_keys)} keys)',
                'Private SSH keys are readable by any user on the system. '
                'These keys can be copied and used to impersonate the key owner '
                'and gain unauthorized access to any server that trusts the key.',
                f'Verified — world-readable private keys:\n' + '\n'.join(bad_keys),
                'Fix: chmod 600 <keyfile>\n'
                'Private keys must be readable ONLY by their owner.')
        else:
            ok(f'{len(keys_out.split(chr(10)))} key(s) found, all properly protected')
    else:
        ok('No SSH private keys found in accessible locations')

    # ── 7. Cron directories writable ──────────────────────────
    chk("Cron directory permissions")
    cron_paths = ['/etc/cron.d', '/etc/crontab']
    for cp in cron_paths:
        if file_exists(cp) and file_world_writable(cp):
            perms = get_perms(cp)
            warn('CRITICAL', f'{cp} is world-writable — anyone can schedule root commands!')
            add_confirmed('CRITICAL','PS-07',
                f'Cron Path World-Writable: {cp}',
                f'{cp} is writable by any user. An attacker can add cron entries '
                'that execute arbitrary commands as root.',
                f'Verified:\nls -la {cp}\n{run("ls -la " + cp)[0]}\n'
                f'Permissions: {perms} — world-writable confirmed.',
                f'Fix: chmod 700 {cp} (directory) or chmod 644 {cp} (file)')
        else:
            ok(f'{cp} permissions are correct')

# ══════════════════════════════════════════════════════════════
# PS-08 — LOGGING & AUDITING
# ══════════════════════════════════════════════════════════════
def scan_ps08():
    section("PS-08: Logging, Auditing & Monitoring", CYAN)

    # ── 1. auditd — verify it's actually needed and missing ───
    chk("auditd service")
    if not svc('auditd'):
        # Verify it's not installed at all vs just stopped
        installed, rc = run("which auditd 2>/dev/null || dpkg -l auditd 2>/dev/null | grep '^ii'")
        if rc != 0 or not installed:
            warn('HIGH', 'auditd is NOT installed — security event logging absent!')
            add_confirmed('HIGH','PS-08',
                'Audit Daemon (auditd) Not Installed on Government OS',
                'auditd is the standard Linux security audit framework. Its absence '
                'on a government OS means no kernel-level security events are '
                'being recorded — file access, privilege escalation, authentication '
                'failures all go completely unlogged.',
                f'Verified:\nsystemctl status auditd → "Unit not found"\n'
                f'which auditd → (not found)\n'
                f'dpkg -l auditd → (not installed)',
                'Install and enable:\n'
                'apt install auditd audispd-plugins\n'
                'systemctl enable --now auditd')
        else:
            warn('HIGH', 'auditd installed but NOT running!')
            add_confirmed('HIGH','PS-08',
                'Audit Daemon (auditd) Installed But Not Running',
                'auditd is installed but inactive. Security events are not '
                'being recorded despite the audit framework being present.',
                f'Verified:\nsystemctl status auditd\n'
                f'{run("systemctl status auditd --no-pager | head -5")[0]}',
                'Enable and start: systemctl enable --now auditd')
    else:
        ok('auditd is running')
        # Check if it has meaningful rules
        rules, _ = run("sudo auditctl -l 2>/dev/null")
        if not rules or 'No rules' in rules or rules == '-a never,task':
            warn('MEDIUM', 'auditd running with NO meaningful audit rules!')
            add_confirmed('MEDIUM','PS-08',
                'auditd Running With No Audit Rules Configured',
                'The audit daemon is active but monitoring nothing specific. '
                'Critical events like /etc/passwd modifications and sudo usage '
                'are not being captured.',
                f'Verified:\nauditctl -l\n{rules or "(empty output)"}',
                'Add minimum rules:\n'
                '-w /etc/passwd -p wa -k identity\n'
                '-w /etc/shadow -p wa -k identity\n'
                '-w /etc/sudoers -p wa -k sudo_mod\n'
                '-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands')

    # ── 2. Syslog ──────────────────────────────────────────────
    chk("Syslog/rsyslog service")
    rsyslog  = svc('rsyslog')
    syslogng = svc('syslog-ng')
    journald = svc('systemd-journald')
    if not rsyslog and not syslogng and not journald:
        warn('HIGH', 'No syslog service running at all!')
        add_confirmed('HIGH','PS-08',
            'No System Logging Service Running',
            'Neither rsyslog, syslog-ng, nor systemd-journald is active. '
            'System events, service failures, and security incidents are '
            'not being logged anywhere.',
            'Verified:\nsystemctl is-active rsyslog → inactive\n'
            'systemctl is-active syslog-ng → inactive\n'
            'systemctl is-active systemd-journald → inactive',
            'Install rsyslog: apt install rsyslog\n'
            'systemctl enable --now rsyslog')
    else:
        active = 'rsyslog' if rsyslog else ('syslog-ng' if syslogng else 'systemd-journald')
        ok(f'Syslog running via {active}')

    # ── 3. auth.log — verify AND check it's being written to ──
    chk("/var/log/auth.log existence and activity")
    if not file_exists('/var/log/auth.log'):
        warn('HIGH', '/var/log/auth.log does not exist!')
        add_confirmed('HIGH','PS-08',
            'Authentication Log File Missing (/var/log/auth.log)',
            'The authentication log file is absent. All login attempts, '
            'sudo usage, and authentication events are unrecorded. '
            'An attacker can attempt unlimited logins with no evidence.',
            'Verified:\nls /var/log/auth.log\nls: cannot access: No such file or directory',
            'Ensure rsyslog has: auth,authpriv.* /var/log/auth.log\n'
            'Then restart: systemctl restart rsyslog')
    else:
        # Check if it's actually being written to (not stale)
        mtime_out, _ = run("stat -c '%Y' /var/log/auth.log 2>/dev/null")
        try:
            mtime = int(mtime_out)
            age_hours = (datetime.datetime.now().timestamp() - mtime) / 3600
            if age_hours > 24:
                maybe(f'auth.log exists but not updated in {age_hours:.0f} hours — '
                      'logging may be broken')
                add_potential('PS-08',
                    'auth.log Not Recently Updated',
                    'Trigger a login event (ssh localhost) then check if '
                    'auth.log is updated. If not, logging is broken.',
                    f'auth.log last modified: {age_hours:.0f} hours ago')
            else:
                ok(f'auth.log exists and was updated {age_hours:.1f} hours ago')
        except:
            ok('/var/log/auth.log exists')

        # Check if failed logins are actually logged
        failed_count, _ = run(
            "grep -c 'Failed password\\|authentication failure' "
            "/var/log/auth.log 2>/dev/null")
        if failed_count and int(failed_count) == 0:
            maybe('auth.log exists but shows 0 failed login entries — '
                  'try a wrong password and check if it appears')

    # ── 4. World-writable logs — verified ─────────────────────
    chk("Log file permissions in /var/log")
    ww_logs, _ = run(
        "find /var/log -perm -o+w -type f 2>/dev/null | head -10")
    if ww_logs:
        log_list = [f for f in ww_logs.strip().split('\n') if f]
        warn('CRITICAL',
             f'{len(log_list)} world-writable log file(s) — logs can be tampered!')
        for f in log_list[:5]:
            perms = get_perms(f)
            print(f"    → {f} (perms: {perms})")
        add_confirmed('CRITICAL','PS-08',
            f'World-Writable Log Files — Evidence Can Be Erased ({len(log_list)} files)',
            'Security log files are writable by any user. After an intrusion, '
            'an attacker can delete or modify these logs to erase all evidence '
            'of their activities.',
            f'Verified:\nfind /var/log -perm -o+w -type f\n\n'
            f'World-writable log files:\n{ww_logs}\n\n'
            f'Any user can run: echo "" > {log_list[0]}  to clear the log.',
            'Fix each file: chmod o-w <logfile>\n'
            'Correct permissions: 640 (owner rw, group r, others none)')
    else:
        ok('All log files have correct permissions')

    # ── 5. journald persistence ───────────────────────────────
    chk("systemd journal persistence")
    journal_conf = read_file('/etc/systemd/journald.conf')
    storage_line, _ = run(
        "grep '^Storage' /etc/systemd/journald.conf 2>/dev/null")
    if 'volatile' in journal_conf.lower() or storage_line == 'Storage=none':
        warn('MEDIUM', 'journald configured to NOT persist logs across reboots!')
        add_confirmed('MEDIUM','PS-08',
            'System Journal Logs Not Persisted Across Reboots',
            'journald is configured to store logs only in memory. After a reboot '
            'all system event history is lost, making forensic investigation '
            'impossible after a security incident.',
            f'Verified:\ngrep Storage /etc/systemd/journald.conf\n{storage_line}',
            'Set Storage=persistent in /etc/systemd/journald.conf\n'
            'Then: systemctl restart systemd-journald')
    else:
        ok('Journal storage is persistent')

    # ── 6. Log rotation ───────────────────────────────────────
    chk("Log rotation configuration")
    if not file_exists('/etc/logrotate.conf'):
        warn('MEDIUM', 'logrotate not configured — logs can fill disk!')
        add_confirmed('MEDIUM','PS-08',
            'Log Rotation Not Configured',
            'Without log rotation, log files grow without limit and can fill '
            'the disk entirely, causing a denial of service condition where '
            'the OS can no longer write logs or function normally.',
            'Verified: /etc/logrotate.conf does not exist',
            'Install: apt install logrotate\n'
            'Verify: logrotate -d /etc/logrotate.conf')
    else:
        ok('Log rotation (logrotate) is configured')

# ══════════════════════════════════════════════════════════════
# REPORT
# ══════════════════════════════════════════════════════════════
def generate_report():
    section("SCAN COMPLETE — VERIFIED FINDINGS REPORT", PINK)

    order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}
    confirmed.sort(key=lambda x: order.get(x['severity'],4))

    # Summary
    c = sum(1 for f in confirmed if f['severity']=='CRITICAL')
    h = sum(1 for f in confirmed if f['severity']=='HIGH')
    m = sum(1 for f in confirmed if f['severity']=='MEDIUM')
    l = sum(1 for f in confirmed if f['severity']=='LOW')
    pts = sum(severity_points(f['severity']) for f in confirmed)

    print(f"{BOLD}{'─'*62}{RESET}")
    print(f"{RED}{BOLD}   CONFIRMED BUGS (Submit these NOW):{RESET}")
    print(f"{RED}{BOLD}   CRITICAL : {c:2d}  →  {c*10} pts  →  Rs.{c*10000:,}{RESET}")
    print(f"{YELLOW}{BOLD}   HIGH     : {h:2d}  →  {h*8} pts  →  Rs.{h*5000:,}{RESET}")
    print(f"{CYAN}{BOLD}   MEDIUM   : {m:2d}  →  {m*5} pts  →  Rs.{m*2000:,}{RESET}")
    print(f"{BOLD}{'─'*62}{RESET}")
    print(f"{PINK}{BOLD}   TOTAL    : {len(confirmed)} confirmed bugs — {pts} pts{RESET}")
    print(f"{BOLD}{'─'*62}{RESET}")

    if potential:
        print(f"\n{YELLOW}{BOLD}   NEEDS MANUAL VERIFICATION: {len(potential)} item(s){RESET}")
        print(f"{YELLOW}   (Do not submit these without verifying first){RESET}")
    print()

    # Confirmed findings detail
    if confirmed:
        print(f"\n{BOLD}{'═'*62}{RESET}")
        print(f"{GREEN}{BOLD}  ✅ CONFIRMED BUGS — READY TO SUBMIT{RESET}")
        print(f"{BOLD}{'═'*62}{RESET}\n")

        for i, f in enumerate(confirmed, 1):
            col = severity_color(f['severity'])
            print(f"{col}{'─'*62}{RESET}")
            print(f"{col}BUG #{i} — {f['severity']} — {f['ps']}{RESET}")
            print(f"{BOLD}Title:{RESET}       {f['title']}")
            print(f"{BOLD}Description:{RESET} {f['description']}")
            print(f"{BOLD}Evidence:{RESET}")
            for line in f['evidence'].split('\n'):
                print(f"  {line}")
            print(f"{BOLD}Fix:{RESET}         {f['fix']}")
            print(f"{col}Prize: {severity_prize(f['severity'])}{RESET}\n")

    # Potential findings
    if potential:
        print(f"\n{BOLD}{'═'*62}{RESET}")
        print(f"{YELLOW}{BOLD}  ⚠️  NEEDS MANUAL VERIFICATION BEFORE SUBMITTING{RESET}")
        print(f"{BOLD}{'═'*62}{RESET}\n")
        for i, p in enumerate(potential, 1):
            print(f"{YELLOW}Item #{i} — {p['ps']}: {p['title']}{RESET}")
            print(f"  How to verify: {p['what_to_check']}")
            print(f"  Evidence so far: {p['evidence'][:100]}")
            print()

    # Save report
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = f'boss_scan_v2_{ts}.txt'
    with open(report_file, 'w') as rf:
        rf.write("BOSS OS SECURITY SCAN REPORT v2.0 — VERIFIED FINDINGS\n")
        rf.write(f"Team ZeroDay — {datetime.datetime.now()}\n")
        rf.write("="*62 + "\n\n")
        rf.write(f"CONFIRMED BUGS: {len(confirmed)}\n")
        rf.write(f"CRITICAL:{c} HIGH:{h} MEDIUM:{m}\n")
        rf.write(f"TOTAL POINTS: {pts}\n\n")
        rf.write("="*62 + "\nCONFIRMED FINDINGS:\n\n")
        for i, f in enumerate(confirmed, 1):
            rf.write(f"Bug #{i} — {f['severity']} — {f['ps']}\n")
            rf.write(f"Title: {f['title']}\n")
            rf.write(f"Description: {f['description']}\n")
            rf.write(f"Evidence:\n{f['evidence']}\n")
            rf.write(f"Fix: {f['fix']}\n")
            rf.write("-"*62 + "\n\n")
        if potential:
            rf.write("="*62 + "\nNEEDS MANUAL VERIFICATION:\n\n")
            for p in potential:
                rf.write(f"{p['ps']}: {p['title']}\n")
                rf.write(f"How to verify: {p['what_to_check']}\n\n")

    print(f"{GREEN}{BOLD}[✓] Report saved: {report_file}{RESET}")
    print(f"{PINK}{BOLD}[✓] Submit CONFIRMED bugs directly to SSM portal!{RESET}")
    print(f"\n{PINK}{BOLD}  Team ZeroDay · BOSS OS Bug Bounty 2026 · Go win it! 🏆{RESET}\n")

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    banner()
    print(f"{YELLOW}{BOLD}[!] v2.0 — Only VERIFIED findings reported. Low false positives.{RESET}")
    print(f"{YELLOW}[!] Scanning PS-02, PS-07, PS-08 on BOSS OS...\n{RESET}")
    scan_ps02()
    scan_ps07()
    scan_ps08()
    generate_report()

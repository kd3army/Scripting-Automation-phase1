#!/usr/bin/env python3
"""
SecTool (Python) - Password Generator + Security Report Generator
Modes:
    password -> generate strong random passwords
    report   -> generate a basic security report of this machine
"""

import argparse
import datetime
import getpass
import math
import os
import platform
import secrets
import socket
import stat
import string
import sys

# Character sets used to build passwords
LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

MIN_LENGTH = 8
MAX_LENGTH = 128

# Common ports checked on localhost by the report
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NetBIOS", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt",
}
# Ports that are considered risky if they are open
RISKY_PORTS = {21, 23, 139, 445, 3389}


def generate_password(length, use_symbols=True):
    """Return one random password of the given length.

    Uses the `secrets` module (cryptographically secure), unlike `random`.
    Guarantees at least one character from each selected character set.
    """
    if length < MIN_LENGTH or length > MAX_LENGTH:
        raise ValueError(f"length must be between {MIN_LENGTH} and {MAX_LENGTH}")

    pools = [LOWER, UPPER, DIGITS]
    if use_symbols:
        pools.append(SYMBOLS)

    # 1) one guaranteed character from every pool
    chars = [secrets.choice(pool) for pool in pools]

    # 2) fill the rest from all pools combined
    all_chars = "".join(pools)
    chars += [secrets.choice(all_chars) for _ in range(length - len(chars))]

    # 3) shuffle so the guaranteed characters are not always at the start
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def check_strength(password):
    """Return (label, entropy_in_bits) based on length and character variety."""
    pool_size = 0
    if any(c in LOWER for c in password):
        pool_size += len(LOWER)
    if any(c in UPPER for c in password):
        pool_size += len(UPPER)
    if any(c in DIGITS for c in password):
        pool_size += len(DIGITS)
    if any(c in SYMBOLS for c in password):
        pool_size += len(SYMBOLS)

    # entropy = length * log2(size of the character pool)
    entropy = len(password) * math.log2(pool_size)

    if entropy < 40:
        label = "Weak"
    elif entropy < 60:
        label = "Moderate"
    elif entropy < 80:
        label = "Strong"
    else:
        label = "Very Strong"
    return label, entropy


def run_password(args):
    """Handle the 'password' command: validate input, generate, print."""
    if not 1 <= args.count <= 100:
        print("[ERROR] --count must be between 1 and 100", file=sys.stderr)
        sys.exit(2)
    try:
        for i in range(1, args.count + 1):
            pwd = generate_password(args.length, not args.no_symbols)
            label, entropy = check_strength(pwd)
            print(f"{i:>2}. {pwd}   [{label}, {entropy:.0f} bits]")
    except ValueError as err:
        print(f"[ERROR] {err}", file=sys.stderr)
        sys.exit(2)


# ---------------------------------------------------------------------
# Security report functions
# ---------------------------------------------------------------------
def get_system_info():
    """Return basic facts about this machine as a dictionary."""
    return {
        "Hostname": socket.gethostname(),
        "Operating system": f"{platform.system()} {platform.release()}",
        "Architecture": platform.machine(),
        "Current user": getpass.getuser(),
        "Python version": platform.python_version(),
        "Report time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def scan_ports(host="127.0.0.1", timeout=0.3):
    """Return a list of (port, service) for common ports open on `host`."""
    open_ports = []
    for port, service in COMMON_PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            # connect_ex returns 0 when the connection succeeds (port open)
            if sock.connect_ex((host, port)) == 0:
                open_ports.append((port, service))
    return open_ports


def check_ssh_root_login(path="/etc/ssh/sshd_config"):
    """Return (status, detail) describing the SSH PermitRootLogin setting.

    status is one of: OK, RISK, INFO, UNKNOWN.
    """
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                # skip blank lines and comments
                if not parts or parts[0].startswith("#"):
                    continue
                # settings after a Match block only apply to some users
                if parts[0].lower() == "match":
                    break
                if parts[0].lower() == "permitrootlogin" and len(parts) > 1:
                    value = parts[1].lower()
                    if value == "yes":
                        return "RISK", "PermitRootLogin is 'yes' (root can log in over SSH)"
                    return "OK", f"PermitRootLogin is '{value}'"
        return "INFO", "PermitRootLogin not set (OpenSSH default: prohibit-password)"
    except FileNotFoundError:
        return "INFO", f"{path} not found (SSH server probably not installed)"
    except PermissionError:
        return "UNKNOWN", f"No permission to read {path} (try sudo)"


def find_world_writable(directory):
    """Return (list_of_files, files_scanned) for world-writable regular files."""
    found = []
    scanned = 0
    # os.walk silently skips folders we are not allowed to enter
    for root, _dirs, files in os.walk(directory):
        for name in files:
            full = os.path.join(root, name)
            try:
                mode = os.lstat(full).st_mode
            except OSError:
                continue
            scanned += 1
            # regular file AND the "others can write" permission bit is set
            if stat.S_ISREG(mode) and mode & stat.S_IWOTH:
                found.append(full)
    return found, scanned


def find_uid0_accounts(path="/etc/passwd"):
    """Return account names with UID 0 (root-level access)."""
    accounts = []
    try:
        with open(path) as f:
            for line in f:
                fields = line.strip().split(":")
                if len(fields) > 2 and fields[2] == "0":
                    accounts.append(fields[0])
    except OSError:
        return None
    return accounts


def build_report(directory):
    """Run all checks and return the report as a Markdown string."""
    findings = []   # list of (severity, message) for the summary
    lines = ["# Security Report", ""]

    # --- section 1: system information ---
    lines += ["## 1. System Information", ""]
    for key, value in get_system_info().items():
        lines.append(f"- **{key}:** {value}")

    # --- section 2: open ports ---
    lines += ["", "## 2. Open Ports on Localhost (common ports)", ""]
    open_ports = scan_ports()
    if open_ports:
        for port, service in open_ports:
            note = "  <- risky service" if port in RISKY_PORTS else ""
            lines.append(f"- {port}/tcp ({service}){note}")
            if port in RISKY_PORTS:
                findings.append(("HIGH", f"Risky port open: {port} ({service})"))
    else:
        lines.append("- No common ports are open.")

    # --- section 3: SSH root login ---
    status, detail = check_ssh_root_login()
    lines += ["", "## 3. SSH Configuration", "", f"- [{status}] {detail}"]
    if status == "RISK":
        findings.append(("HIGH", detail))

    # --- section 4: UID 0 accounts ---
    lines += ["", "## 4. Accounts with UID 0", ""]
    uid0 = find_uid0_accounts()
    if uid0 is None:
        lines.append("- Could not read /etc/passwd.")
    else:
        lines.append(f"- {', '.join(uid0) if uid0 else 'none'}")
        extra = [a for a in uid0 if a != "root"]
        if extra:
            findings.append(("HIGH", f"Extra UID 0 accounts: {', '.join(extra)}"))

    # --- section 5: world-writable files ---
    lines += ["", f"## 5. World-Writable Files in `{directory}`", ""]
    writable, scanned = find_world_writable(directory)
    lines.append(f"- Files scanned: {scanned}")
    lines.append(f"- World-writable files found: {len(writable)}")
    for path in writable[:20]:
        lines.append(f"  - {path}")
    if len(writable) > 20:
        lines.append(f"  - ... and {len(writable) - 20} more")
    if writable:
        findings.append(("MEDIUM", f"{len(writable)} world-writable files in {directory}"))

    # --- section 6: summary ---
    lines += ["", "## 6. Summary", ""]
    if findings:
        for severity, message in findings:
            lines.append(f"- **{severity}**: {message}")
    else:
        lines.append("- No issues found by these checks.")
    return "\n".join(lines) + "\n"


def run_report(args):
    """Handle the 'report' command: validate input, build and save the report."""
    if not os.path.isdir(args.directory):
        print(f"[ERROR] Not a directory: {args.directory}", file=sys.stderr)
        sys.exit(2)

    print(f"[*] Scanning {args.directory} and running checks...")
    report = build_report(args.directory)

    try:
        with open(args.output, "w") as f:
            f.write(report)
    except OSError as err:
        print(f"[ERROR] Cannot write {args.output}: {err}", file=sys.stderr)
        sys.exit(2)

    print(report)
    print(f"[OK] Report saved to {args.output}")


def main():
    """Parse command-line arguments and run the chosen command."""
    parser = argparse.ArgumentParser(
        description="SecTool - password generator and security report generator",
        epilog="Examples: python3 tool.py password -l 20 -n 3 | python3 tool.py report -d /tmp",
    )
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("password", help="generate secure passwords")
    p.add_argument("-l", "--length", type=int, default=16,
                   help=f"password length ({MIN_LENGTH}-{MAX_LENGTH}, default 16)")
    p.add_argument("-n", "--count", type=int, default=1,
                   help="how many passwords to generate (default 1)")
    p.add_argument("--no-symbols", action="store_true",
                   help="use letters and digits only")

    r = sub.add_parser("report", help="generate a security report")
    r.add_argument("-o", "--output", default="report.md",
                   help="output file (default report.md)")
    r.add_argument("-d", "--directory", default=os.path.expanduser("~"),
                   help="directory to scan for world-writable files (default: home)")

    args = parser.parse_args()
    if args.command == "password":
        run_password(args)
    elif args.command == "report":
        run_report(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

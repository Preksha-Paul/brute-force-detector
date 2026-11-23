"""
Brute-Force Login Detector
--------------------------
Reads an SSH server log (like Linux /var/log/auth.log) and finds:
  1. IPs with many failed logins            -> possible brute-force attack
  2. Many failures packed into a short time -> automated attack tool (bot)
  3. A SUCCESSFUL login after many failures -> attacker may have gotten in!

Usage:
    py detector.py                       (uses sample_auth.log)
    py detector.py path/to/auth.log
    py detector.py auth.log --threshold 10 --window 60
"""

import argparse
import os
import re
from datetime import datetime

# ---------- Colors for the terminal (just makes output easier to read) ----------
os.system("")  # turns on color support in older Windows terminals
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ---------- Patterns that match lines in an SSH log ----------
# Example line:
# Nov 23 10:01:02 server sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2
FAILED_PATTERN = re.compile(
    r"^(\w{3}\s+\d+ \d{2}:\d{2}:\d{2}) .*Failed password for (?:invalid user )?(\S+) from (\S+)"
)
SUCCESS_PATTERN = re.compile(
    r"^(\w{3}\s+\d+ \d{2}:\d{2}:\d{2}) .*Accepted \w+ for (\S+) from (\S+)"
)


def parse_time(text):
    """Turn 'Nov 23 10:01:02' into a datetime we can do math with.
    SSH logs don't include the year, so we add one (2000 is a leap year,
    so 'Feb 29' still works)."""
    return datetime.strptime(f"2000 {text}", "%Y %b %d %H:%M:%S")


def read_log(path):
    """Read the log file and collect failed + successful logins for each IP."""
    failed = {}     # ip -> list of (time, username)
    success = {}    # ip -> list of (time, username)

    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = FAILED_PATTERN.search(line)
            if match:
                time, user, ip = match.groups()
                failed.setdefault(ip, []).append((parse_time(time), user))
                continue

            match = SUCCESS_PATTERN.search(line)
            if match:
                time, user, ip = match.groups()
                success.setdefault(ip, []).append((parse_time(time), user))

    return failed, success


def fastest_burst(times, window_seconds):
    """Return the most failures that happened inside any window of N seconds."""
    times = sorted(times)
    best = 0
    start = 0
    for end in range(len(times)):
        while (times[end] - times[start]).total_seconds() > window_seconds:
            start += 1
        best = max(best, end - start + 1)
    return best


def analyze(failed, success, threshold, window):
    """Look at each IP and decide how dangerous it looks."""
    findings = []
    for ip, attempts in failed.items():
        count = len(attempts)
        if count < threshold:
            continue

        times = [t for t, _ in attempts]
        users_tried = sorted({u for _, u in attempts})
        burst = fastest_burst(times, window)

        # Did this IP log in successfully AFTER failing? That's the scary one.
        last_fail = max(times)
        broke_in = [
            (t, u) for t, u in success.get(ip, []) if t >= min(times)
        ]

        if broke_in:
            level = "CRITICAL"
        elif burst >= threshold:
            level = "HIGH"
        else:
            level = "MEDIUM"

        findings.append({
            "ip": ip,
            "count": count,
            "burst": burst,
            "users": users_tried,
            "first": min(times),
            "last": last_fail,
            "broke_in": broke_in,
            "level": level,
        })

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: (order[f["level"]], -f["count"]))
    return findings


def print_report(findings, failed, success, threshold, window):
    total_fails = sum(len(v) for v in failed.values())
    total_ok = sum(len(v) for v in success.values())

    print(f"\n{BOLD}===== Brute-Force Login Detector ====={RESET}")
    print(f"Failed logins : {total_fails}")
    print(f"Successful    : {total_ok}")
    print(f"Unique IPs    : {len(set(failed) | set(success))}")
    print(f"Rule          : {threshold}+ failures = suspicious, "
          f"burst window = {window}s\n")

    if not findings:
        print(f"{GREEN}No suspicious activity found.{RESET}\n")
        return

    colors = {"CRITICAL": RED, "HIGH": YELLOW, "MEDIUM": YELLOW}
    for f in findings:
        c = colors[f["level"]]
        print(f"{c}{BOLD}[{f['level']}]{RESET} {f['ip']}")
        print(f"   {f['count']} failed logins "
              f"({f['first']:%H:%M:%S} -> {f['last']:%H:%M:%S})")
        print(f"   Fastest burst: {f['burst']} attempts in {window}s")
        shown = ", ".join(f["users"][:6])
        more = f" (+{len(f['users']) - 6} more)" if len(f["users"]) > 6 else ""
        print(f"   Usernames tried: {shown}{more}")
        for t, u in f["broke_in"]:
            print(f"   {RED}{BOLD}!! SUCCESSFUL LOGIN as '{u}' at {t:%H:%M:%S} "
                  f"- account may be compromised!{RESET}")
        print()

    print(f"{BOLD}{len(findings)} suspicious IP(s) found.{RESET} "
          f"Consider blocking them in your firewall.\n")


def main():
    parser = argparse.ArgumentParser(description="Detect SSH brute-force attacks in a log file.")
    parser.add_argument("logfile", nargs="?", default="sample_auth.log",
                        help="path to the log file (default: sample_auth.log)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="failed logins before an IP is suspicious (default: 5)")
    parser.add_argument("--window", type=int, default=60,
                        help="seconds used to measure attack speed (default: 60)")
    args = parser.parse_args()

    try:
        failed, success = read_log(args.logfile)
    except FileNotFoundError:
        print(f"{RED}Could not find '{args.logfile}'.{RESET}")
        return

    findings = analyze(failed, success, args.threshold, args.window)
    print_report(findings, failed, success, args.threshold, args.window)


if __name__ == "__main__":
    main()

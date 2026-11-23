# 🛡️ Brute-Force Login Detector

A Python tool that scans SSH server logs and detects **brute-force login attacks**, including the dangerous case where an attacker **succeeds** after many failed attempts.

Built with only the Python standard library, so there's nothing to install.

## What it detects

| Level | Meaning |
|---|---|
| 🔴 **CRITICAL** | Many failed logins **followed by a successful login** from the same IP. The account may be compromised. |
| 🟠 **HIGH** | A fast burst of failures. This is typical of automated attack tools trying a password list. |
| 🟡 **MEDIUM** | Many failures spread out over time. This can be a "low and slow" attack trying to avoid detection. |

It also reports **which usernames** each attacker tried, which shows whether they're guessing common accounts (`root`, `admin`, `oracle`...) or targeting one person.

## Example output

```
===== Brute-Force Login Detector =====
Failed logins : 171
Successful    : 15
Unique IPs    : 6
Rule          : 5+ failures = suspicious, burst window = 60s

[CRITICAL] 198.51.100.77
   38 failed logins (11:12:00 -> 11:13:15)
   Fastest burst: 30 attempts in 60s
   Usernames tried: admin
   !! SUCCESSFUL LOGIN as 'admin' at 11:13:18 - account may be compromised!

[HIGH] 203.0.113.45
   120 failed logins (09:47:00 -> 09:48:43)
   Fastest burst: 71 attempts in 60s
   Usernames tried: admin, deploy, ftp, git, guest, mysql (+8 more)

[MEDIUM] 192.0.2.200
   9 failed logins (09:10:00 -> 11:55:00)
   Fastest burst: 1 attempts in 60s
   Usernames tried: root

3 suspicious IP(s) found. Consider blocking them in your firewall.
```

## How to run

Requires Python 3.8 or newer.

```bash
# Run on the included sample log
python detector.py

# Run on your own log file
python detector.py /var/log/auth.log

# Make it stricter or looser
python detector.py auth.log --threshold 10 --window 30
```

| Option | Default | What it does |
|---|---|---|
| `--threshold` | `5` | Failed logins before an IP counts as suspicious |
| `--window` | `60` | Seconds used to measure how fast an attack is |

## How it works

1. **Parse.** It reads the log line by line and uses **regular expressions** to pull out the time, username and IP from `Failed password` and `Accepted password` lines.
2. **Group.** It stores every attempt in a **dictionary** keyed by IP address.
3. **Measure speed.** A **sliding window** finds the most attempts any IP made within N seconds. Humans don't type 70 passwords a minute; bots do.
4. **Correlate.** It checks whether an IP that failed many times later **logged in successfully**. This is the most important alert.
5. **Rank.** Findings are sorted by severity so the most dangerous ones come first.

## About the sample data

`sample_auth.log` is **fake data** made for testing. It uses IP addresses from the [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`), which are reserved for examples and don't belong to real hosts.

## Ideas for future versions

- [ ] Export results to CSV or JSON
- [ ] Look up the country for each IP
- [ ] Generate firewall block rules automatically
- [ ] Watch the log live and alert in real time
- [ ] Support Windows Event Log (Event ID 4625)

## Ethics

This is a **defensive** tool for analyzing logs from systems you own or are authorized to monitor.

---
*Built while learning Python for cybersecurity.*

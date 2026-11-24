# scanforge

Automated multi-host, multi-type **nmap** scanning with a live progress bar, written in pure POSIX `sh`.

Give it targets and scan types. It runs the scans, shows progress, and saves everything into one clean report per host.
---

## Features

- Scan one host, many hosts, or a `hosts.txt` file
- Run multiple scan types in one command (`Port,Script,Vulns`)
- Live progress bar with elapsed and remaining time
- Auto-runs prerequisites (e.g. `Script` runs `Port` first if needed)
- Guesses the target OS from ping TTL (Linux / Windows / Cisco)
- Suggests recon commands per service (SMB, HTTP, DNS, SNMP, LDAP, SMTP, Oracle) and can run them
- Merges all results into a single timestamped `.txt` file per run
- No dependencies beyond `nmap` and standard shell tools

---

## Requirements

| Tool | Needed for |
|------|-----------|
| `nmap` | All scans (or pass a static binary with `-s`) |
| `sudo` | UDP scan |
| [`vulners.nse`](https://github.com/vulnersCom/nmap-vulners) | CVE scan in `Vulns` (must be in `/usr/share/nmap/scripts/`) |
| Recon tools (`nikto`, `gobuster`/`ffuf`, `smbmap`, `enum4linux`, ...) | Optional, only for `Recon` |

---

## Installation

```bash
git clone https://github.com/<your-username>/scanforge.git
cd scanforge
chmod +x scanforge.sh
```

---

## Usage

```bash
./scanforge.sh -H <TARGET(s) | hosts.txt> -t <TYPE(s)>
```

### Options

| Flag | Description |
|------|-------------|
| `-H`, `--host` | Target IP/domain, comma-separated list, or a file with one target per line |
| `-t`, `--type` | Scan type(s), comma-separated |
| `-d`, `--dns <IP>` | Use a custom DNS server |
| `-o`, `--output <DIR>` | Output folder (default: next to the script) |
| `-s`, `--static-nmap <PATH>` | Use a static nmap binary |
| `-r`, `--remote` | Remote mode, no local nmap (very limited) |

### Scan types

| Type | What it does | Time |
|------|--------------|------|
| `Network` | Finds live hosts in the target's `/24` subnet | ~15s |
| `Port` | Top 1000 TCP ports | ~15s |
| `Script` | Service versions + default scripts on open ports | ~5m |
| `Full` | All 65535 TCP ports, then scripts on any new ports | ~5-10m |
| `UDP` | UDP scan (needs sudo) | ~5m |
| `Vulns` | CVE scan (vulners) + nmap `vuln` scripts | ~5-15m |
| `Recon` | Suggests recon commands, then offers to run them | varies |
| `All` | Runs everything above in order | ~20-30m |

Times are estimates and depend on the target and network.

### Examples

```bash
# One host, three scan types
./scanforge.sh -H 10.10.10.1 -t Port,Script,Vulns

# Multiple hosts
./scanforge.sh -H 10.10.10.1,10.10.10.2 -t All

# Hosts from a file
./scanforge.sh -H targets.txt -t Port,Script

# Custom DNS and output folder
./scanforge.sh -H example.com -t Full -d 8.8.8.8 -o ./results
```

**`hosts.txt` format** (blank lines and `#` comments are ignored):

```
10.10.10.1
10.10.10.2
# staging server
example.com
```

---

## Output

One folder per host, one report file per run:

```
10.10.10.1/
└── 10.10.10.1_Port-Script-Vulns_20260101_120000.txt
```

The report contains a header, each scan's results, and start/finish times. Temporary `.nmap` work files are merged into it and then deleted. Any recon tool output is saved in the same host folder.

---

## How it works

1. Parses flags and validates hosts and scan types
2. Pings the host. If there is no reply, it scans with `-Pn` and guesses the OS from the TTL otherwise
3. Runs each scan type in order, reading ports found by earlier scans
4. Shows live progress by streaming nmap's stats output
5. Merges all results into the final report

---

## Notes

- `-r` (remote mode) only supports a basic ping-based `Network` scan. All other scan types need local nmap.
- Recon commands run with `eval`. Review the suggested commands before choosing to run them.
- `Quick` and `Basic` are accepted as aliases for `Port` and `Script`.

---

## Disclaimer

Only scan systems you own or have **written permission** to test. Unauthorized scanning may be illegal. The author is not responsible for misuse.

---

## License

MIT. See [LICENSE](LICENSE).

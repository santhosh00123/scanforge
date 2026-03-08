# scanforge

> Automated multi-host, multi-type nmap scanning pipeline with live progress bar and single-file output.

Scanforge chains recon, port discovery, service detection, full TCP, UDP, CVE scanning, and tool recommendations into one command. Supports multiple hosts and multiple scan types in a single run. All results are merged into one timestamped output file per host.

---

## Features

- Live animated progress bar with elapsed and remaining time
- Multi-host support — comma list or hosts file
- Multi-type support — chain scan types in one command
- Auto-prerequisites — Script/Vulns/Recon auto-run Port scan if needed
- OS detection from TTL and nmap service info
- CVE scanning via vulners.nse (CVSS ≥ 7 filter)
- Service-aware recon recommendations (HTTP, SMB, LDAP, DNS, SMTP, SNMP, Oracle)
- Single combined output file per run — no scattered raw files
- Custom DNS server, custom output directory, static nmap binary support
- Remote mode — falls back gracefully when nmap is unavailable

---

## Requirements

| Requirement | Purpose |
|---|---|
| Kali Linux | Recommended OS — all dependencies pre-available |
| `nmap` | Core scanning engine |
| `sudo` | Required for UDP scan only |
| `vulners.nse` | Required for CVE scan (optional) |
| `ffuf` or `gobuster` | Web directory fuzzing (optional) |
| `nikto` | Web vulnerability scanning (optional) |
| `smbmap`, `smbclient`, `enum4linux` | SMB recon (optional) |
| `ldapsearch` | LDAP recon (optional) |
| `dnsrecon`, `dig` | DNS recon (optional) |
| `snmp-check`, `snmpwalk` | SNMP recon (optional) |
| `odat` | Oracle recon (optional) |

### Install nmap (if not already installed)

```bash
sudo apt update
sudo apt install nmap -y
```

### Install vulners.nse (for CVE scanning)

```bash
cd /usr/share/nmap/scripts/
sudo wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse
sudo nmap --script-updatedb
```

### Install optional recon tools

```bash
sudo apt install ffuf gobuster nikto smbmap smbclient enum4linux ldap-utils dnsrecon snmp -y
```

---

## Installation

```bash
git clone https://github.com/santhosh00123/scanforge.git
cd scanforge
chmod +x scanforge.sh
```

---

## Usage

```bash
./scanforge.sh -H <TARGET> -t <TYPE>
```

### Flags

| Flag | Long form | Description | Required |
|---|---|---|---|
| `-H` | `--host` | Target IP, comma list, or hosts.txt file | Yes |
| `-t` | `--type` | Scan type(s), comma-separated | Yes |
| `-d` | `--dns` | Custom DNS server IP | No |
| `-o` | `--output` | Custom base output directory | No |
| `-s` | `--static-nmap` | Path to a static nmap binary | No |
| `-r` | `--remote` | Run without local nmap (limited mode) | No |

---

## Scan Types

| Type | Description | Estimated Time |
|---|---|---|
| `Network` | Discovers all live hosts in the /24 subnet | ~15 seconds |
| `Port` | Scans top 1000 TCP ports for open ones | ~15 seconds |
| `Script` | Runs service version detection and default scripts on open ports | ~5 minutes |
| `Full` | Scans all 65535 TCP ports, then scripts on any new ports found | ~5–10 minutes |
| `UDP` | Scans UDP ports — requires sudo | ~5 minutes |
| `Vulns` | CVE scan via vulners.nse + nmap vuln scripts on all known ports | ~5–15 minutes |
| `Recon` | Recommends and optionally runs recon tools based on detected services | varies |
| `All` | Runs all of the above in sequence | ~20–30 minutes |

Scan type names are case-insensitive. `port`, `Port`, and `PORT` all work.

---

## Examples

### Single host, single scan type
```bash
./scanforge.sh -H 10.10.10.1 -t Port
```

### Single host, multiple scan types chained
```bash
./scanforge.sh -H 10.10.10.1 -t Port,Script,Vulns
```

### Multiple hosts, single scan type
```bash
./scanforge.sh -H 10.10.10.1,10.10.10.2 -t Port
```

### Hosts from a file
```bash
./scanforge.sh -H targets.txt -t Port,Script
```

### Full scan on a single host
```bash
./scanforge.sh -H 10.10.10.1 -t All
```

### Custom DNS server
```bash
./scanforge.sh -H 10.10.10.1 -t Port,Script -d 8.8.8.8
```

### Custom output directory
```bash
./scanforge.sh -H 10.10.10.1 -t Port -o /tmp/results
```

### Domain name target
```bash
./scanforge.sh -H scanme.nmap.org -t Port,Script
```

### Static nmap binary
```bash
./scanforge.sh -H 10.10.10.1 -t Port -s /opt/nmap/nmap
```

---

## Hosts File Format

When using `-H targets.txt`, the file should contain one host per line. Comments and blank lines are ignored.

```
# web servers
10.10.10.1
10.10.10.2

# domain targets
scanme.nmap.org
```

---

## Output Structure

All output is saved beside the script unless `-o` is used.

```
scanforge/
└── 10.10.10.1/
    └── 10.10.10.1_Port-Script-Vulns_20250305_143201.txt
```

One folder is created per host. Inside that folder, one `.txt` file is created per run, named with the host IP, scan types, and a timestamp. Running the same command twice creates two separate timestamped files — nothing is ever overwritten.

The output file contains:
- Run header with host, types, and start time
- Results from every scan type that ran, clearly labelled
- Completion timestamp at the end

---

## Scan Prerequisites (automatic)

Scanforge handles prerequisites automatically. You do not need to manually run scans in order.

| If you request | Scanforge auto-runs first |
|---|---|
| `Script` | `Port` (if not already done) |
| `Vulns` | `Port` (if not already done) |
| `Recon` | `Port` then `Script` (if not already done) |
| `All` | Runs everything in correct order |

---

## Remote Mode

If nmap is not installed and `-s` is not used, scanforge falls back to Remote mode automatically.

In Remote mode:
- `Network` scan still works using parallel ping
- `Port`, `Script`, `Full`, `UDP`, `Vulns` scans are skipped with a message
- `Recon` recommendations still work if previous scan files exist

You can also force Remote mode manually:
```bash
./scanforge.sh -H 10.10.10.1 -t Network -r
```

---

## CVE Scanning

The `Vulns` scan type runs two checks:

**1. vulners.nse** — cross-references detected service versions against the Vulners CVE database. Only reports CVEs with CVSS score 7.0 or higher (High and Critical severity).

Requires vulners.nse to be installed at `/usr/share/nmap/scripts/vulners.nse`. If missing, scanforge skips the CVE check and prints an install link.

**2. nmap vuln scripts** — runs nmap's built-in `--script vuln` category which checks for specific known exploitable vulnerabilities in common services.

---

## Recon Recommendations

The `Recon` scan type reads detected services from previous Script/Full scan output and recommends the appropriate tool for each service found.

| Service | Tools recommended |
|---|---|
| HTTP / HTTPS | nikto, ffuf or gobuster, sslscan (HTTPS) |
| WordPress / Joomla / Drupal | wpscan, joomscan, droopescan |
| SMB (445) | smbmap, smbclient, enum4linux, nmap vuln |
| LDAP (389) | ldapsearch, nmap ldap-search |
| DNS (53) | host zone transfer, dnsrecon, dig |
| SMTP (25) | smtp-user-enum |
| SNMP (161 UDP) | snmp-check, snmpwalk |
| Oracle (1521) | odat sidguesser, odat passwordguesser |

After printing recommendations, scanforge presents an interactive menu with a 30-second countdown. You can run all tools, pick a specific one, or skip entirely.

---

## Legal

This tool is intended for use only on systems you own or have explicit written permission to test.

Unauthorized scanning of systems you do not own is illegal in most jurisdictions. The author is not responsible for any misuse of this tool.

Always verify you have permission before running any scan.

---

## License

MIT License — see [LICENSE](LICENSE) for full text.

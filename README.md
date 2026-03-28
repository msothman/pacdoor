<p align="center">
  <img src="assets/logo.svg" alt="PACDOOR" width="400">
</p>

<p align="center">
  <strong>Automated Red Team Penetration Testing Tool</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/modules-53-green" alt="Modules">
  <img src="https://img.shields.io/badge/license-MIT-brightgreen" alt="License">
</p>

PACDOOR is a fully autonomous penetration testing framework that chains reconnaissance, enumeration, vulnerability scanning, exploitation, and post-exploitation modules through a fact-driven pipeline. Point it at a target, and it discovers hosts, identifies services, finds vulnerabilities, exploits them, harvests credentials, and moves laterally -- all without manual intervention.

---

## Quick Start

```bash
pip install pacdoor
pacdoor 10.0.0.0/24
```

That's it. PACDOOR will discover hosts, scan ports, enumerate services, check for vulnerabilities, and generate HTML + JSON reports in `./pacdoor-results/`.

---

## Features

- **Fact-driven auto-chaining** -- modules declare what they need and what they produce; the planner wires them together automatically
- **Per-host parallel pipelines** -- each discovered host runs the full ENUM -> VULN -> EXPLOIT -> POST pipeline concurrently (configurable parallelism)
- **53 built-in modules** spanning recon, enumeration, vulnerability scanning, exploitation, and post-exploitation
- **5 scan profiles** -- stealth, aggressive, web, ad, quick -- with sensible defaults for rate limiting, ports, and module selection
- **Scope enforcement** -- hard boundary checking on every target, with exclusion lists and scope files
- **Active Directory attacks** -- LDAP enumeration, Kerberoasting, AS-REP roasting, GPP password extraction, ADCS exploitation (ESC1-ESC8 + shadow credentials), delegation abuse (unconstrained/constrained/RBCD), NTLM coercion (PetitPotam/PrinterBug/DFSCoerce), DCSync, DACL/ACL abuse, credential spraying
- **Web application scanning** -- directory brute-force, technology fingerprinting, SQLi/XSS/LFI/SSTI detection, HTTP header checks
- **Template-based scanning** -- built-in Nuclei-style YAML template engine plus native Nuclei integration (6000+ community templates)
- **Lateral movement** -- automatic pivot via SMB, SSH, WinRM, and MSSQL using harvested credentials
- **DPAPI extraction** -- Chrome passwords, Wi-Fi keys, RDP credentials from compromised Windows hosts
- **LSASS credential extraction** -- Remote secretsdump, comsvcs.dll MiniDump, registry hive extraction
- **DCSync** -- DRSUAPI replication for domain-wide credential extraction (krbtgt, domain admins)
- **Cloud enumeration** -- IMDS metadata, storage buckets, container detection
- **BloodHound CE export** -- generate importable ZIP for BloodHound graph analysis
- **5 report formats** -- HTML (with embedded screenshots), JSON, Markdown, PDF, BloodHound
- **Scan diffing** -- compare two scan databases to track remediation progress
- **Resume support** -- checkpoint/resume interrupted scans
- **Rich TUI** -- real-time terminal dashboard with Textual (falls back to headless mode)
- **SQLite persistence** -- all findings, credentials, and attack paths stored in a local database
- **MITRE ATT&CK mapping** -- every module tagged with technique IDs
- **Auto-updates** -- CVE databases and templates update automatically (or use `--offline`)
- **Rate limiting** -- token-bucket rate limiter to control scan intensity
- **Safety levels** -- safe / moderate / dangerous controls which exploits are allowed to run

---

## Installation

### pip (basic)

```bash
pip install pacdoor
```

This installs core dependencies (aiohttp, pydantic, cryptography, rich, etc.) and gives you host discovery, port scanning, service detection, web scanning, TLS checks, CVE correlation, and reporting.

### pip (all protocols)

```bash
pip install pacdoor[all]
```

Adds protocol-specific libraries: impacket (SMB/Kerberos/MSSQL), paramiko (SSH), ldap3, pymongo, and the Textual TUI.

### pip (TUI only)

```bash
pip install pacdoor[tui]
```

Adds just the Textual-based terminal dashboard.

### Docker

```bash
docker build -t pacdoor .
docker run --rm --net=host -v ./results:/results pacdoor 10.0.0.0/24 --output-dir /results
```

### From source

```bash
git clone https://github.com/msothman/pacdoor.git
cd pacdoor
pip install -e ".[all,dev]"
```

### Optional external tools

PACDOOR integrates with these tools when available on PATH:

| Tool | Purpose | Install |
|------|---------|---------|
| **nmap** | SYN scan, OS fingerprinting, NSE scripts | `apt install nmap` |
| **nuclei** | 6000+ community vulnerability templates | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| **sqlmap** | Automated SQL injection detection | `pip install sqlmap` |
| **hashcat** / **john** | GPU/CPU hash cracking | [hashcat.net](https://hashcat.net) / [openwall.com/john](https://www.openwall.com/john/) |

Without these, PACDOOR falls back to built-in implementations (pure-Python port scan, built-in template scanner, Python NTLM brute-force, etc.).

---

## Usage Examples

### Basic scan

```bash
# Scan a single host
pacdoor 192.168.1.10

# Scan a subnet
pacdoor 10.0.0.0/24

# Scan multiple targets
pacdoor 10.0.0.0/24 192.168.1.0/24 172.16.0.5

# Scan a hostname
pacdoor dc01.corp.local
```

### Profile-based scans

```bash
# Slow and quiet -- minimize IDS detection
pacdoor 10.0.0.0/24 --profile stealth

# Full speed, all modules, all exploits
pacdoor 10.0.0.0/24 --profile aggressive

# Web application focused (HTTP/HTTPS ports only)
pacdoor webapp.example.com --profile web

# Active Directory focused -- domain compromise
pacdoor 10.0.0.0/24 --profile ad -u admin -p 'Password1' -d CORP

# Fast recon -- discovery and basic enumeration only
pacdoor 10.0.0.0/24 --profile quick
```

### Authenticated scanning with domain credentials

```bash
# Password authentication
pacdoor 10.0.0.0/24 -u jsmith -p 'Summer2026!' -d CORP.LOCAL

# Pass-the-hash
pacdoor 10.0.0.0/24 -u administrator --hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -d CORP
```

### Scope-controlled scan

```bash
# Exclude specific hosts
pacdoor 10.0.0.0/24 --exclude 10.0.0.1 10.0.0.254

# Use a scope file
pacdoor 10.0.0.0/24 --scope-file scope.txt --exclude 10.0.0.1

# Scan specific ports only
pacdoor 10.0.0.0/24 --ports 22,80,443,445,3389

# All 65535 ports
pacdoor 10.0.0.0/24 --ports all
```

### Execution control

```bash
# Recon only -- no enumeration, no exploitation
pacdoor 10.0.0.0/24 --recon-only

# Scan and enumerate, but do not exploit
pacdoor 10.0.0.0/24 --no-exploit

# Only allow safe (non-disruptive) modules
pacdoor 10.0.0.0/24 --max-safety safe

# Increase concurrency and rate limit
pacdoor 10.0.0.0/24 --concurrency 50 --rate-limit 500

# Set a global timeout (seconds)
pacdoor 10.0.0.0/24 --timeout 3600
```

### Resume interrupted scan

```bash
# Ctrl+C during a scan saves a checkpoint automatically
pacdoor 10.0.0.0/24 --resume
```

### Download templates

```bash
# Bulk-download all Nuclei community templates
pacdoor --download-templates

# Update CVE databases and exit
pacdoor --update-only
```

### Compare scans (diff)

```bash
# Compare old scan against new scan to track remediation
pacdoor --diff ./results-jan/pacdoor.db ./results-mar/pacdoor.db --output-dir ./diff-report
```

### Report formats

```bash
# Default: HTML + JSON
pacdoor 10.0.0.0/24

# All formats
pacdoor 10.0.0.0/24 --report-format html json markdown pdf bloodhound

# Just BloodHound export
pacdoor 10.0.0.0/24 --report-format bloodhound

# Custom output directory
pacdoor 10.0.0.0/24 --output-dir /pentest/client-abc/
```

### Headless mode (no TUI)

```bash
# Log to stderr instead of TUI
pacdoor 10.0.0.0/24 --no-tui

# Useful for automation / CI
pacdoor 10.0.0.0/24 --no-tui --report-format json --output-dir /results
```

---

## Architecture Overview

PACDOOR uses a **fact-driven reactive planner**. Modules declare what fact types they require as input and what they produce as output. The planner watches the central fact store and dispatches modules the moment their prerequisites are satisfied.

```
                          +-------------------+
                          |   Fact Store      |
                          |  (central state)  |
                          +--------+----------+
                                   |
              reads/writes         |         reads
         +-------------------------+-------------------------+
         |                         |                         |
   +-----v------+          +------v-------+          +------v-------+
   |   Planner  |          |    Engine    |          |   Reporter   |
   | (scheduler)|          | (orchestrator)|         | (HTML/JSON)  |
   +-----+------+          +------+-------+          +--------------+
         |                         |
         |  dispatches             |  callbacks
         v                         v
   +------------------------------------------+
   |            Module Pipeline               |
   |                                          |
   |  RECON ---> ENUM ---> VULN ---> EXPLOIT  |
   |    |          |         |          |     |
   |    v          v         v          v     |
   |   POST <--- LATERAL (loop max 3x) ------+
   +------------------------------------------+
```

### How modules chain

1. **Reconnaissance** -- Host discovery and port scanning produce `host` and `port.open` facts
2. **Enumeration** -- Service-specific modules consume `port.open` + `service.*` facts, produce `service.smb`, `webapp.*`, `domain.*`, etc.
3. **Vulnerability Scanning** -- Consumes service facts, produces `vuln.*` facts
4. **Exploitation** -- Consumes `vuln.*` facts, produces `credential.valid` and `credential.admin` facts
5. **Post-Exploitation** -- Consumes credentials, produces additional credentials, GPP passwords, hashes, DPAPI secrets
6. **Lateral Movement** -- Uses harvested credentials to access new hosts, producing `host.lateral` facts that restart the pipeline

Per-host pipelines run in parallel (default: 10 concurrent hosts), so a /24 scan processes multiple hosts through the full pipeline simultaneously.

### Module Table

| # | Module | Phase | Description |
|---|--------|-------|-------------|
| 1 | `recon.host_discovery` | Recon | Discover live hosts via TCP ping sweep |
| 2 | `recon.port_scan` | Recon | TCP connect scan on discovered hosts |
| 3 | `recon.udp_scan` | Recon | UDP scan on discovered hosts (top 20 UDP ports) |
| 4 | `recon.service_detect` | Recon | Banner grabbing and service version detection |
| 5 | `recon.os_detect` | Recon | OS fingerprinting from network behaviour |
| 6 | `recon.nmap_scan` | Recon | Nmap SYN scan with service detection, OS fingerprinting, and NSE scripts |
| 7 | `recon.screenshot` | Recon | Capture screenshots of HTTP services for visual evidence |
| 8 | `recon.wifi_recon` | Recon | Cross-platform wireless network scanning, rogue AP detection, WEP/WPA assessment |
| 9 | `enum.smb_enum` | Enum | SMB enumeration -- signing, null sessions, shares, users |
| 10 | `enum.ssh_enum` | Enum | SSH enumeration -- auth methods, weak algorithms, banner CVEs |
| 11 | `enum.ftp_enum` | Enum | FTP enumeration -- anonymous access, writable dirs, TLS, files |
| 12 | `enum.http_enum` | Enum | HTTP directory bruteforce and technology fingerprinting |
| 13 | `enum.dns_enum` | Enum | DNS enumeration -- zone transfers, records, open resolver, DNSSEC |
| 14 | `enum.ldap_enum` | Enum | LDAP enumeration -- anonymous bind, users, SPNs, password policy |
| 15 | `enum.mssql_enum` | Enum | MSSQL enumeration -- version, databases, xp_cmdshell, linked servers |
| 16 | `enum.mysql_enum` | Enum | MySQL enumeration -- version, databases, privileges |
| 17 | `enum.redis_enum` | Enum | Redis enumeration -- auth check, INFO, writable config, modules |
| 18 | `enum.mongo_enum` | Enum | MongoDB enumeration -- auth check, databases, server info |
| 19 | `enum.snmp_enum` | Enum | SNMP enumeration -- community string brute-force and system info |
| 20 | `enum.cloud_enum` | Enum | Cloud infrastructure enumeration (IMDS, storage, containers) |
| 21 | `vuln.tls_vulns` | Vuln | TLS/SSL vulnerability scanner -- protocols, certificates, configuration |
| 22 | `vuln.http_vulns` | Vuln | HTTP security header and misconfiguration checks |
| 23 | `vuln.web_vulns` | Vuln | Web application vulnerability scanner (SQLi, XSS, LFI, redirect, SSTI) |
| 24 | `vuln.smb_vulns` | Vuln | SMB vulnerability detection -- EternalBlue, PrintNightmare, PetitPotam, ZeroLogon |
| 25 | `vuln.cve_checker` | Vuln | Correlate service versions against known CVE database |
| 26 | `vuln.default_creds` | Vuln | Try default/vendor credentials on discovered services |
| 27 | `vuln.template_scanner` | Vuln | Nuclei-style YAML template vulnerability scanner |
| 28 | `vuln.nuclei_scan` | Vuln | Nuclei template-based vulnerability scanner (6000+ templates) |
| 29 | `vuln.sqlmap_scan` | Vuln | SQLMap SQL injection scanner -- automated detection and confirmation |
| 30 | `vuln.api_fuzzer` | Vuln | API security testing -- OpenAPI/Swagger/GraphQL discovery, JWT attacks, parameter fuzzing, CORS/IDOR |
| 31 | `exploit.ssh_brute` | Exploit | SSH brute force with common credentials and wordlist |
| 32 | `exploit.credential_spray` | Exploit | Spray discovered credentials across hosts and services |
| 33 | `exploit.kerberoast` | Exploit | Extract Kerberos TGS and AS-REP hashes for offline cracking |
| 34 | `exploit.db_exploits` | Exploit | Database exploitation -- command execution via MSSQL, PostgreSQL, Redis, MySQL |
| 35 | `exploit.adcs_exploit` | Exploit | AD CS certificate abuse -- ESC1/ESC8 exploitation, shadow credentials, PKINIT auth |
| 36 | `exploit.kerberos_abuse` | Exploit | Advanced Kerberos attacks -- delegation abuse (unconstrained/constrained/RBCD), S4U, overpass-the-hash |
| 37 | `exploit.ntlm_coerce` | Exploit | NTLM authentication coercion -- PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce |
| 38 | `exploit.cloud_privesc` | Exploit | Cloud privilege escalation -- AWS IAM/STS, Azure managed identity, GCP service account abuse |
| 39 | `exploit.container_escape` | Exploit | Container security -- Docker socket abuse, K8s SA token, privileged container detection, kernel CVE surface |
| 40 | `post.ad_enum` | Post | Active Directory enumeration via LDAP (BloodHound-style recon) |
| 41 | `post.cred_harvest` | Post | Credential harvesting from compromised hosts |
| 42 | `post.privesc_enum` | Post | Privilege escalation enumeration on compromised hosts |
| 43 | `post.hash_crack` | Post | Crack extracted hashes with hashcat/john or pure-Python NTLM brute |
| 44 | `post.gpp_extract` | Post | Extract and decrypt GPP passwords from SYSVOL (MS14-025) |
| 45 | `post.dpapi_extract` | Post | Extract DPAPI-protected credentials (Chrome, Wi-Fi, RDP) |
| 46 | `post.adcs_enum` | Post | AD CS certificate template misconfiguration detection (ESC1-ESC8) |
| 47 | `post.ssh_pivot` | Post | SSH tunnel pivoting to discover and access internal networks |
| 48 | `post.lateral_move` | Post | Lateral movement using harvested credentials to access new hosts |
| 49 | `post.dcsync` | Post | DCSync credential extraction via DRSUAPI replication (krbtgt, domain admins, all users) |
| 50 | `post.dacl_abuse` | Post | AD DACL/ACL abuse -- detect and exploit GenericAll, WriteDACL, ForceChangePassword, RBCD |
| 51 | `post.lsass_dump` | Post | Remote LSASS credential extraction -- secretsdump, MiniDump, registry hive extraction |
| 52 | `post.edr_evasion` | Post | EDR/AV detection assessment -- AMSI, ETW, Sysmon, endpoint agent coverage, defense gap scoring |
| 53 | `post.verified_proof` | Post | Exploitation proof -- command execution, file canary, sensitive file hash, secret discovery, pivot verification |

---

## Module Development Guide

### Writing a new module

Every module extends `BaseModule` and implements four required properties plus the `run()` method.

```python
"""Example: Custom FTP backdoor checker."""

from pacdoor.core.models import Evidence, Finding, Phase, Severity
from pacdoor.modules.base import BaseModule, ModuleContext


class FtpBackdoorCheck(BaseModule):
    # ---- Required properties ----

    @property
    def name(self) -> str:
        return "vuln.ftp_backdoor"

    @property
    def description(self) -> str:
        return "Check for known FTP backdoors (vsftpd 2.3.4, ProFTPD)"

    @property
    def phase(self) -> Phase:
        return Phase.VULN_SCAN

    @property
    def attack_technique_ids(self) -> list[str]:
        return ["T1190"]  # Exploit Public-Facing Application

    # ---- Fact-based chaining ----

    @property
    def required_facts(self) -> list[str]:
        # This module will only run after FTP services are discovered
        return ["port.open", "service.ftp"]

    @property
    def produced_facts(self) -> list[str]:
        return ["vuln.ftp_backdoor"]

    # ---- Execution ----

    async def run(self, ctx: ModuleContext) -> list[Finding]:
        findings = []

        # Read facts from the central store
        ftp_services = await ctx.facts.get_values("service.ftp")

        for svc in ftp_services:
            # Respect rate limiting
            await ctx.rate_limiter.acquire()

            # ... your detection logic here ...

            if backdoor_detected:
                findings.append(Finding(
                    title="FTP Backdoor: vsftpd 2.3.4",
                    description="The vsftpd 2.3.4 backdoor was detected...",
                    severity=Severity.CRITICAL,
                    host_id=svc.host_id,
                    cve_id="CVE-2011-2523",
                    module_name=self.name,
                    attack_technique_ids=self.attack_technique_ids,
                    evidence=[Evidence(kind="banner", data=svc.banner)],
                    remediation="Upgrade vsftpd to a patched version.",
                ))

                # Push new facts so downstream modules can chain
                await ctx.facts.add(
                    "vuln.ftp_backdoor", svc, self.name, host_id=svc.host_id
                )

        return findings
```

Place the file in `src/pacdoor/modules/vuln/ftp_backdoor.py` (or the appropriate phase directory). The module registry auto-discovers all `BaseModule` subclasses at startup -- no registration code needed.

### Fact types reference

| Fact Type | Produced By | Consumed By |
|-----------|------------|-------------|
| `host` | host_discovery | port_scan, all per-host modules |
| `cidr` | user input | host_discovery |
| `port.open` | port_scan, nmap_scan | service_detect, all enum/vuln modules |
| `service.smb` | service_detect | smb_enum, smb_vulns |
| `service.ssh` | service_detect | ssh_enum, ssh_brute |
| `service.http` | service_detect | http_enum, http_vulns, web_vulns |
| `service.ftp` | service_detect | ftp_enum |
| `service.dns` | service_detect | dns_enum |
| `service.ldap` | service_detect | ldap_enum |
| `service.mssql` | service_detect | mssql_enum, db_exploits |
| `service.mysql` | service_detect | mysql_enum |
| `service.redis` | service_detect | redis_enum |
| `service.mongo` | service_detect | mongo_enum |
| `service.snmp` | service_detect | snmp_enum |
| `credential.valid` | default_creds, ssh_brute, credential_spray | post modules, lateral_move |
| `credential.admin` | cred_harvest, kerberoast | lateral_move, privesc_enum |
| `vuln.*` | vuln modules | exploit modules |
| `host.lateral` | lateral_move | triggers new host pipelines |
| `domain.*` | ldap_enum, ad_enum | kerberoast, adcs_enum |
| `webapp.*` | http_enum | web_vulns, template_scanner |

### Adding YAML vulnerability templates

Place templates in `src/pacdoor/templates/vulns/` using the Nuclei-compatible format:

```yaml
id: exposed-actuator
info:
  name: Spring Boot Actuator Exposed
  severity: high
  tags: misconfig,spring
  reference:
    - https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html

requests:
  - method: GET
    path:
      - "{{BaseURL}}/actuator"
      - "{{BaseURL}}/actuator/env"
    matchers:
      - type: word
        words:
          - '"status":"UP"'
          - '"_links"'
        condition: or
      - type: status
        status:
          - 200
```

---

## CLI Reference

```
usage: pacdoor [-h] [--profile {stealth,aggressive,web,ad,quick}]
               [--exclude [EXCLUDE ...]] [--ports PORTS]
               [--scope-file SCOPE_FILE] [--concurrency CONCURRENCY]
               [--rate-limit RATE_LIMIT] [--timeout TIMEOUT]
               [--conn-timeout CONN_TIMEOUT] [--recon-only] [--no-exploit]
               [--max-safety {safe,moderate,dangerous}] [--resume]
               [--offline] [--update-only] [--download-templates]
               [--diff OLD_DB NEW_DB] [--output-dir OUTPUT_DIR]
               [--report-format {html,json,markdown,pdf,bloodhound} [...]]
               [--no-tui] [-u USERNAME] [-p PASSWORD] [--hash HASH]
               [-d DOMAIN] [--brand-name BRAND_NAME]
               [--classification CLASSIFICATION] [--logo LOGO]
               [--cred-file CRED_FILE] [--module-dir MODULE_DIR]
               [--agent CONFIG]
               [target ...]
```

### Positional arguments

| Argument | Description |
|----------|-------------|
| `target` | Target IP, CIDR range, or hostname (e.g. `10.0.0.0/24`, `192.168.1.5`) |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--profile` | none | Scan profile: `stealth`, `aggressive`, `web`, `ad`, `quick` |
| `--exclude` | none | IPs or CIDRs to exclude from scanning |
| `--ports` | `top1000` | Port spec: `top1000`, `all`, or comma-separated (e.g. `22,80,443`) |
| `--scope-file` | none | File with in-scope IPs/CIDRs/hostnames, one per line |
| `--concurrency` | `20` | Max concurrent module executions |
| `--rate-limit` | `100` | Max requests per second |
| `--timeout` | `0` | Global scan timeout in seconds (0 = unlimited) |
| `--conn-timeout` | `5` | Per-connection timeout in seconds |
| `--recon-only` | off | Only run reconnaissance (no enum/vuln/exploit) |
| `--no-exploit` | off | Scan + enum + vuln but do NOT exploit |
| `--max-safety` | `moderate` | Max exploit safety level: `safe`, `moderate`, `dangerous` |
| `--resume` | off | Resume interrupted scan from checkpoint |
| `--offline` | off | Skip auto-updates, use local data only |
| `--update-only` | off | Update databases and exit (no scanning) |
| `--download-templates` | off | Bulk-download all Nuclei community templates and exit |
| `--diff OLD NEW` | none | Compare two scan databases and generate a diff report |
| `--output-dir` | `./pacdoor-results` | Directory for reports and database |
| `--report-format` | `html json` | Report formats: `html`, `json`, `markdown`, `pdf`, `bloodhound` |
| `--no-tui` | off | Disable TUI, log to stderr |
| `-u` / `--username` | none | Username for authenticated scanning |
| `-p` / `--password` | none | Password for authenticated scanning |
| `--hash` | none | NTLM hash for pass-the-hash |
| `-d` / `--domain` | none | Domain for AD authentication |
| `--brand-name` | none | Company/assessor name for report branding |
| `--classification` | none | Classification marking (e.g. CONFIDENTIAL) |
| `--logo` | none | Path to logo image for report branding |
| `--cred-file` | none | Credential file (one per line: user:pass or user:hash) |
| `--module-dir` | none | Path to external module directory for custom modules |
| `--agent CONFIG` | none | Run as autonomous agent daemon with YAML config file |

---

## Report Formats

### HTML

The default report. A self-contained HTML file with:
- Executive summary with finding counts by severity
- Consolidated findings (deduplicated across hosts with "N hosts affected" badges)
- Per-host detail views with evidence
- Embedded screenshots as base64 data URIs
- MITRE ATT&CK technique mapping
- Attack path visualization

### JSON

Machine-readable output containing both raw and consolidated findings, full host inventory, credentials, and attack paths. Suitable for ingestion into SIEMs, ticketing systems, or custom dashboards.

### Markdown

Text-based report suitable for inclusion in pentest deliverables, wiki pages, or Git repositories.

### BloodHound

Generates a BloodHound CE-compatible ZIP containing `computers.json`, `users.json`, `groups.json`, and `domains.json`. Import directly into BloodHound CE for Active Directory attack path visualization.

```bash
# Generate BloodHound export
pacdoor 10.0.0.0/24 --profile ad -u admin -p pass -d CORP --report-format bloodhound

# Import into BloodHound CE
# Upload the generated .zip via the BloodHound CE web interface
```

---

## Configuration

### Profiles

Profiles set sensible defaults for common scenarios. CLI flags always override profile values.

| Profile | Rate Limit | Concurrency | Ports | Safety | Exploits | Description |
|---------|-----------|-------------|-------|--------|----------|-------------|
| `stealth` | 10/s | 5 | top1000 | safe | disabled | Slow, quiet -- minimize IDS detection |
| `aggressive` | 500/s | 50 | all 65535 | dangerous | enabled | Full speed, all modules, all exploits |
| `web` | 100/s | 20 | 80,443,8080,... | moderate | enabled | Web application focused |
| `ad` | 100/s | 20 | AD ports | moderate | enabled | Active Directory focused |
| `quick` | 200/s | 30 | common 10 | safe | disabled | Fast recon and basic enumeration |

### Scope files

Create a text file with one target per line:

```
# scope.txt -- lines starting with # are ignored
10.0.0.0/24
192.168.1.0/24
dc01.corp.local
webapp.example.com
```

```bash
pacdoor 10.0.0.0/24 --scope-file scope.txt
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `PACDOOR_OUTPUT_DIR` | Default output directory |
| `PACDOOR_NMAP_PATH` | Path to nmap binary (if not on PATH) |
| `PACDOOR_NUCLEI_PATH` | Path to nuclei binary (if not on PATH) |
| `PACDOOR_SQLMAP_PATH` | Path to sqlmap (if not on PATH) |

---

## Output Structure

```
pacdoor-results/
  pacdoor.db              # SQLite database with all findings
  report.html             # HTML report
  report.json             # JSON report
  report.md               # Markdown report (if requested)
  bloodhound.zip          # BloodHound CE import (if requested)
  screenshots/            # HTTP service screenshots
  checkpoint.json         # Resume checkpoint (deleted on completion)
```

---

## Agent Mode

PACDOOR supports an autonomous agent mode for continuous security monitoring. Create a YAML configuration file and run:

```bash
pacdoor --agent config.yaml
```

Example configuration:

```yaml
agent:
  targets:
    - 10.0.0.0/24
    - 192.168.1.0/24
  exclude:
    - 10.0.0.1
  schedules:
    - name: daily_recon
      profile: quick
      interval: 24h
    - name: weekly_full
      profile: aggressive
      interval: 7d
      credentials:
        username: svc_scan
        password: "${SCAN_PASSWORD}"
        domain: CORP.LOCAL
  behavior:
    max_safety: moderate
    adaptive: true
    escalation: "off"              # "off" or "progressive" — whether to escalate scan intensity over time
    escalation_after_hours: 3      # hours before escalation kicks in (only used when escalation is "progressive")
    concurrent_scans: 1
  output:
    dir: ./pacdoor-results
    reports: [html, json]
    retain_runs: 30
  notifications:
    on_critical: true
    summary_after_each: true
```

The agent daemon:
- Runs scheduled scans at configurable intervals
- Tracks findings across runs (new, persistent, fixed)
- Adapts scan strategy based on discovered environment (AD-heavy, web-heavy, etc.)
- Manages PID files and graceful shutdown on SIGINT/SIGTERM

---

## Development

### Prerequisites

- Python 3.11+
- Git

### Setup

```bash
git clone https://github.com/msothman/pacdoor.git
cd pacdoor
pip install -e ".[all,dev]"
```

### Running tests

```bash
pytest tests/ -v
```

### Linting and type checking

```bash
ruff check src/
mypy src/pacdoor/ --ignore-missing-imports
```

### Project structure

```
src/pacdoor/
  core/             Engine, planner, fact store, scope, safety, models
  modules/
    recon/          Host discovery, port scan, service detection, OS fingerprinting
    enum/           SMB, LDAP, HTTP, SSH, FTP, DNS, Redis, MongoDB, MySQL, MSSQL, SNMP, cloud
    vuln/           CVE correlation, default creds, web vulns, TLS, template scanner
    exploit/        Kerberoast, credential spray, SSH brute, ADCS, NTLM coerce
    post/           AD enum, cred harvest, DCSync, DPAPI, lateral movement, LSASS
  agent/            Autonomous daemon, scheduler, adaptive strategy, campaign tracking
  report/           HTML/JSON/Markdown/BloodHound generation, compliance mapping
  tui/              Real-time Textual terminal dashboard
  db/               Async SQLite with encrypted credential storage
  updater/          Auto-update NVD CVEs, Nuclei templates, MITRE ATT&CK
  data/             Default credentials, wordlists
  templates/        Nuclei-style YAML vulnerability templates
```

---

## Legal Disclaimer

PACDOOR is designed for **authorized security testing only**. By using this tool, you agree that:

1. You have **explicit written authorization** to test the target systems
2. You will only use PACDOOR within the scope defined by your authorization
3. You accept full responsibility for any actions performed with this tool
4. Unauthorized access to computer systems is illegal in most jurisdictions

The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before conducting any security assessment.

---

## License

MIT

# SubHunter — Advanced Subdomain Discovery Framework

```
 ██████╗ ██╗   ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██╔════╝ ██║   ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
╚█████╗  ██║   ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ╚═══██╗ ██║   ██║██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██████╔╝ ╚██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═════╝   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

           ━━━  Advanced Subdomain Discovery Framework v2.0  ━━━
           ━━━  Passive │ Active │ API-Enriched │ Production   ━━━
```

Multi-source subdomain enumeration with concurrent passive tools, 10 API integrations, active brute-force, and DNS resolution.

---

## Architecture

```
subhunter.py
│
├── Phase 1: Passive CLI Tools (ThreadPoolExecutor)
│   ├── subfinder      — ProjectDiscovery multi-source
│   ├── amass          — OWASP passive mode
│   ├── assetfinder    — tomnomnom fast passive
│   ├── findomain      — Rust-based, cert/DNS sources
│   ├── chaos          — ProjectDiscovery dataset
│   ├── crobat         — Rapid7 Sonar dataset
│   └── shuffledns     — passive resolve mode
│
├── Phase 2: API Sources (asyncio concurrent)
│   ├── crt.sh         — certificate transparency (no key)
│   ├── HackerTarget   — free tier (no key)
│   ├── ThreatCrowd    — threat intel (no key)
│   ├── SecurityTrails — commercial API
│   ├── VirusTotal     — paginated subdomain API
│   ├── Shodan         — DNS reverse lookup
│   ├── BinaryEdge     — paginated domain search
│   ├── Censys         — certificate search v2
│   ├── ZoomEye        — Chinese OSINT platform
│   └── DNSDumpster    — CSRF-scraped web query
│
├── Phase 3: Normalization
│   └── Lowercase, strip wildcards, validate regex, filter to base domain
│
├── Phase 4: Active Brute-Force (puredns)
│   └── DNS brute against wordlist with resolver rotation
│
└── Phase 5: DNS Resolution (dnsx)
    └── 100-thread concurrent resolution with retry
```

---

## Output Structure

```
output/
└── example.com/
    ├── raw.txt         # All unique normalized subdomains (pre-resolution)
    ├── resolved.txt    # DNS-verified live subdomains
    ├── final.txt       # Final clean output (same as resolved)
    ├── brute_raw.txt   # Raw puredns brute output (if --no-brute not set)
    ├── results.json    # Structured JSON output (if --json flag used)
    └── subhunter.log   # Per-domain log file with timestamps
```

---

## Installation

```bash
# Clone
git clone https://github.com/yourhandle/subhunter
cd subhunter

# Install all dependencies
chmod +x install.sh
sudo ./install.sh

# Manually verify tools
which subfinder amass assetfinder findomain dnsx puredns crobat shuffledns
```

### Manual Go Tool Install

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/cgboal/sonarsearch/cmd/crobat@latest
go install github.com/d3mondev/puredns/v2@latest
export PATH=$PATH:$(go env GOPATH)/bin
```

---

## Configuration

Copy and edit `config.yaml`:

```yaml
securitytrails: "YOUR_API_KEY"
virustotal:     "YOUR_API_KEY"
shodan:         "YOUR_API_KEY"
censys_id:      "YOUR_ID"
censys_secret:  "YOUR_SECRET"
zoomeye:        "YOUR_API_KEY"
binaryedge:     "YOUR_API_KEY"
chaos:          "YOUR_API_KEY"

rate_limit_delay: 1
tool_timeout: 300
resolvers_file: "/tmp/subhunter_resolvers.txt"
wordlist: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
```

Missing or empty keys are gracefully skipped — no crashes.

---

## Usage

### Basic Single Domain

```bash
python3 subhunter.py -d example.com
```

### Multi-Target from File

```bash
python3 subhunter.py -l targets.txt
```

### Passive + API Only (No Brute, No Resolve)

```bash
python3 subhunter.py -d example.com --no-brute --no-resolve
```

### API Sources Only (Skip CLI Tools)

```bash
python3 subhunter.py -d example.com --no-passive
```

### Silent Mode + JSON Output

```bash
python3 subhunter.py -d example.com --silent --json
```

### Full Scan with Custom Config

```bash
python3 subhunter.py -d example.com -c /path/to/config.yaml --json
```

### Skip API Sources (Air-Gapped / Rate-Limited)

```bash
python3 subhunter.py -d example.com --no-api
```

---

## Flags Reference

| Flag           | Description                                        |
|----------------|----------------------------------------------------|
| `-d DOMAIN`    | Single target domain                               |
| `-l FILE`      | File with one domain per line                      |
| `-c CONFIG`    | Path to config.yaml (default: ./config.yaml)       |
| `--silent`     | Suppress subdomain list stdout, keep summary       |
| `--json`       | Write results.json per domain                      |
| `--no-resolve` | Skip dnsx resolution phase                         |
| `--no-brute`   | Skip puredns active brute-force                    |
| `--no-passive` | Skip all CLI passive tools                         |
| `--no-api`     | Skip all API-based sources                         |

---

## API Key Sources

| Service        | URL                                                        |
|----------------|------------------------------------------------------------|
| SecurityTrails | https://securitytrails.com/app/account/credentials         |
| VirusTotal     | https://www.virustotal.com/gui/my-apikey                   |
| Shodan         | https://account.shodan.io/                                 |
| Censys         | https://search.censys.io/account/api                       |
| ZoomEye        | https://www.zoomeye.org/profile                            |
| BinaryEdge     | https://www.binaryedge.io/pricing.html                     |
| Chaos          | https://chaos.projectdiscovery.io/ (invite-only)           |

Free sources (no key needed): crt.sh, HackerTarget, ThreatCrowd, DNSDumpster

---

## Extending SubHunter

Adding a new passive CLI tool:
```python
def mod_mytool(domain: str, cfg: dict) -> set:
    if not available("mytool"):
        return set()
    tag_run("mytool")
    rc, out, _ = run_cmd(["mytool", domain], cfg["tool_timeout"])
    results = parse_lines(out)
    tag_found(len(results), "mytool")
    return results

# Then add to PASSIVE_MODULES list
PASSIVE_MODULES.append(mod_mytool)
```

Adding a new async API source:
```python
async def api_myservice(domain: str, cfg: dict, sess: aiohttp.ClientSession) -> set:
    key = cfg.get("myservice", "")
    if not key:
        return set()
    tag_run("MyService")
    results = set()
    # ... fetch logic ...
    tag_found(len(results), "MyService")
    return results

# Add to tasks list in collect_api_results()
```

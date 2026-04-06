# SubHunter

```
 ██████╗ ██╗   ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██╔════╝ ██║   ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
╚█████╗  ██║   ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ╚═══██╗ ██║   ██║██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██████╔╝ ╚██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═════╝   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

**Advanced Subdomain Discovery Framework**

Multi-source subdomain enumeration across passive CLI tools, 10 API integrations, active DNS brute-force, and resolution — all running concurrently in a single pipeline. Built for bug bounty recon and penetration testing on Linux.

---

## Features

- **7 passive CLI tools** — subfinder, amass, assetfinder, findomain, chaos, crobat, shuffledns
- **10 API sources** — SecurityTrails, VirusTotal, Shodan, Censys, BinaryEdge, ZoomEye, crt.sh, HackerTarget, ThreatCrowd, DNSDumpster
- **Active brute-force** via puredns with resolver rotation
- **DNS resolution** via dnsx with 100-thread concurrency and retry
- **Concurrent execution** — CLI tools in ThreadPoolExecutor, APIs in asyncio
- **Graceful degradation** — missing tools and absent API keys are silently skipped, never crash
- **Structured output** — per-domain folder with raw, resolved, final, JSON, and log files
- **Rate limit handling** — configurable delay between paginated API calls
- **Domain normalization** — wildcard stripping, regex validation, base-domain enforcement

---

## How It Works

```
Input (domain / list)
        │
        ▼
┌───────────────────────────────────────────────┐
│  Phase 1 — Passive CLI Tools (concurrent)     │
│  subfinder · amass · assetfinder · findomain  │
│  chaos · crobat · shuffledns                  │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│  Phase 2 — API Sources (async concurrent)     │
│  crt.sh · HackerTarget · ThreatCrowd         │
│  SecurityTrails · VirusTotal · Shodan         │
│  BinaryEdge · Censys · ZoomEye · DNSDumpster  │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│  Phase 3 — Normalize & Deduplicate            │
│  Lowercase · strip wildcards · regex validate │
│  enforce subdomain-of-base filter             │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│  Phase 4 — Active Brute-Force (puredns)       │
│  Wordlist bruteforce with resolver rotation   │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────┐
│  Phase 5 — DNS Resolution (dnsx)              │
│  100-thread concurrent resolution with retry  │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
              Structured Output Files
```

---

## Output Structure

```
output/
└── example.com/
    ├── raw.txt          # All unique normalized subdomains (pre-resolution)
    ├── resolved.txt     # DNS-verified live subdomains
    ├── final.txt        # Final clean output
    ├── brute_raw.txt    # Raw puredns output (active phase)
    ├── results.json     # Structured JSON (--json flag)
    └── subhunter.log    # Timestamped per-run log
```

---

## Requirements

- Python 3.10+
- Linux (Debian / Ubuntu / Kali recommended)
- Go 1.20+ (for CLI tool installation)

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourhandle/subhunter.git
cd subhunter
```

### 2. Install Python dependencies

```bash
pip3 install -r requirements.txt
```

### 3. Install CLI tools (automated)

```bash
chmod +x install.sh
sudo ./install.sh
```

This installs: subfinder, dnsx, shuffledns, assetfinder, chaos, crobat, puredns, findomain, amass, and SecLists.

### 4. Manual Go tool install (if preferred)

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/cgboal/sonarsearch/cmd/crobat@latest
go install github.com/d3mondev/puredns/v2@latest

export PATH=$PATH:$(go env GOPATH)/bin
```

Add the export to `~/.bashrc` to make it persistent.

### 5. Verify installed tools

```bash
which subfinder amass assetfinder findomain dnsx puredns shuffledns crobat
```

---

## Configuration

Edit `config.yaml` to add API keys. All keys are optional — missing or empty values are silently skipped.

```yaml
# API Keys
securitytrails: ""
virustotal:     ""
shodan:         ""
censys_id:      ""
censys_secret:  ""
zoomeye:        ""
binaryedge:     ""
chaos:          ""

# Performance
rate_limit_delay: 1      # seconds between paginated API calls
tool_timeout: 300        # per-tool timeout in seconds

# Active Phase
resolvers_file: "/tmp/subhunter_resolvers.txt"
wordlist: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
```

### Where to get API keys

| Source | Free Tier | URL |
|---|---|---|
| SecurityTrails | 50 req/month | https://securitytrails.com/app/account/credentials |
| VirusTotal | 500 req/day | https://www.virustotal.com/gui/my-apikey |
| Shodan | Limited | https://account.shodan.io |
| Censys | 250 req/month | https://search.censys.io/account/api |
| ZoomEye | 10,000 req/month | https://www.zoomeye.org/profile |
| BinaryEdge | Paid only | https://www.binaryedge.io/pricing.html |
| Chaos | Invite only | https://chaos.projectdiscovery.io |

The following sources require **no API key**: crt.sh, HackerTarget, ThreatCrowd, DNSDumpster.

---

## Usage

### Single domain

```bash
python3 subhunter.py -d example.com
```

### Multiple domains from file

```bash
python3 subhunter.py -l targets.txt
```

### API-only fast mode (no CLI tools, no brute-force)

```bash
python3 subhunter.py -d example.com --no-passive --no-brute
```

### Passive tools only (no APIs, no brute-force, no resolution)

```bash
python3 subhunter.py -d example.com --no-api --no-brute --no-resolve
```

### Silent output with JSON export

```bash
python3 subhunter.py -d example.com --silent --json
```

### Full scan with custom config path

```bash
python3 subhunter.py -d example.com -c /path/to/config.yaml --json
```

### Pipeline into httpx

```bash
python3 subhunter.py -d example.com --silent --no-brute 2>/dev/null
cat output/example.com/resolved.txt | httpx -silent -title -status-code
```

### Chain into nuclei

```bash
python3 subhunter.py -d example.com --silent --no-brute 2>/dev/null
nuclei -l output/example.com/resolved.txt -t ~/nuclei-templates/
```

---

## Flags

| Flag | Description |
|---|---|
| `-d DOMAIN` | Single target domain |
| `-l FILE` | File with one domain per line (`#` lines ignored) |
| `-c CONFIG` | Path to config YAML (default: `./config.yaml`) |
| `--silent` | Suppress per-subdomain stdout, keep summary |
| `--json` | Write `results.json` per target domain |
| `--no-resolve` | Skip dnsx DNS resolution phase |
| `--no-brute` | Skip puredns active brute-force phase |
| `--no-passive` | Skip all passive CLI tools |
| `--no-api` | Skip all API-based sources |

---

## JSON Output Format

When `--json` is used, a `results.json` is written per domain:

```json
{
  "domain": "example.com",
  "raw_count": 843,
  "normalized_count": 791,
  "resolved_count": 412,
  "resolved": [
    "api.example.com",
    "app.example.com",
    "dev.example.com"
  ],
  "elapsed_seconds": 47.3,
  "timestamp": "2025-01-15T10:22:31Z"
}
```

---

## Extending SubHunter

### Add a passive CLI tool

```python
def mod_mytool(domain: str, cfg: dict) -> set:
    if not available("mytool"):
        tag_warn("mytool: not installed, skipping")
        return set()
    tag_run("mytool")
    rc, out, _ = run_cmd(["mytool", "-d", domain], cfg["tool_timeout"])
    results = parse_lines(out)
    tag_found(len(results), "mytool")
    return results

# Register it at the bottom of the file
PASSIVE_MODULES.append(mod_mytool)
```

### Add an async API source

```python
async def api_myservice(domain: str, cfg: dict, sess: aiohttp.ClientSession) -> set:
    key = cfg.get("myservice", "")
    if not key:
        return set()
    tag_run("MyService")
    results = set()
    data = await _get_json(sess, f"https://api.myservice.io/subdomains/{domain}",
                           headers={"Authorization": f"Bearer {key}"})
    if data:
        results.update(data.get("subdomains", []))
    tag_found(len(results), "MyService")
    return results

# Add to the tasks list inside collect_api_results()
tasks.append(api_myservice(domain, cfg, sess))
```

---

## Technical Notes

**Concurrency model** — Passive CLI tools run in a `ThreadPoolExecutor` since they're subprocess-bound. All API sources fire simultaneously via `asyncio.gather()`. Neither phase blocks the other.

**Normalization** — The pipeline enforces a strict regex (`^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`), strips wildcard prefixes, and hard-filters results to the target base domain. Sources like ThreatCrowd routinely return unrelated domains without this filter.

**DNSDumpster** — Has no public API. The integration scrapes the CSRF token from the homepage, reuses the session cookie, then replays the POST request. May break if they update their frontend.

**ZoomEye** — Authentication uses the API key as a password with an empty username against their JWT endpoint, which is undocumented but functional.

**Resolver fallback** — If the `resolvers_file` path doesn't exist, a default list of 10 public resolvers is written automatically.

**dnsx fallback** — If dnsx is not installed, the resolved output falls back to the full normalized set with a `[WARN]` — the pipeline does not abort.

---

## Legal

This tool is intended for **authorized security testing and bug bounty programs only**. Always obtain explicit written permission before running enumeration against any target. The authors accept no responsibility for misuse.

---

## License

MIT

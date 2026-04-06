#!/usr/bin/env python3
"""
SubHunter - Advanced Subdomain Discovery Framework v2.0
Multi-source passive + active + API-enriched enumeration
"""

import asyncio
import aiohttp
import argparse
import base64
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import yaml
from datetime import datetime
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Terminal Colors ─────────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def tag_info(msg):     print(f"{C.CYAN}[INFO]{C.RESET}    {msg}")
def tag_run(msg):      print(f"{C.BLUE}[RUNNING]{C.RESET} {msg}")
def tag_ok(msg):       print(f"{C.GREEN}[SUCCESS]{C.RESET} {msg}")
def tag_err(msg):      print(f"{C.RED}[ERROR]{C.RESET}   {msg}")
def tag_warn(msg):     print(f"{C.YELLOW}[WARN]{C.RESET}    {msg}")
def tag_found(n, src): print(f"{C.MAGENTA}[FOUND]{C.RESET}   {C.BOLD}{n}{C.RESET} subdomains ← {C.CYAN}{src}{C.RESET}")

# ─── ASCII Banner ─────────────────────────────────────────────────────────────────
BANNER = f"""{C.CYAN}{C.BOLD}
 ██████╗ ██╗   ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██╔════╝ ██║   ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
╚█████╗  ██║   ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ╚═══██╗ ██║   ██║██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██████╔╝ ╚██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═════╝   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{C.RESET}{C.DIM}
           ━━━  Advanced Subdomain Discovery Framework v2.0  ━━━
           ━━━  Passive │ Active │ API-Enriched │ Production   ━━━
{C.RESET}"""

# ─── Default Config ───────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "securitytrails":   "",
    "virustotal":       "",
    "shodan":           "",
    "censys_id":        "",
    "censys_secret":    "",
    "zoomeye":          "",
    "binaryedge":       "",
    "chaos":            "",
    "rate_limit_delay": 1,
    "tool_timeout":     300,
    "resolvers_file":   "/tmp/subhunter_resolvers.txt",
    "wordlist":         "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
}

def load_config(config_path: str = "config.yaml") -> dict:
    config = DEFAULT_CONFIG.copy()
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                user_cfg = yaml.safe_load(f) or {}
            config.update({k: v for k, v in user_cfg.items() if v is not None})
            tag_info(f"Config loaded from {C.BOLD}{config_path}{C.RESET}")
        except Exception as e:
            tag_warn(f"Config parse error ({e}), using defaults")
    else:
        tag_warn(f"No config.yaml found — API keys unavailable")
    return config

# ─── Output / Logging ─────────────────────────────────────────────────────────────
class OutputManager:
    def __init__(self, domain: str, base_dir: str = "output"):
        self.domain = domain
        self.dir = Path(base_dir) / domain
        self.dir.mkdir(parents=True, exist_ok=True)
        self.raw_file      = self.dir / "raw.txt"
        self.resolved_file = self.dir / "resolved.txt"
        self.final_file    = self.dir / "final.txt"
        self.json_file     = self.dir / "results.json"
        self.log_file      = self.dir / "subhunter.log"
        # File logger
        self._logger = logging.getLogger(domain)
        self._logger.setLevel(logging.DEBUG)
        if not self._logger.handlers:
            fh = logging.FileHandler(self.log_file)
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
            self._logger.addHandler(fh)

    def _write(self, path, data: set):
        with open(path, "w") as f:
            f.write("\n".join(sorted(data)) + "\n" if data else "")

    def write_raw(self, s: set):      self._write(self.raw_file, s)
    def write_resolved(self, s: set): self._write(self.resolved_file, s)
    def write_final(self, s: set):    self._write(self.final_file, s)
    def log(self, msg: str):          self._logger.info(msg)

# ─── Domain Normalization ─────────────────────────────────────────────────────────
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE
)

def normalize(domain: str, base: str) -> Optional[str]:
    d = domain.strip().lower().lstrip("*.")
    if not d or not _DOMAIN_RE.match(d):
        return None
    if d != base and not d.endswith(f".{base}"):
        return None
    return d

def normalize_set(raw: set, base: str) -> set:
    result = set()
    for d in raw:
        n = normalize(d, base)
        if n:
            result.add(n)
    return result

# ─── External Tool Helpers ────────────────────────────────────────────────────────
def available(tool: str) -> bool:
    return shutil.which(tool) is not None

def run_cmd(cmd: list, timeout: int = 300, env: dict = None) -> tuple:
    """Returns (returncode, stdout, stderr). rc=-2 means tool not found."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=timeout,
            env={**os.environ, **(env or {})},
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout after {timeout}s"
    except FileNotFoundError:
        return -2, "", f"Not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)

def parse_lines(text: str) -> set:
    return {l.strip() for l in text.splitlines() if l.strip()}

# ─── Passive CLI Tool Modules ─────────────────────────────────────────────────────

def mod_subfinder(domain: str, cfg: dict) -> set:
    if not available("subfinder"):
        tag_warn("subfinder: not installed, skipping")
        return set()
    tag_run("subfinder")
    rc, out, _ = run_cmd(["subfinder", "-d", domain, "-silent", "-all"], cfg["tool_timeout"])
    results = parse_lines(out)
    tag_found(len(results), "subfinder")
    return results


def mod_amass(domain: str, cfg: dict) -> set:
    if not available("amass"):
        tag_warn("amass: not installed, skipping")
        return set()
    tag_run("amass (passive)")
    rc, out, _ = run_cmd(["amass", "enum", "-passive", "-d", domain, "-silent"], cfg["tool_timeout"])
    results = parse_lines(out)
    tag_found(len(results), "amass")
    return results


def mod_assetfinder(domain: str, cfg: dict) -> set:
    if not available("assetfinder"):
        tag_warn("assetfinder: not installed, skipping")
        return set()
    tag_run("assetfinder")
    rc, out, _ = run_cmd(["assetfinder", "--subs-only", domain], cfg["tool_timeout"])
    results = parse_lines(out)
    tag_found(len(results), "assetfinder")
    return results


def mod_findomain(domain: str, cfg: dict) -> set:
    if not available("findomain"):
        tag_warn("findomain: not installed, skipping")
        return set()
    tag_run("findomain")
    rc, out, _ = run_cmd(["findomain", "-t", domain, "-q"], cfg["tool_timeout"])
    results = parse_lines(out)
    tag_found(len(results), "findomain")
    return results


def mod_chaos(domain: str, cfg: dict) -> set:
    if not available("chaos"):
        tag_warn("chaos: not installed, skipping")
        return set()
    key = cfg.get("chaos", "")
    if not key:
        tag_warn("chaos: API key not set, skipping")
        return set()
    tag_run("chaos (ProjectDiscovery)")
    rc, out, _ = run_cmd(["chaos", "-d", domain, "-silent"], cfg["tool_timeout"], {"CHAOS_KEY": key})
    results = parse_lines(out)
    tag_found(len(results), "chaos")
    return results


def mod_crobat(domain: str, cfg: dict) -> set:
    if not available("crobat"):
        tag_warn("crobat: not installed, skipping")
        return set()
    tag_run("crobat")
    rc, out, _ = run_cmd(["crobat", "-s", domain], cfg["tool_timeout"])
    results = parse_lines(out)
    tag_found(len(results), "crobat")
    return results


def mod_shuffledns(domain: str, cfg: dict) -> set:
    if not available("shuffledns"):
        tag_warn("shuffledns: not installed, skipping")
        return set()
    tag_run("shuffledns (passive resolve)")
    rc, out, _ = run_cmd(
        ["shuffledns", "-d", domain, "-mode", "resolve", "-silent"],
        cfg["tool_timeout"]
    )
    results = parse_lines(out)
    tag_found(len(results), "shuffledns")
    return results

# ─── API-Based Source Modules (async) ────────────────────────────────────────────

async def _get_json(session, url, **kw):
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30), **kw) as r:
        if r.status == 200:
            return await r.json(content_type=None)
        return None

async def _get_text(session, url, **kw):
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30), **kw) as r:
        if r.status == 200:
            return await r.text()
        return None


async def api_crtsh(domain: str, cfg: dict, sess: aiohttp.ClientSession) -> set:
    tag_run("crt.sh")
    results = set()
    try:
        data = await _get_json(sess, f"https://crt.sh/?q=%.{domain}&output=json")
        if data:
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    results.add(name.strip().lstrip("*."))
        tag_found(len(results), "crt.sh")
    except Exception as e:
        tag_err(f"crt.sh: {e}")
    return results


async def api_hackertarget(domain: str, cfg: dict, sess: aiohttp.ClientSession) -> set:
    tag_run("HackerTarget")
    results = set()
    try:
        text = await _get_text(sess, f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if text and "API count exceeded" not in text and "error" not in text.lower()[:50]:
            for line in text.splitlines():
                parts = line.split(",")
                if parts:
                    results.add(parts[0].strip())
        tag_found(len(results), "HackerTarget")
    except Exception as e:
        tag_err(f"HackerTarget: {e}")
    return results


async def api_threatcrowd(domain: str, cfg: dict, sess: aiohttp.ClientSession) -> set:
    tag_run("ThreatCrowd")
    results = set()
    try:
        data = await _get_json(sess, f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}")
        if data:
            results.update(data.get("subdomains", []))
        tag_found(len(results), "ThreatCrowd")
    except Exception as e:
        tag_err(f"ThreatCrowd: {e}")
    return results


async def api_securitytrails(domain: str, cfg: dict, sess: aiohttp.ClientSession) -> set:
    key = cfg.get("securitytrails", "")
    if not key:
        return set()
    tag_run("SecurityTrails")
    results = set()
    try:
        data = await _get_json(sess, f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                               headers={"APIKEY": key})
        if data:
            results = {f"{s}.{domain}" for s in data.get("subdomains", [])}
        tag_found(len(results), "SecurityTrails")
    except Exception as e:
        tag_err(f"SecurityTrails: {e}")
    return results


async def api_virustotal(domain: str, cfg: dict, sess: aiohttp.ClientSession) -> set:
    key = cfg.get("virustotal", "")
    if not key:
        return set()
    tag_run("VirusTotal")
    results = set()
    headers = {"x-apikey": key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    cursor = None
    try:
        while True:
            params = {"limit": 40}
            if cursor:
                params["cursor"] = cursor
            async with sess.get(url, headers=headers, params=params,
                                timeout=aiohttp.ClientTimeout(total=30)) as r:
                if r.status != 200:
                    break
                data = await r.json()
                for item in data.get("data", []):
                    results.add(item.get("id", ""))
                cursor = data.get("meta", {}).get("cursor")
                if not cursor:
                    break
                await asyncio.sleep(cfg.get("rate_limit_delay", 1))
        tag_found(len(results), "VirusTotal")
    except Exception as e:
        tag_err(f"VirusTotal: {e}")
    return results


async def api_shodan(domain: str, cfg: dict, sess: aiohttp.ClientSession) -> set:
    key = cfg.get("shodan", "")
    if not key:
        return set()
    tag_run("Shodan")
    results = set()
    try:
        data = await _get_json(sess, f"https://api.shodan.io/dns/domain/{domain}",
                               params={"key": key})
        if data:
            for sub in data.get("subdomains", []):
                results.add(f"{sub}.{domain}")
        tag_found(len(results), "Shodan")
    except Exception as e:
        tag_err(f"Shodan: {e}")
    return results


async def api_binaryedge(domain: str, cfg: dict, sess: aiohttp.ClientSession) -> set:
    key = cfg.get("binaryedge", "")
    if not key:
        return set()
    tag_run("BinaryEdge")
    results = set()
    headers = {"X-Key": key}
    url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
    try:
        page = 1
        while True:
            async with sess.get(url, headers=headers, params={"page": page},
                                timeout=aiohttp.ClientTimeout(total=30)) as r:
                if r.status != 200:
                    break
                data = await r.json()
                events = data.get("events", [])
                if not events:
                    break
                results.update(events)
                total_pages = max(1, data.get("total", 0) // data.get("pagesize", 100) + 1)
                if page >= min(total_pages, 10):  # cap at 10 pages
                    break
                page += 1
                await asyncio.sleep(cfg.get("rate_limit_delay", 1))
        tag_found(len(results), "BinaryEdge")
    except Exception as e:
        tag_err(f"BinaryEdge: {e}")
    return results


async def api_censys(domain: str, cfg: dict, sess: aiohttp.ClientSession) -> set:
    uid = cfg.get("censys_id", "")
    secret = cfg.get("censys_secret", "")
    if not uid or not secret:
        return set()
    tag_run("Censys")
    results = set()
    creds = base64.b64encode(f"{uid}:{secret}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}", "Content-Type": "application/json"}
    url = "https://search.censys.io/api/v2/certificates/search"
    try:
        payload = {"q": f"parsed.names: {domain}", "per_page": 100, "fields": ["parsed.names"]}
        async with sess.post(url, headers=headers, json=payload,
                             timeout=aiohttp.ClientTimeout(total=30)) as r:
            if r.status == 200:
                data = await r.json()
                for hit in data.get("result", {}).get("hits", []):
                    for name in hit.get("parsed.names", []):
                        results.add(name.lstrip("*."))
            else:
                tag_warn(f"Censys: HTTP {r.status}")
        tag_found(len(results), "Censys")
    except Exception as e:
        tag_err(f"Censys: {e}")
    return results


async def api_zoomeye(domain: str, cfg: dict, sess: aiohttp.ClientSession) -> set:
    key = cfg.get("zoomeye", "")
    if not key:
        return set()
    tag_run("ZoomEye")
    results = set()
    try:
        async with sess.post("https://api.zoomeye.org/user/login",
                             json={"username": "", "password": key},
                             timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status != 200:
                tag_warn("ZoomEye: Auth failed")
                return set()
            token = (await r.json()).get("access_token", "")
        async with sess.get("https://api.zoomeye.org/domain/search",
                            headers={"Authorization": f"JWT {token}"},
                            params={"q": domain, "type": 1},
                            timeout=aiohttp.ClientTimeout(total=30)) as r:
            if r.status == 200:
                data = await r.json()
                for item in data.get("list", []):
                    results.add(item.get("name", ""))
        tag_found(len(results), "ZoomEye")
    except Exception as e:
        tag_err(f"ZoomEye: {e}")
    return results


async def api_dnsdumpster(domain: str, cfg: dict, sess: aiohttp.ClientSession) -> set:
    tag_run("DNSDumpster")
    results = set()
    try:
        async with sess.get("https://dnsdumpster.com/",
                            timeout=aiohttp.ClientTimeout(total=15)) as r:
            text = await r.text()
            m = re.search(r'csrfmiddlewaretoken.*?value=["\']([^"\']+)', text)
            if not m:
                tag_warn("DNSDumpster: CSRF scrape failed")
                return set()
            token = m.group(1)
            cookies = r.cookies

        async with sess.post(
            "https://dnsdumpster.com/",
            headers={"Referer": "https://dnsdumpster.com/"},
            data={"csrfmiddlewaretoken": token, "targetip": domain, "user": "free"},
            cookies=cookies,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as r:
            text = await r.text()
            found = re.findall(r'[\w\-\.]+\.' + re.escape(domain), text)
            results.update(found)
        tag_found(len(results), "DNSDumpster")
    except Exception as e:
        tag_err(f"DNSDumpster: {e}")
    return results

# ─── Active Resolution ────────────────────────────────────────────────────────────
DEFAULT_RESOLVERS = [
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "149.112.112.112", "208.67.222.222", "64.6.64.6", "77.88.8.8", "74.82.42.42"
]

def ensure_resolvers(path: str):
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write("\n".join(DEFAULT_RESOLVERS) + "\n")


def run_dnsx(input_file: str, output_file: str, cfg: dict) -> set:
    if not available("dnsx"):
        tag_warn("dnsx: not installed, skipping resolution")
        return set()
    tag_run("dnsx (resolution)")
    rc, out, err = run_cmd(
        ["dnsx", "-l", input_file, "-silent", "-o", output_file, "-t", "100", "-retry", "3"],
        cfg["tool_timeout"] * 2
    )
    if rc == -2:
        return set()
    try:
        with open(output_file) as f:
            resolved = set(f.read().splitlines())
        resolved.discard("")
        tag_ok(f"dnsx resolved {C.BOLD}{len(resolved)}{C.RESET} subdomains")
        return resolved
    except Exception:
        return set()


def run_puredns_brute(domain: str, wordlist: str, resolvers: str, output_file: str, cfg: dict) -> set:
    if not available("puredns"):
        tag_warn("puredns: not installed, skipping active brute-force")
        return set()
    if not os.path.exists(wordlist):
        tag_warn(f"puredns: wordlist not found ({wordlist}), skipping")
        return set()
    tag_run("puredns (active brute-force)")
    rc, out, err = run_cmd(
        ["puredns", "bruteforce", wordlist, domain, "-r", resolvers, "-w", output_file, "--quiet"],
        cfg["tool_timeout"] * 3
    )
    if rc == -2:
        return set()
    try:
        with open(output_file) as f:
            results = set(f.read().splitlines())
        results.discard("")
        tag_found(len(results), "puredns (brute)")
        return results
    except Exception:
        return set()

# ─── Orchestration ────────────────────────────────────────────────────────────────

PASSIVE_MODULES = [
    mod_subfinder,
    mod_amass,
    mod_assetfinder,
    mod_findomain,
    mod_chaos,
    mod_crobat,
    mod_shuffledns,
]

async def collect_api_results(domain: str, cfg: dict) -> set:
    all_results = set()
    connector = aiohttp.TCPConnector(limit=10, ssl=False)
    async with aiohttp.ClientSession(
        connector=connector,
        headers={"User-Agent": "SubHunter/2.0 (security-research)"}
    ) as sess:
        tasks = [
            api_crtsh(domain, cfg, sess),
            api_hackertarget(domain, cfg, sess),
            api_threatcrowd(domain, cfg, sess),
            api_securitytrails(domain, cfg, sess),
            api_virustotal(domain, cfg, sess),
            api_shodan(domain, cfg, sess),
            api_binaryedge(domain, cfg, sess),
            api_censys(domain, cfg, sess),
            api_zoomeye(domain, cfg, sess),
            api_dnsdumpster(domain, cfg, sess),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, set):
                all_results.update(r)
    return all_results


def collect_passive_results(domain: str, cfg: dict) -> set:
    all_results = set()
    with ThreadPoolExecutor(max_workers=len(PASSIVE_MODULES)) as pool:
        futures = {pool.submit(fn, domain, cfg): fn.__name__ for fn in PASSIVE_MODULES}
        for future in as_completed(futures):
            try:
                all_results.update(future.result())
            except Exception as e:
                tag_err(f"{futures[future]}: {e}")
    return all_results


async def enumerate_domain(domain: str, cfg: dict, args: argparse.Namespace):
    t0 = time.time()
    out = OutputManager(domain)
    sep = f"{C.CYAN}{'━'*62}{C.RESET}"

    print(f"\n{sep}")
    tag_info(f"Target : {C.BOLD}{C.WHITE}{domain}{C.RESET}")
    tag_info(f"Output : {C.DIM}{out.dir}{C.RESET}")
    print(sep + "\n")

    all_raw = set()

    # Phase 1 — Passive CLI Tools
    if not args.no_passive:
        print(f"\n{C.YELLOW}{C.BOLD}[PHASE 1]{C.RESET} Passive Tool Enumeration\n")
        passive = collect_passive_results(domain, cfg)
        all_raw.update(passive)
        tag_ok(f"Passive tools: {C.BOLD}{len(passive)}{C.RESET} raw results")

    # Phase 2 — API Sources
    if not args.no_api:
        print(f"\n{C.YELLOW}{C.BOLD}[PHASE 2]{C.RESET} API-Based Enumeration\n")
        api_res = await collect_api_results(domain, cfg)
        all_raw.update(api_res)
        tag_ok(f"API sources: {C.BOLD}{len(api_res)}{C.RESET} raw results")

    # Normalize & Deduplicate
    print(f"\n{C.YELLOW}{C.BOLD}[PHASE 3]{C.RESET} Normalization & Deduplication\n")
    normalized = normalize_set(all_raw, domain)
    tag_ok(f"Unique after normalization: {C.BOLD}{len(normalized)}{C.RESET}")
    out.write_raw(normalized)

    # Phase 4 — Active Brute-Force
    if not args.no_brute:
        print(f"\n{C.YELLOW}{C.BOLD}[PHASE 4]{C.RESET} Active DNS Brute-Force\n")
        ensure_resolvers(cfg["resolvers_file"])
        brute_out = str(out.dir / "brute_raw.txt")
        brute = run_puredns_brute(domain, cfg["wordlist"], cfg["resolvers_file"], brute_out, cfg)
        brute_norm = normalize_set(brute, domain)
        before = len(normalized)
        normalized.update(brute_norm)
        tag_ok(f"Brute-force added {C.BOLD}{len(normalized) - before}{C.RESET} new subdomains")
        out.write_raw(normalized)

    # Phase 5 — DNS Resolution
    resolved = set()
    if not args.no_resolve:
        print(f"\n{C.YELLOW}{C.BOLD}[PHASE 5]{C.RESET} DNS Resolution via dnsx\n")
        resolved = run_dnsx(str(out.raw_file), str(out.resolved_file), cfg)
        if not resolved:
            tag_warn("Resolution returned 0 results, using normalized set as fallback")
            resolved = normalized
            out.write_resolved(resolved)
    else:
        resolved = normalized
        out.write_resolved(resolved)

    out.write_final(resolved)

    elapsed = time.time() - t0
    out.log(f"Complete: raw={len(all_raw)}, normalized={len(normalized)}, resolved={len(resolved)}, time={elapsed:.1f}s")

    # Summary
    print(f"\n{C.GREEN}{C.BOLD}{'━'*62}{C.RESET}")
    print(f"{C.GREEN}{C.BOLD}  RESULTS — {domain}{C.RESET}")
    print(f"{C.GREEN}{'━'*62}{C.RESET}")
    print(f"  {C.CYAN}Raw Collected   {C.RESET}: {len(all_raw)}")
    print(f"  {C.CYAN}Unique/Normed   {C.RESET}: {len(normalized)}")
    print(f"  {C.CYAN}DNS Resolved    {C.RESET}: {C.BOLD}{len(resolved)}{C.RESET}")
    print(f"  {C.CYAN}Time Elapsed    {C.RESET}: {elapsed:.1f}s")
    print(f"  {C.CYAN}Output Dir      {C.RESET}: {out.dir}")
    print(f"{C.GREEN}{'━'*62}{C.RESET}\n")

    if args.json:
        data = {
            "domain": domain,
            "raw_count": len(all_raw),
            "normalized_count": len(normalized),
            "resolved_count": len(resolved),
            "resolved": sorted(resolved),
            "elapsed_seconds": round(elapsed, 2),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        with open(out.json_file, "w") as f:
            json.dump(data, f, indent=2)
        tag_ok(f"JSON: {out.json_file}")

    if not args.silent:
        for sub in sorted(resolved):
            print(f"  {C.DIM}↳{C.RESET} {sub}")

    return resolved

# ─── Argument Parser ──────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subhunter",
        description="SubHunter — Advanced Subdomain Discovery Framework",
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--domain",  help="Single target domain (e.g. example.com)")
    target.add_argument("-l", "--list",    help="File with one domain per line")
    p.add_argument("-c", "--config",       default="config.yaml", help="Config YAML path")
    p.add_argument("--silent",             action="store_true",   help="Suppress subdomain list output")
    p.add_argument("--json",               action="store_true",   help="Write JSON output per domain")
    p.add_argument("--no-resolve",         action="store_true",   help="Skip DNS resolution")
    p.add_argument("--no-brute",           action="store_true",   help="Skip active brute-force")
    p.add_argument("--no-passive",         action="store_true",   help="Skip passive CLI tools")
    p.add_argument("--no-api",             action="store_true",   help="Skip API sources")
    return p

# ─── Entry Point ──────────────────────────────────────────────────────────────────
async def main():
    print(BANNER)
    args = build_parser().parse_args()
    cfg  = load_config(args.config)

    domains: list[str] = []
    if args.domain:
        domains = [args.domain.strip().lower()]
    elif args.list:
        path = args.list
        if not os.path.exists(path):
            tag_err(f"Target file not found: {path}")
            sys.exit(1)
        with open(path) as f:
            domains = [l.strip().lower() for l in f if l.strip() and not l.startswith("#")]

    if not domains:
        tag_err("No valid targets provided.")
        sys.exit(1)

    tag_info(f"Loaded {C.BOLD}{len(domains)}{C.RESET} target(s)\n")

    def _sigint(sig, frame):
        print(f"\n{C.RED}[!] Interrupted. Partial results saved in output/{C.RESET}")
        sys.exit(0)
    signal.signal(signal.SIGINT, _sigint)

    for domain in domains:
        try:
            await enumerate_domain(domain, cfg, args)
        except Exception as e:
            tag_err(f"Fatal error on {domain}: {e}")
            import traceback; traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())

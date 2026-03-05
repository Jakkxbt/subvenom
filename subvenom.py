#!/usr/bin/env python3
"""
subvenom — Subdomain & Tech Stack Intelligence
Multi-source passive DNS + active validation + tech fingerprinting.
Zero false positives. CobraSEC.
"""

import re
import sys
import json
import socket
import shutil
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text
from rich.columns import Columns
from rich import box

# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = r"""
[bold green] ░▒▓[/bold green][bold white]  ▄▄▄▄▄ ▄• ▄▌▄▄▄▄·  ▌ ▐·▄▄▄ . ▐ ▄       • ▌ ▄ ·. [/bold white][bold green]▓▒░[/bold green]
[bold green] ░▒▓[/bold green][bold white]  •██  █▪██▌▐█ ▀█▪▪█·█▌▀▄.▀·•█▌▐█▪     •█▌▐█ ▌░▄▄██[/bold white][bold green]▓▒░[/bold green]
[bold green] ░▒▓[/bold green][bold white]   ▐█.▪█▌▐█▌▐█▀▀█▄▐█▐█•▐▀▀▪▄▐█▐▐▌ ▄█▀▄ ▐█▐▐▌▐▀▀▄ ▐█·[/bold white][bold green]▓▒░[/bold green]
[bold green] ░▒▓[/bold green][bold white]   ▐█▌·▐█▄█▌██▄▪▐█ ███ ▐█▄▄▌██▐█▌▐█▌.▐▌██▐█▌▐█•█▌▐█▌[/bold white][bold green]▓▒░[/bold green]
[bold green] ░▒▓[/bold green][bold white]   ▀▀▀  ▀▀▀ ·▀▀▀▀ ▀ ▀  ▀▀▀ ▀▀ █▪ ▀█▄▀▪▀▀ █▪.▀  ▀▀▀▀[/bold white][bold green]▓▒░[/bold green]

[dim green]  ◈  passive dns  ·  cert logs  ·  shodan  ·  tech stack  ·  live only  ◈[/dim green]
[dim white]                         CobraSEC  ·  v0.1.0[/dim white]
"""

# ── Config ────────────────────────────────────────────────────────────────────

CONFIG_FILE = Path.home() / ".config" / "subvenom" / "config.yaml"
TIMEOUT = 10
MAX_WORKERS = 30

console = Console()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
}

# ── Tech Fingerprints ─────────────────────────────────────────────────────────

TECH_SIGNATURES = {
    # Server headers
    "nginx":        {"headers": {"server": ["nginx"]}},
    "Apache":       {"headers": {"server": ["apache"]}},
    "IIS":          {"headers": {"server": ["microsoft-iis"]}},
    "LiteSpeed":    {"headers": {"server": ["litespeed"]}},
    "Caddy":        {"headers": {"server": ["caddy"]}},
    "Tomcat":       {"headers": {"server": ["apache-coyote", "tomcat"]}},
    # CDN / WAF
    "Cloudflare":   {"headers": {"server": ["cloudflare"], "cf-ray": [""]}},
    "Akamai":       {"headers": {"x-akamai-transformed": [""]}},
    "Fastly":       {"headers": {"x-served-by": ["cache-"], "via": ["varnish"]}},
    "AWS CloudFront": {"headers": {"x-amz-cf-id": [""]}},
    "AWS ELB":      {"headers": {"server": ["awselb"]}},
    "Vercel":       {"headers": {"server": ["vercel"], "x-vercel-id": [""]}},
    "Netlify":      {"headers": {"server": ["netlify"], "x-nf-request-id": [""]}},
    "Sucuri":       {"headers": {"server": ["sucuri"]}},
    "Imperva":      {"headers": {"x-iinfo": [""]}},
    # Frameworks
    "Next.js":      {"headers": {"x-powered-by": ["next.js"]}, "body": ["__NEXT_DATA__", "_next/static"]},
    "React":        {"body": ["react", "ReactDOM", "__react"]},
    "Angular":      {"body": ["ng-version", "angular", "ng-app"]},
    "Vue.js":       {"body": ["__vue__", "vue.min.js", "data-v-"]},
    "WordPress":    {"body": ["wp-content", "wp-includes", "wordpress"], "headers": {"x-powered-by": ["wordpress"]}},
    "Drupal":       {"body": ["drupal", "Drupal.settings"], "headers": {"x-generator": ["drupal"]}},
    "Joomla":       {"body": ["joomla", "/components/com_"]},
    "Laravel":      {"headers": {"x-powered-by": ["php"]}, "cookies": ["laravel_session"]},
    "Django":       {"cookies": ["csrftoken", "sessionid"], "headers": {"x-frame-options": ["sameorigin"]}},
    "Rails":        {"headers": {"x-powered-by": ["phusion passenger"]}, "cookies": ["_session_id"]},
    "Spring":       {"headers": {"x-application-context": [""]}},
    "PHP":          {"headers": {"x-powered-by": ["php"]}},
    "ASP.NET":      {"headers": {"x-powered-by": ["asp.net"], "x-aspnet-version": [""]}},
    # Databases / Services
    "Elasticsearch":{"body": ["elastic", "kibana"]},
    "GraphQL":      {"body": ["__schema", "graphql", "GraphiQL"]},
    # Auth / Identity
    "Keycloak":     {"body": ["keycloak", "kc-form-login"]},
    "Auth0":        {"body": ["auth0", "cdn.auth0.com"]},
    "Okta":         {"body": ["okta", "okta-signin"]},
    # Analytics
    "Google Analytics": {"body": ["google-analytics.com", "gtag(", "ga("]},
    "Hotjar":       {"body": ["hotjar", "hj("]},
    # E-commerce
    "Shopify":      {"body": ["cdn.shopify.com", "Shopify.theme"]},
    "Magento":      {"body": ["mage/", "Magento"]},
    "WooCommerce":  {"body": ["woocommerce", "wc-blocks"]},
}

# ── Config Loader ─────────────────────────────────────────────────────────────

def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return yaml.safe_load(f) or {}
    return {}


def save_config(data: dict):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(data, f)

# ── Passive DNS Sources ───────────────────────────────────────────────────────

def source_crtsh(domain: str) -> set[str]:
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=TIMEOUT, headers=HEADERS
        )
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for entry in data:
                names = entry.get("name_value", "")
                for name in names.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        subs.add(name.lower())
            return subs
    except Exception:
        pass
    return set()


def source_hackertarget(domain: str) -> set[str]:
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=TIMEOUT, headers=HEADERS
        )
        if r.status_code == 200 and "error" not in r.text.lower():
            subs = set()
            for line in r.text.splitlines():
                parts = line.split(",")
                if parts:
                    sub = parts[0].strip().lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        subs.add(sub)
            return subs
    except Exception:
        pass
    return set()


def source_alienvault(domain: str) -> set[str]:
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        r = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for entry in data.get("passive_dns", []):
                h = entry.get("hostname", "").lower().lstrip("*.")
                if h.endswith(f".{domain}") or h == domain:
                    subs.add(h)
            return subs
    except Exception:
        pass
    return set()


def source_urlscan(domain: str) -> set[str]:
    try:
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200",
            timeout=TIMEOUT, headers=HEADERS
        )
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for result in data.get("results", []):
                h = result.get("page", {}).get("domain", "").lower()
                if h.endswith(f".{domain}") or h == domain:
                    subs.add(h)
            return subs
    except Exception:
        pass
    return set()


def source_rapiddns(domain: str) -> set[str]:
    try:
        r = requests.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            timeout=TIMEOUT, headers=HEADERS
        )
        if r.status_code == 200:
            subs = set()
            for match in re.findall(r'<td>([\w\.\-]+\.' + re.escape(domain) + r')</td>', r.text):
                subs.add(match.lower())
            return subs
    except Exception:
        pass
    return set()


def source_threatcrowd(domain: str) -> set[str]:
    try:
        r = requests.get(
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
            timeout=TIMEOUT, headers=HEADERS
        )
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for sub in data.get("subdomains", []):
                sub = sub.lower().lstrip("*.")
                if sub.endswith(f".{domain}") or sub == domain:
                    subs.add(sub)
            return subs
    except Exception:
        pass
    return set()


def source_bufferover(domain: str) -> set[str]:
    try:
        r = requests.get(
            f"https://dns.bufferover.run/dns?q=.{domain}",
            timeout=TIMEOUT, headers=HEADERS
        )
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for entry in data.get("FDNS_A", []) + data.get("RDNS", []):
                parts = entry.split(",")
                for p in parts:
                    p = p.strip().lower()
                    if p.endswith(f".{domain}") or p == domain:
                        subs.add(p)
            return subs
    except Exception:
        pass
    return set()


def source_shodan(domain: str, api_key: str) -> set[str]:
    if not api_key:
        return set()
    try:
        r = requests.get(
            f"https://api.shodan.io/dns/domain/{domain}?key={api_key}",
            timeout=TIMEOUT
        )
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for entry in data.get("subdomains", []):
                sub = f"{entry}.{domain}".lower()
                subs.add(sub)
            return subs
    except Exception:
        pass
    return set()


def source_subfinder(domain: str) -> set[str]:
    if not shutil.which("subfinder"):
        return set()
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-all"],
            capture_output=True, text=True, timeout=60
        )
        subs = set()
        for line in result.stdout.splitlines():
            line = line.strip().lower()
            if line.endswith(f".{domain}") or line == domain:
                subs.add(line)
        return subs
    except Exception:
        pass
    return set()


def source_assetfinder(domain: str) -> set[str]:
    if not shutil.which("assetfinder"):
        return set()
    try:
        result = subprocess.run(
            ["assetfinder", "--subs-only", domain],
            capture_output=True, text=True, timeout=60
        )
        subs = set()
        for line in result.stdout.splitlines():
            line = line.strip().lower()
            if line.endswith(f".{domain}") or line == domain:
                subs.add(line)
        return subs
    except Exception:
        pass
    return set()


# ── DNS Resolution ────────────────────────────────────────────────────────────

def resolve_dns(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def resolve_all(hostnames: set[str]) -> dict[str, str]:
    resolved = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(resolve_dns, h): h for h in hostnames}
        for f in as_completed(futures):
            h = futures[f]
            ip = f.result()
            if ip:
                resolved[h] = ip
    return resolved


# ── HTTP Probing + Tech Detection ─────────────────────────────────────────────

def probe_host(hostname: str, timeout: int = TIMEOUT, detect_tech_flag: bool = True) -> dict | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            r = requests.get(
                url, headers=HEADERS, timeout=timeout,
                allow_redirects=True, verify=False
            )
            tech = detect_tech(r) if detect_tech_flag else []
            title = extract_title(r.text)
            return {
                "hostname": hostname,
                "url": url,
                "status": r.status_code,
                "title": title,
                "tech": tech,
                "server": r.headers.get("Server", ""),
                "content_length": len(r.content),
                "final_url": r.url,
            }
        except requests.exceptions.SSLError:
            continue
        except Exception:
            continue
    return None


def probe_all(hostnames: list[str], threads: int = MAX_WORKERS,
              timeout: int = TIMEOUT, detect_tech_flag: bool = True) -> list[dict]:
    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe_host, h, timeout, detect_tech_flag): h for h in hostnames}
        for f in as_completed(futures):
            result = f.result()
            if result:
                results.append(result)
    return results


def detect_tech(r: requests.Response) -> list[str]:
    tech = []
    headers = {k.lower(): v.lower() for k, v in r.headers.items()}
    body = r.text[:50000].lower()
    cookies = {c.lower() for c in r.cookies.keys()}

    for name, sigs in TECH_SIGNATURES.items():
        matched = False

        if "headers" in sigs:
            for hdr, vals in sigs["headers"].items():
                hdr_val = headers.get(hdr, "")
                if vals == [""]:  # just presence
                    if hdr_val:
                        matched = True
                else:
                    if any(v in hdr_val for v in vals):
                        matched = True

        if not matched and "body" in sigs:
            if any(sig.lower() in body for sig in sigs["body"]):
                matched = True

        if not matched and "cookies" in sigs:
            if any(c in cookies for c in sigs["cookies"]):
                matched = True

        if matched:
            tech.append(name)

    return tech


def extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>([^<]{1,100})</title>", html, re.IGNORECASE)
    return match.group(1).strip() if match else ""


# ── Output Helpers ────────────────────────────────────────────────────────────

STATUS_STYLE = {
    200: "bold green",
    201: "bold green",
    301: "bold yellow",
    302: "bold yellow",
    304: "yellow",
    401: "bold red",
    403: "bold red",
    404: "dim white",
    500: "bold red",
    503: "bold red",
}

TECH_COLOURS = {
    "Cloudflare": "orange1",
    "AWS CloudFront": "orange1",
    "Akamai": "orange1",
    "Fastly": "orange1",
    "Vercel": "white",
    "Netlify": "cyan",
    "Next.js": "white",
    "React": "cyan",
    "Angular": "red",
    "Vue.js": "green",
    "WordPress": "blue",
    "Drupal": "blue",
    "Laravel": "red",
    "Django": "green",
    "Rails": "red",
    "PHP": "blue",
    "ASP.NET": "blue",
    "nginx": "dim green",
    "Apache": "dim yellow",
    "GraphQL": "hot_pink",
    "Keycloak": "yellow",
}


def tech_badges(tech_list: list[str]) -> str:
    parts = []
    for t in tech_list:
        colour = TECH_COLOURS.get(t, "dim white")
        parts.append(f"[{colour}]{t}[/{colour}]")
    return "  ".join(parts)


def status_badge(code: int) -> str:
    style = STATUS_STYLE.get(code, "dim white")
    return f"[{style}]{code}[/{style}]"


def print_section(title: str):
    console.print()
    console.print(Rule(f"[bold green]{title}[/bold green]", style="dim green"))


# ── Source Runner ─────────────────────────────────────────────────────────────

SOURCES = {
    "crt.sh":       source_crtsh,
    "HackerTarget": source_hackertarget,
    "AlienVault":   source_alienvault,
    "URLScan":      source_urlscan,
    "RapidDNS":     source_rapiddns,
    "ThreatCrowd":  source_threatcrowd,
    "BufferOver":   source_bufferover,
}


def gather_subdomains(domain: str, config: dict) -> dict[str, set[str]]:
    """Run all sources concurrently and return {source: {subdomains}}."""
    results = {}

    def run_source(name, fn):
        subs = fn(domain)
        return name, subs

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(run_source, n, f): n for n, f in SOURCES.items()}

        # Add tool-based sources
        if shutil.which("subfinder"):
            futures[ex.submit(run_source, "subfinder", source_subfinder)] = "subfinder"
        if shutil.which("assetfinder"):
            futures[ex.submit(run_source, "assetfinder", source_assetfinder)] = "assetfinder"

        # Shodan
        shodan_key = config.get("shodan_api_key", "")
        if shodan_key:
            futures[ex.submit(run_source, "Shodan", lambda d: source_shodan(d, shodan_key))] = "Shodan"

        for f in as_completed(futures):
            name, subs = f.result()
            results[name] = subs

    return results


# ── DNS Bruteforce ────────────────────────────────────────────────────────────

def dns_bruteforce(domain: str, wordlist: str, threads: int = MAX_WORKERS) -> set[str]:
    """Brute-force subdomains from a wordlist via DNS resolution."""
    with open(wordlist) as f:
        words = [l.strip() for l in f if l.strip()]
    candidates = {f"{w}.{domain}" for w in words}

    resolved = set()
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(resolve_dns, h): h for h in candidates}
        for f in as_completed(futures):
            h = futures[f]
            if f.result():
                resolved.add(h)
    return resolved


# ── Report ────────────────────────────────────────────────────────────────────

def save_report_multi(domain: str, live_hosts: list[dict], dead: set[str],
                      source_counts: dict[str, int], output_dir: str | None,
                      fmt: str, resolved: dict) -> list[str]:
    """Save in all requested formats. fmt can be comma-separated: 'markdown,json,csv'"""
    formats = [f.strip() for f in fmt.split(",")]
    saved = []
    for f in formats:
        path = save_report(domain, live_hosts, dead, source_counts, output_dir, f, resolved)
        saved.append(path)
    return saved


def _save_and_exit(domain, all_subs, live_hosts, resolved, source_counts, output_dir, fmt):
    """Save results and print summary for early-exit modes."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_dir:
        base = Path(output_dir).expanduser().resolve()
    else:
        base = Path.home() / "bughunt" / domain / "recon"
    base.mkdir(parents=True, exist_ok=True)

    # Always save plain txt list of subdomains
    txt_path = base / f"subvenom_{domain}_{ts}_subs.txt"
    txt_path.write_text("\n".join(sorted(all_subs)))

    console.print()
    console.print(Panel(
        f"[dim white]Subdomains found:[/dim white] [bold green]{len(all_subs)}[/bold green]  "
        f"[dim red]|[/dim red]  "
        f"[dim white]Saved:[/dim white] [bold green]{txt_path}[/bold green]",
        border_style="green", expand=False, title="[bold green][ COMPLETE ][/bold green]"
    ))


def save_report(domain: str, live_hosts: list[dict], dead: set[str],
                source_counts: dict[str, int], output_dir: str | None,
                fmt: str = "markdown", resolved: dict = None) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"markdown": "md", "json": "json", "csv": "csv", "txt": "txt"}.get(fmt, "md")
    filename = f"subvenom_{domain}_{ts}.{ext}"

    if output_dir:
        path = Path(output_dir).expanduser().resolve() / filename
    else:
        path = Path.home() / "bughunt" / domain / "recon" / filename

    path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        data = {
            "domain": domain,
            "date": datetime.now().isoformat(),
            "sources": source_counts,
            "live_hosts": live_hosts,
            "dns_only": sorted(dead),
            "resolved": resolved or {},
        }
        path.write_text(json.dumps(data, indent=2))

    elif fmt == "csv":
        lines = ["hostname,status,title,tech,ip"]
        for h in sorted(live_hosts, key=lambda x: x["hostname"]):
            ip = (resolved or {}).get(h["hostname"], "")
            tech_str = "|".join(h["tech"])
            title = h["title"].replace(",", " ")
            lines.append(f"{h['hostname']},{h['status']},{title},{tech_str},{ip}")
        for d in sorted(dead):
            ip = (resolved or {}).get(d, "")
            lines.append(f"{d},dns_only,,,{ip}")
        path.write_text("\n".join(lines))

    elif fmt == "txt":
        lines = [f"# SubVenom — {domain} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ""]
        lines.append("# LIVE HOSTS")
        for h in sorted(live_hosts, key=lambda x: x["hostname"]):
            lines.append(h["hostname"])
        lines.append("\n# DNS ONLY")
        for d in sorted(dead):
            lines.append(d)
        path.write_text("\n".join(lines))

    else:  # markdown (default)
        lines = [
            f"# SubVenom Report — {domain}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Live Hosts:** {len(live_hosts)}",
            f"**Total Subdomains:** {sum(source_counts.values())}",
            "",
            "## Sources",
            "",
        ]
        for src, count in sorted(source_counts.items(), key=lambda x: -x[1]):
            lines.append(f"- **{src}**: {count}")
        lines.append("")
        lines += ["## Live Hosts", ""]
        lines += ["| Subdomain | Status | Title | Tech Stack | IP |",
                  "|-----------|--------|-------|------------|----|"]
        for h in sorted(live_hosts, key=lambda x: x["status"]):
            ip = (resolved or {}).get(h["hostname"], "")
            tech_str = ", ".join(h["tech"]) if h["tech"] else "—"
            title = h["title"][:50] if h["title"] else "—"
            lines.append(f"| `{h['hostname']}` | {h['status']} | {title} | {tech_str} | {ip} |")
        lines.append("")
        if dead:
            lines += ["## DNS Only (No HTTP)", ""]
            for d in sorted(dead):
                ip = (resolved or {}).get(d, "")
                lines.append(f"- `{d}` — {ip}")
        path.write_text("\n".join(lines))

    return str(path)


# ── Main ──────────────────────────────────────────────────────────────────────

def run(
    domain: str,
    output_dir: str | None = None,
    no_banner: bool = False,
    mode: str = "full",          # full | passive | subs-only | tech-only
    fmt: str = "markdown",       # markdown | json | csv | txt
    subs_only: bool = False,     # just enumerate, skip HTTP
    no_tech: bool = False,       # skip tech detection
    resolve_only: bool = False,  # DNS resolve but no HTTP
    show_dead: bool = False,     # show non-resolving subdomains
    threads: int = MAX_WORKERS,
    timeout: int = TIMEOUT,
    wordlist: str | None = None, # DNS bruteforce wordlist
):
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    config = load_config()

    if not no_banner:
        console.print(BANNER)

    # Build mode label
    mode_labels = {
        "full": "[bold green]FULL[/bold green] — passive + DNS + HTTP + tech",
        "passive": "[bold cyan]PASSIVE[/bold cyan] — sources only, no DNS/HTTP",
        "subs-only": "[bold yellow]SUBS ONLY[/bold yellow] — enum + DNS resolve, no HTTP",
        "tech-only": "[bold magenta]TECH ONLY[/bold magenta] — HTTP probe + tech detect",
    }

    console.print(Panel(
        f"[dim white]Target:[/dim white] [bold green]{domain}[/bold green]  "
        f"[dim white]Mode:[/dim white] {mode_labels.get(mode, mode)}  "
        f"[dim white]Format:[/dim white] [dim cyan]{fmt}[/dim cyan]",
        border_style="green", expand=False, title="[bold green][ SUBVENOM ][/bold green]"
    ))
    console.print()

    source_counts = {}
    all_subs = set()
    resolved = {}
    live_hosts = []
    dns_only: set[str] = set()

    # ── Phase 1: Passive enumeration ─────────────────────────────────────────
    if mode != "tech-only":
        print_section("PHASE 1 — PASSIVE ENUMERATION")
        console.print("  [dim green][*] Querying all sources in parallel...[/dim green]")

        source_results = gather_subdomains(domain, config)

        for src, subs in source_results.items():
            source_counts[src] = len(subs)
            all_subs |= subs

        # DNS bruteforce if wordlist provided
        if wordlist and Path(wordlist).exists():
            print_section("DNS BRUTEFORCE")
            console.print(f"  [dim green][*] Bruteforcing with wordlist: {wordlist}[/dim green]")
            brute_subs = dns_bruteforce(domain, wordlist, threads)
            console.print(f"  [dim white]Brute found:[/dim white] [bold green]{len(brute_subs)}[/bold green]")
            source_counts["bruteforce"] = len(brute_subs)
            all_subs |= brute_subs

        # Source table
        src_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
        src_table.add_column("Source", style="bold white")
        src_table.add_column("Found", style="bold green", justify="right")
        src_table.add_column("Status", style="dim white")

        for src, count in sorted(source_counts.items(), key=lambda x: -x[1]):
            status = "[green]✓[/green]" if count > 0 else "[dim red]✗[/dim red]"
            src_table.add_row(src, str(count), status)

        src_table.add_row("", "", "")
        src_table.add_row("[bold]TOTAL UNIQUE[/bold]", f"[bold green]{len(all_subs)}[/bold green]", "")
        console.print(src_table)

        if not all_subs:
            console.print("  [bold red][!] No subdomains found.[/bold red]")
            return

        # Passive only — stop here
        if mode == "passive":
            _save_and_exit(domain, all_subs, [], {}, source_counts, output_dir, fmt)
            return

    # ── Phase 2: DNS Resolution ───────────────────────────────────────────────
    if mode not in ("passive",):
        targets_to_resolve = all_subs if mode != "tech-only" else {domain}
        print_section("PHASE 2 — DNS RESOLUTION")
        console.print(f"  [dim green][*] Resolving {len(targets_to_resolve)} hostnames...[/dim green]")

        resolved = resolve_all(targets_to_resolve)
        dead_dns = targets_to_resolve - set(resolved.keys())

        console.print(f"  [dim white]Resolved:[/dim white]  [bold green]{len(resolved)}[/bold green]")
        console.print(f"  [dim white]No DNS:[/dim white]    [dim red]{len(dead_dns)}[/dim red]  [dim](dropped)[/dim]")

        if show_dead and dead_dns:
            console.print(f"\n  [dim]Non-resolving:[/dim]")
            for h in sorted(dead_dns)[:50]:
                console.print(f"  [dim red]  ✗ {h}[/dim red]")

        if not resolved:
            console.print("  [bold red][!] Nothing resolved. Exiting.[/bold red]")
            return

        # Subs only — stop after DNS
        if mode == "subs-only" or subs_only or resolve_only:
            _save_and_exit(domain, all_subs, [], resolved, source_counts, output_dir, fmt)
            return

    # ── Phase 3: HTTP Probing ─────────────────────────────────────────────────
    print_section("PHASE 3 — HTTP PROBING")
    console.print(f"  [dim green][*] Probing {len(resolved)} hosts (threads={threads})...[/dim green]")

    live_hosts = probe_all(list(resolved.keys()), threads=threads, timeout=timeout, detect_tech_flag=not no_tech)
    dead_http = set(resolved.keys()) - {h["hostname"] for h in live_hosts}
    dns_only = dead_http

    console.print(f"  [dim white]Live HTTP:[/dim white]  [bold green]{len(live_hosts)}[/bold green]")
    console.print(f"  [dim white]No HTTP:[/dim white]    [dim red]{len(dead_http)}[/dim red]  [dim](DNS only)[/dim]")

    # ── Phase 4: Results ──────────────────────────────────────────────────────
    print_section("PHASE 4 — LIVE HOSTS")

    if not live_hosts:
        console.print("  [dim]No live HTTP hosts found.[/dim]")
    else:
        live_hosts.sort(key=lambda x: (x["status"] != 200, x["hostname"]))

        results_table = Table(box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1), expand=True)
        results_table.add_column("Subdomain", style="bold white", no_wrap=True)
        results_table.add_column("Status", justify="center", width=6)
        results_table.add_column("Title", style="dim white", max_width=35)
        if not no_tech:
            results_table.add_column("Tech Stack", no_wrap=False)
        results_table.add_column("IP", style="dim cyan", no_wrap=True)

        for h in live_hosts:
            ip = resolved.get(h["hostname"], "")
            row = [
                h["hostname"],
                status_badge(h["status"]),
                h["title"][:35] if h["title"] else "[dim]—[/dim]",
            ]
            if not no_tech:
                row.append(tech_badges(h["tech"]) if h["tech"] else "[dim]—[/dim]")
            row.append(ip)
            results_table.add_row(*row)

        console.print(results_table)

    # DNS-only hosts
    if dns_only:
        print_section("DNS ONLY — NO HTTP RESPONSE")
        dns_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        dns_table.add_column(style="dim white")
        dns_table.add_column(style="dim cyan")
        for h in sorted(dns_only):
            ip = resolved.get(h, "")
            dns_table.add_row(h, ip)
        console.print(dns_table)

    # ── Tech Summary ──────────────────────────────────────────────────────────
    if live_hosts and not no_tech:
        print_section("TECH STACK SUMMARY")
        tech_count: dict[str, int] = {}
        for h in live_hosts:
            for t in h["tech"]:
                tech_count[t] = tech_count.get(t, 0) + 1

        if tech_count:
            tech_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            tech_table.add_column(style="bold white")
            tech_table.add_column(style="bold green", justify="right")
            for tech, count in sorted(tech_count.items(), key=lambda x: -x[1]):
                colour = TECH_COLOURS.get(tech, "dim white")
                tech_table.add_row(f"[{colour}]{tech}[/{colour}]", str(count))
            console.print(tech_table)
        else:
            console.print("  [dim]No tech stack detected[/dim]")

    # ── Save Report ───────────────────────────────────────────────────────────
    report_paths = save_report_multi(domain, live_hosts, dns_only, source_counts, output_dir, fmt, resolved)
    console.print()
    console.print(Panel(
        f"[dim white]Live:[/dim white] [bold green]{len(live_hosts)}[/bold green]  "
        f"[dim red]|[/dim red]  "
        f"[dim white]DNS only:[/dim white] [dim]{len(dns_only)}[/dim]  "
        f"[dim red]|[/dim red]  "
        f"[dim white]Saved:[/dim white] [bold green]{', '.join(report_paths)}[/bold green]",
        border_style="green", expand=False, title="[bold green][ COMPLETE ][/bold green]"
    ))


def main():
    parser = argparse.ArgumentParser(
        description="subvenom — Subdomain & Tech Stack Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  full        Passive enum + DNS resolve + HTTP probe + tech detect (default)
  passive     Sources only — no DNS, no HTTP. Fast, zero noise.
  subs-only   Enum + DNS resolve. No HTTP probing.
  tech-only   Just HTTP probe the domain itself for tech stack.

Formats (can combine with commas):
  markdown    Full report with tables (default)
  json        Machine-readable JSON
  csv         Spreadsheet-friendly
  txt         Plain list of subdomains

Examples:
  subvenom target.com
  subvenom target.com -o ~/bughunt/target/recon/
  subvenom target.com --mode passive --format txt
  subvenom target.com --mode subs-only --format json,txt
  subvenom target.com --no-tech --format csv
  subvenom target.com --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
  subvenom target.com --show-dead --threads 50
  subvenom -l domains.txt -o ~/bughunt/results/ --format markdown,json
  subvenom --set-shodan YOUR_KEY
        """
    )
    parser.add_argument("domain", nargs="?", help="Target domain")
    parser.add_argument("-l", "--list", metavar="FILE", help="File with list of domains")
    parser.add_argument("-o", "--output", metavar="DIR", help="Output directory for reports")

    # Mode
    parser.add_argument("--mode", default="full",
        choices=["full", "passive", "subs-only", "tech-only"],
        help="Scan mode (default: full)")

    # Output format
    parser.add_argument("--format", "-f", default="markdown", metavar="FMT",
        help="Output format: markdown,json,csv,txt (comma-separated, default: markdown)")

    # Filtering
    parser.add_argument("--no-tech", action="store_true", help="Skip tech stack detection (faster)")
    parser.add_argument("--show-dead", action="store_true", help="Show non-resolving subdomains")
    parser.add_argument("--resolve-only", action="store_true", help="DNS resolve only, skip HTTP")
    parser.add_argument("--subs-only", action="store_true", help="Enumerate + resolve, no HTTP")

    # Performance
    parser.add_argument("--threads", type=int, default=MAX_WORKERS, help=f"Thread count (default: {MAX_WORKERS})")
    parser.add_argument("--timeout", type=int, default=TIMEOUT, help=f"HTTP timeout in seconds (default: {TIMEOUT})")

    # Bruteforce
    parser.add_argument("--wordlist", metavar="FILE", help="DNS bruteforce wordlist path")

    # Config
    parser.add_argument("--set-shodan", metavar="KEY", help="Save Shodan API key to config")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")

    args = parser.parse_args()

    if args.set_shodan:
        cfg = load_config()
        cfg["shodan_api_key"] = args.set_shodan
        save_config(cfg)
        console.print(f"[bold green][+] Shodan key saved to ~/.config/subvenom/config.yaml[/bold green]")
        return

    if not args.domain and not args.list:
        parser.print_help()
        sys.exit(1)

    domains = []
    if args.list:
        domains = [l.strip() for l in open(args.list) if l.strip()]
    elif args.domain:
        domains = [args.domain]

    for i, d in enumerate(domains):
        d = re.sub(r"^https?://", "", d).rstrip("/")
        if i > 0:
            console.print("\n" + "═" * 80 + "\n")
        run(
            d,
            output_dir=args.output,
            no_banner=(args.no_banner or i > 0),
            mode=args.mode,
            fmt=args.format,
            subs_only=args.subs_only,
            no_tech=args.no_tech,
            resolve_only=args.resolve_only,
            show_dead=args.show_dead,
            threads=args.threads,
            timeout=args.timeout,
            wordlist=args.wordlist,
        )


if __name__ == "__main__":
    main()

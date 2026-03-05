# SubVenom

**Subdomain & Tech Stack Intelligence. Multi-source. Zero false positives.**

Aggregates subdomains from 9+ sources, resolves DNS, confirms live HTTP hosts, and fingerprints the tech stack — all in one command.

---

## Sources

| Source | Type |
|--------|------|
| crt.sh | Certificate transparency |
| HackerTarget | Passive DNS |
| AlienVault OTX | Threat intel DNS |
| URLScan.io | Web crawl dataset |
| RapidDNS | Passive DNS |
| ThreatCrowd | DNS dataset |
| BufferOver | DNS recon |
| subfinder | Tool (if installed) |
| assetfinder | Tool (if installed) |
| Shodan | API (optional) |

---

## Install

```bash
git clone https://github.com/Jakkxbt/subvenom.git
cd subvenom
pip install -e .
```

---

## Usage

```bash
# Single domain
subvenom target.com

# Save report to specific directory
subvenom target.com -o ~/bughunt/target/recon/

# Bulk scan
subvenom -l domains.txt -o ~/bughunt/results/

# Set Shodan API key (saved locally, never in source)
subvenom --set-shodan YOUR_SHODAN_KEY
```

---

## Pipeline

```
All sources → deduplicate → DNS resolve → HTTP probe → tech detect → report
```

Only hosts that pass ALL three checks (subdomain found → DNS resolves → HTTP responds) appear in the live results. Zero false positives.

---

## Tech Stack Detection

Fingerprints 35+ technologies from HTTP headers, response body, and cookies:

CDN/WAF · Next.js · React · Angular · Vue · WordPress · Drupal · Laravel · Django · Rails · PHP · ASP.NET · GraphQL · Keycloak · Auth0 · Cloudflare · Vercel · Netlify · AWS · Shopify · and more.

---

## Output

- Rich terminal — colour-coded status codes, tech badges, source table
- Auto-saved markdown report to `~/bughunt/<domain>/recon/` or `-o DIR`

---

## API Keys

Shodan key is stored in `~/.config/subvenom/config.yaml` — local only, never committed.

```bash
subvenom --set-shodan YOUR_KEY
```

---

## License

MIT — By CobraSEC

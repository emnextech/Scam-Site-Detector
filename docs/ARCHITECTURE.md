# Architecture

Scam Site Detector is a small Python project with a shared engine and two front-ends
(a website and a command-line tool). Everything relies only on **public information**.

```
                         ┌─────────────────────────┐
   Website (Flask)  ───► │                         │
   webapp/app.py         │   scaminvestigator/     │ ───►  public services
                         │   (the shared engine)   │       (RDAP, DNS, TLS,
   CLI investigator ───► │                         │        IP registries,
   investigate.py        └─────────────────────────┘        crt.sh, Wayback)
```

## The engine — `scaminvestigator/`

| Module | Responsibility |
|---|---|
| `recon.py` | Infrastructure lookups: WHOIS via **RDAP**, DNS (over HTTPS), the **TLS certificate**, **IP geolocation/hosting**, and Internet-Archive history. No external binaries required. |
| `deepdive.py` | Pivoting: **certificate transparency** (crt.sh) to find sibling hostnames, **reverse-IP** to find co-hosted sites, and a domain **age/expiry timeline**. |
| `scoring.py` | Pure, network-free function `assess(recon)` that turns the collected data into a risk score, a level, plain-English reasons, and a summary paragraph. |
| `analyze.py` | Orchestrator used by the website: runs the lookups **in parallel under a hard time budget**, then scores the result. |
| `crawler.py` | Polite, same-site page crawler (CLI only). |
| `extractors.py` | Regex extraction of contact/payment indicators from page text (CLI only). |
| `evidence.py` | Byte-for-byte capture with **SHA-256 hash + UTC timestamp** for chain of custody (CLI only). |
| `report.py` | Builds the `dossier.md` / `findings.json` report (CLI only). |

### Why the parallel time budget matters

Some public services (certificate transparency in particular) can be slow for very large,
legitimate domains. `analyze.quick_scan()`:

1. resolves the domain's first IPv4 address quickly via the local resolver;
2. fires every independent lookup at once in a thread pool;
3. collects results under a shared **deadline** (~16s). Anything not finished by then is
   simply dropped — its signal is missing, but the page still returns promptly.

This keeps the website responsive and predictable regardless of third-party latency.

## The website — `webapp/`

| File | Responsibility |
|---|---|
| `app.py` | Flask routes: `/` (form), `/scan` (run a check), `/site/<domain>` (shareable result), `/catalog` (recently checked / highest risk), `/about`, `/health`. |
| `db.py` | SQLite storage. Doubles as a **catalogue** of checked sites and a **30-minute result cache**. |
| `security.py` | `validate_target_url()` — the **SSRF guard** that refuses private/loopback/link-local/reserved addresses — plus a simple per-IP **rate limiter**. |
| `templates/` | Server-rendered HTML (Jinja2). No JavaScript framework. |
| `static/style.css` | Plain, old-school styling. No external fonts or CDNs. |

### Request flow for a scan

```
POST /scan
  → validate_target_url()      reject internal/invalid addresses (SSRF guard)
  → db.get_cached(domain)      return a fresh cached result if we have one
  → rate limiter               throttle abusive traffic (uncached scans only)
  → analyze.quick_scan(url)    parallel recon + deepdive + scoring
  → db.save_scan(result)       persist to the catalogue
  → render result.html         the verdict page
```

## Design principles

- **Public data only.** No authenticated access to systems you don't own, no attacks.
- **Fail soft.** Any single lookup can fail or time out without breaking the scan.
- **Readable over clever.** Heuristics live in one small file and are easy to adjust.
- **Responsible output.** Always an estimate with a disclaimer, never an accusation.

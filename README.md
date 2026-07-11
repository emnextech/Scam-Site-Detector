# Scam Site Detector

A free, open-source tool that helps ordinary people check whether a website is a
likely **investment / "cloud mining" / "earn money" scam** before they trust it with
their money.

Paste a web address and get a plain-English verdict focused on the facts that matter:
**when the domain was registered, when it expires, how old it is, who hosts it, other
suspicious sites on the same server, and an overall risk score.**

It ships in two parts:

| Part | For whom | What it is |
|---|---|---|
| **Website** (`webapp/`) | Everyone | A simple, old-school web page: paste a URL, get a risk report. |
| **CLI investigator** (`investigate.py`) | Researchers / reporters | A deeper command-line tool that also preserves tamper-evident evidence and builds a dossier for authorities. |

Both are powered by the same engine (`scaminvestigator/`) and use **only public
information** — WHOIS/RDAP, DNS, TLS certificates, IP/hosting registries, certificate
transparency logs, and the Internet Archive. It performs **no** hacking, attacks,
brute-forcing, or unauthorised access.

> ⚠️ **Disclaimer.** The risk score is an automated estimate based on public data, not
> a legal ruling. A "Low" result is not a guarantee a site is safe, and a "High" result
> is not proof of a crime. **Do not use these results to publicly accuse a named
> individual.** Always verify independently before sending money.

---

## Table of contents

- [Quick start (website)](#quick-start-website)
- [Features](#features)
- [How the risk score works](#how-the-risk-score-works)
- [Command-line investigator](#command-line-investigator-advanced)
- [Project layout](#project-layout)
- [Documentation](#documentation)
- [Reporting a scam](#reporting-a-scam)
- [Contributing](#contributing)
- [License](#license)

---

## Quick start (website)

Requires **Python 3.10+**.

```bash
git clone https://github.com/emnextech/Scam-Site-Detector.git
cd Scam-Site-Detector
pip install -r requirements.txt
python run_web.py
```

Then open **http://127.0.0.1:8080** and paste a website address.

Expose it on your local network (for others to use):

```bash
python run_web.py --host 0.0.0.0 --port 8000
```

A scan takes about **12–16 seconds** (it queries several public services in parallel).
Repeat checks of the same site within 30 minutes are served instantly from a local cache.

---

## Features

- **Plain-English verdict** — a risk level (Low / Medium / High / Critical) and a short
  paragraph anyone can understand.
- **The facts people ask for** — registration date, expiry date, domain age, registrar,
  hosting company and country.
- **Network discovery** — finds other suspicious sites hosted on the same server, which
  often reveals a whole scam operation rather than one site.
- **Old-domain trick detection** — flags dropped domains that were re-registered to fake
  a long, trustworthy history.
- **Growing catalogue** — every scan is saved to a local database and listed on a
  "Recently checked" page.
- **Old-school, lightweight UI** — server-rendered HTML, no JavaScript frameworks, no
  external CDNs. Loads fast even on slow connections.
- **Built for public hosting** — SSRF protection (refuses internal/private addresses),
  per-IP rate limiting, result caching, and a disclaimer on every page.

---

## How the risk score works

Each site gets a score from **0 to 100** and a level. The score is the sum of weighted
warning signs, for example:

| Warning sign | Why it matters |
|---|---|
| Domain registered days/weeks ago | Most scam sites are brand new; real businesses are usually older. |
| Registered for only ~1 year | Scammers register for the minimum time because they plan to vanish. |
| Hosted in a throwaway datacenter | Cheap, offshore, disposable hosting is common for scams. |
| Neighbouring sites with scam-like names | Scammers run many fake sites from one server. |
| Re-registered old/dropped domain | A trick to look established and trustworthy. |
| Free certificate issued the same day | Consistent with a hastily set-up disposable site. |

Reassuring signs (a domain that is several years old, has real mail records, etc.) lower
the score. The full logic lives in [`scaminvestigator/scoring.py`](scaminvestigator/scoring.py)
and is intentionally easy to read and tune. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Command-line investigator (advanced)

For researchers, journalists, and anti-fraud volunteers who need to **preserve evidence**
and build a report for authorities:

```bash
python investigate.py "https://example.com/"
```

This runs the same infrastructure checks **plus**:

- captures each public page/script byte-for-byte, each stored with a **SHA-256 hash** and
  **UTC timestamp** (a tamper-evident chain of custody);
- extracts contact/payment indicators from the site's own pages (phone numbers, wallets,
  Telegram/WhatsApp, e-mails);
- asks the Internet Archive to preserve a snapshot;
- writes a human-readable **`dossier.md`** and machine-readable **`findings.json`**.

Useful options:

```
--out DIR          output folder (default: evidence)
--max-pages N      max pages to capture (default: 40)
--no-deep          skip the reverse-IP / certificate-transparency pivot
--cookie-file F    use your OWN logged-in session cookie to capture member-only pages
```

> The CLI can capture pages behind a login **using your own account cookie** — this is
> accessing your own account, which is legal, and is where deposit/withdrawal details
> usually live. Only ever use your own account. See the tool's `--help`.

---

## Project layout

```
Scam-Site-Detector/
├── run_web.py                 # start the website (production server: waitress)
├── investigate.py             # command-line investigator
├── requirements.txt
├── scaminvestigator/          # the shared engine
│   ├── analyze.py             # orchestrates a fast, parallel scan for the web app
│   ├── scoring.py             # risk score + plain-English summary
│   ├── recon.py               # WHOIS/RDAP, DNS, TLS, IP/hosting, Wayback
│   ├── deepdive.py            # certificate transparency + reverse-IP + timeline
│   ├── crawler.py             # polite same-site page crawler (CLI)
│   ├── extractors.py          # pull contact/payment indicators from page text (CLI)
│   ├── evidence.py            # hashed + timestamped evidence capture (CLI)
│   └── report.py              # dossier / findings generation (CLI)
├── webapp/                    # the website
│   ├── app.py                 # Flask routes
│   ├── db.py                  # SQLite catalogue + result cache
│   ├── security.py            # SSRF guard + rate limiter
│   ├── templates/             # server-rendered pages
│   └── static/style.css
└── docs/                      # architecture & deployment guides
```

---

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the engine and the web app fit together.
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — how to run it as a real public website safely.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to help.

---

## Reporting a scam

If you have lost money or found a fake investment site, keep all your records
(payment confirmations, screenshots, chats) and report it. In **Zambia**:

1. **Zambia Police – Cyber Crime Unit** — for the criminal fraud.
2. **Securities and Exchange Commission (SEC) Zambia** — for unlicensed investment schemes.
3. **Bank of Zambia** — for financial-system / mobile-money abuse.
4. **Your mobile-money provider's fraud line (Airtel / MTN / Zamtel)** — ask them to flag
   the recipient number. Do this quickly — it is the best chance of freezing funds.
5. **The domain registrar's abuse contact** — to request the site be taken down.

**Never** pay an extra "fee" to withdraw your money — that is a second scam.

---

## Contributing

Contributions are welcome — new warning-sign heuristics, translations, bug fixes, and
documentation. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

---

## License

Released under the [MIT License](LICENSE).

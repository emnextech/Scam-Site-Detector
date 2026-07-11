"""
report.py — Turn the collected data into a dossier you can hand to authorities.

Outputs two files in the evidence folder:
  - findings.json : everything, machine-readable
  - dossier.md    : a human-readable report, formatted so you can print it and
                    attach it to a police / regulator complaint.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


def _bullets(items: List[str], empty: str = "_none found_") -> str:
    if not items:
        return empty
    return "\n".join(f"- `{x}`" for x in items)


def _deepdive_section(deep: Dict | None) -> str:
    if not deep:
        return "_deep pivot not run (use without --no-deep)._"

    tl = deep.get("timeline", {})
    lines = []
    if tl:
        age = tl.get("age_days")
        exp = tl.get("days_until_expiry")
        lines.append("**Domain timeline:**")
        if age is not None:
            flag = "  ⚠ brand new" if age <= 60 else ""
            lines.append(f"- Registered: {tl.get('registered','?')} ({age} days old){flag}")
        if exp is not None:
            lines.append(f"- **Expires in {exp} days** ({tl.get('expires','?')})")
        lines.append("")

    ct = deep.get("certificate_transparency", {})
    hosts = ct.get("hostnames", [])
    seen = ct.get("hostnames_with_first_seen", {})
    lines.append(f"**Sibling hostnames / subdomains on TLS certificates (crt.sh, {ct.get('total_certs','?')} certs):**")
    if hosts:
        for h in hosts[:40]:
            first = seen.get(h, "")
            lines.append(f"- `{h}`" + (f"  _(first seen {first[:10]})_" if first else ""))
        if len(hosts) > 40:
            lines.append(f"- … and {len(hosts) - 40} more")
    else:
        lines.append(f"_{ct.get('error','none found')}_")
    lines.append("")

    lines.append("**Other domains co-hosted on the same server(s) (reverse-IP):**")
    any_neigh = False
    for nb in deep.get("reverse_ip", []):
        doms = nb.get("domains", [])
        lines.append(f"- IP `{nb.get('ip','?')}`: {len(doms)} domain(s)"
                     + (f" — {nb.get('note')}" if nb.get("note") else ""))
        for d in doms[:30]:
            lines.append(f"  - `{d}`")
            any_neigh = True
        if len(doms) > 30:
            lines.append(f"  - … and {len(doms) - 30} more")
    if not deep.get("reverse_ip"):
        lines.append("_not run_")
    if any_neigh:
        lines.append("")
        lines.append("> ⚠ Domains co-hosted on the same IP are often the SAME operator's "
                     "other scam sites. Cross-check these for the same layout/contact details.")

    return "\n".join(lines)


def build_report(
    out_dir: str,
    target_url: str,
    recon: Dict,
    extracted: Dict[str, List[str]],
    visited: List[str],
    evidence_log_path: str,
) -> Dict[str, str]:
    root = Path(out_dir)
    findings = {
        "target_url": target_url,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "recon": recon,
        "extracted_indicators": extracted,
        "pages_captured": visited,
        "evidence_log": evidence_log_path,
    }
    json_path = root / "findings.json"
    json_path.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")

    rdap = recon.get("rdap", {})
    dns = recon.get("dns", {})
    cert = recon.get("tls_certificate", {})
    ips = recon.get("ip_details", [])

    host_lines = []
    for ip in ips:
        host_lines.append(
            f"- **{ip.get('query','?')}** — {ip.get('org') or ip.get('isp','?')} "
            f"({ip.get('as','?')}), {ip.get('city','?')}, {ip.get('country','?')}"
            f"{'  ⚠ hosting/datacenter' if ip.get('hosting') else ''}"
        )

    deepdive_md = _deepdive_section(recon.get("deepdive"))

    md = f"""# Scam Website Evidence Dossier

**Target:** {target_url}
**Domain:** {recon.get('host','?')}
**Report generated (UTC):** {findings['generated_at_utc']}

> Prepared with the `scaminvestigator` OSINT toolkit using only publicly
> available information. All captured files are hashed with SHA-256 and
> timestamped in `{Path(evidence_log_path).name}` for chain-of-custody.

---

## 1. What this website is doing

This site presents itself as an **investment / earnings platform**: users are told
to buy a "product" and then receive money "every 24 hours", and are pushed to
recruit others ("my team"). That structure — guaranteed daily returns funded by
new deposits plus a referral pyramid — is the signature of a **Ponzi / task
("recharge") scam**, not a real investment. Such schemes collapse once deposits
slow, and most participants lose their money.

**Why this matters in Zambia:** these platforms specifically target people looking
to escape poverty, take deposits via mobile money, and disappear. Reporting the
cash-out numbers quickly is the best chance of freezing funds.

---

## 2. Who is behind the domain (registry / hosting)

| Field | Value |
|---|---|
| Registrar | {rdap.get('registrar','?')} |
| Registered on | {rdap.get('registered','?')} |
| Expires | {rdap.get('expires','?')} |
| Last changed | {rdap.get('last_changed','?')} |
| Status | {', '.join(rdap.get('status') or []) or '?'} |
| Abuse contact | {rdap.get('abuse_email','?')} / {rdap.get('abuse_phone','?')} |
| Nameservers | {', '.join(rdap.get('nameservers') or []) or '?'} |

**Hosting IP(s):**
{chr(10).join(host_lines) if host_lines else '_not resolved_'}

**DNS records:**
```
{json.dumps(dns, indent=2)}
```

**TLS certificate:**
- Issued to (subject CN): {cert.get('subject',{}).get('commonName','?')}
- Issued by: {cert.get('issuer',{}).get('organizationName') or cert.get('issuer',{}).get('commonName','?')}
- Valid: {cert.get('valid_from','?')} → {cert.get('valid_to','?')}
- Alt names: {', '.join(cert.get('sans') or []) or '?'}

> ⚠ A newly-registered domain, privacy-protected registrant, and cheap/offshore
> hosting are all consistent with a disposable scam operation. The **registrar's
> abuse contact** above is where a takedown request should be sent.

---

## 2b. Deep pivot — related infrastructure (the scammer's wider network)
{deepdive_md}

---

## 3. The money trail & contact points (most important for police)

These identifiers were extracted directly from the site's own pages/JavaScript.
The mobile-money and bank numbers are attached to **real, identifiable account
holders** — this is the strongest lead.

**Zambian phone / mobile-money numbers:**
{_bullets(extracted.get('phones_zambia', []))}

**Other phone numbers:**
{_bullets(extracted.get('phones_intl', []))}

**Bank / mobile-money account context (lines mentioning deposits + numbers):**
{_bullets(extracted.get('money_context_lines', []))}

**Crypto wallets (USDT-TRC20 / TRON):**
{_bullets(extracted.get('wallet_tron_usdt', []))}

**Crypto wallets (Bitcoin):**
{_bullets(extracted.get('wallet_btc', []))}

**Crypto wallets (Ethereum):**
{_bullets(extracted.get('wallet_eth', []))}

**Telegram:**
{_bullets(extracted.get('telegram', []))}

**WhatsApp:**
{_bullets(extracted.get('whatsapp', []))}

**E-mail addresses:**
{_bullets(extracted.get('emails', []))}

---

## 4. Technical fingerprints (helps link multiple scam sites together)

**Backend API endpoints observed:**
{_bullets(extracted.get('api_endpoints', []))}

**External URLs referenced:**
{_bullets(extracted.get('absolute_urls', [])[:40])}

**Chinese-language strings in the code** (many of these kits are re-sold Chinese
scam templates — a shared string set can tie several fake sites to one operator):
{_bullets(extracted.get('chinese_strings', [])[:30])}

---

## 5. Preservation (Internet Archive)

- Snapshot requested now: {recon.get('wayback_saved_now') or '_not available_'}
- Existing historical snapshots: {len(recon.get('wayback_history') or [])} found
{chr(10).join('  - ' + s.get('snapshot_url','') for s in (recon.get('wayback_history') or [])[:10])}

---

## 6. Pages captured as evidence

{_bullets(visited)}

Raw copies are in `raw/`, each recorded with its SHA-256 hash and capture time in
`{Path(evidence_log_path).name}`.

---

## 7. Where to report this in Zambia

Send this dossier (and your own transaction records / screenshots) to:

1. **Zambia Police – Cyber Crime Unit** — for criminal fraud.
2. **Securities and Exchange Commission (SEC) Zambia** — illegal/unlicensed
   investment schemes are their mandate; check whether the operator is licensed.
   (They publish investor alerts on unlicensed schemes.)
3. **Bank of Zambia** — for financial-system / mobile-money abuse.
4. **ZICTA** (Zambia Information & Communications Technology Authority) — to report
   the phone numbers / SIMs used for mobile-money cash-out.
5. **Your mobile-money provider (Airtel / MTN / Zamtel)** fraud line — ask them to
   flag/freeze the recipient numbers listed in section 3. Do this FAST.
6. **The domain registrar's abuse contact** (section 2) — request takedown.

**Keep everything:** your deposit confirmations, SMS from the platform,
screenshots of your account balance and the "withdrawal failed" messages, and any
chat with the operators. Do not send them more money to "unlock" a withdrawal —
that is a standard second-stage scam.
"""
    md_path = root / "dossier.md"
    md_path.write_text(md, encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}

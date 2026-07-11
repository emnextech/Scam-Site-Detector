"""
deepdive.py — Pivoting: find the OTHER sites/infrastructure tied to a target.

Scammers rarely run one site. They reuse the same server, TLS setup, and registrant
across many disposable domains. These lookups (all free, public) help you connect
one fake site to a whole network — which turns a single complaint into a pattern
authorities can act on.

  - crtsh()        : Certificate Transparency logs -> every subdomain + sibling
                     hostname that has ever been issued a cert for this domain,
                     with first-seen dates (shows how long infra has existed).
  - reverse_ip()   : other domains hosted on the SAME IP (co-located scam sites).
  - domain_timeline(): human-readable age + days until the domain expires.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List

import requests

TIMEOUT = 30
UA = {"User-Agent": "scaminvestigator/1.0 (defensive OSINT)"}


def crtsh(domain: str, timeout: int = TIMEOUT) -> Dict:
    """Query crt.sh Certificate Transparency logs for all names seen on certs."""
    out: Dict = {"domain": domain, "source": "crt.sh"}
    try:
        r = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            headers=UA,
            timeout=timeout,
        )
        if r.status_code != 200 or not r.text.strip():
            out["error"] = f"crt.sh HTTP {r.status_code}"
            return out
        rows = r.json()
    except (requests.RequestException, ValueError) as exc:
        out["error"] = f"crt.sh failed: {exc}"
        return out

    names: Dict[str, str] = {}   # name -> earliest not_before seen
    issuers = set()
    for row in rows:
        issuers.add(row.get("issuer_name", ""))
        first = row.get("not_before", "")
        for nm in str(row.get("name_value", "")).splitlines():
            nm = nm.strip().lstrip("*.").lower()
            if not nm:
                continue
            if nm not in names or (first and first < names[nm]):
                names[nm] = first

    out["total_certs"] = len(rows)
    out["hostnames"] = sorted(names.keys())
    out["hostnames_with_first_seen"] = dict(sorted(names.items()))
    out["issuers"] = sorted(i for i in issuers if i)
    return out


def reverse_ip(ip: str, timeout: int = TIMEOUT) -> Dict:
    """Other domains sharing this IP (co-hosted). Uses HackerTarget's free API."""
    out: Dict = {"ip": ip, "source": "hackertarget.com"}
    try:
        r = requests.get(
            "https://api.hackertarget.com/reverseiplookup/",
            params={"q": ip},
            headers=UA,
            timeout=timeout,
        )
        text = r.text.strip()
    except requests.RequestException as exc:
        out["error"] = str(exc)
        return out

    low = text.lower()
    if not text or "no records" in low or "error" in low or "api count" in low:
        out["note"] = text[:200] or "no records / rate-limited"
        out["domains"] = []
        return out
    out["domains"] = [d.strip() for d in text.splitlines() if d.strip()]
    return out


def domain_timeline(rdap: Dict) -> Dict:
    """Turn RDAP registration/expiry dates into age + days-to-expiry."""
    out: Dict = {}

    def _parse(s):
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None

    now = datetime.now(timezone.utc)
    reg = _parse(rdap.get("registered"))
    exp = _parse(rdap.get("expires"))
    if reg:
        out["registered"] = rdap.get("registered")
        out["age_days"] = (now - reg).days
    if exp:
        out["expires"] = rdap.get("expires")
        out["days_until_expiry"] = (exp - now).days
    return out


def full_deepdive(domain: str, ips: List[str], rdap: Dict) -> Dict:
    """Run all pivots and bundle them."""
    print(f"  [deep] certificate transparency (crt.sh) for {domain} ...")
    ct = crtsh(domain)
    neighbors = []
    for ip in ips[:2]:
        print(f"  [deep] reverse-IP neighbours of {ip} ...")
        neighbors.append(reverse_ip(ip))
    print(f"  [deep] domain age / expiry timeline ...")
    timeline = domain_timeline(rdap)
    return {
        "certificate_transparency": ct,
        "reverse_ip": neighbors,
        "timeline": timeline,
    }

"""
recon.py — Infrastructure OSINT on the target domain.

All of this is public-registry information, fetched over plain HTTPS. No binaries
(whois/dig) required, so it runs the same on Windows as on Linux.

  - rdap_domain()  : registrar, creation/expiry dates, nameservers, abuse contact
  - dns_records()  : A / AAAA / MX / NS / TXT via DNS-over-HTTPS (Google)
  - tls_cert()     : who the TLS certificate was issued to + validity + SANs
  - ip_info()      : geolocation, ISP/hosting org for each A record (ip-api.com)
  - wayback_save() : ask the Internet Archive to permanently snapshot the page
  - wayback_history(): list existing archived snapshots (proves how long it ran)
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

TIMEOUT = 20
UA = {"User-Agent": "scaminvestigator/1.0 (defensive OSINT)"}


def host_of(url_or_host: str) -> str:
    if "://" in url_or_host:
        return urlparse(url_or_host).hostname or url_or_host
    return url_or_host.split("/")[0]


# --- WHOIS via RDAP ----------------------------------------------------------

def rdap_domain(domain: str) -> Dict:
    """Registry data via RDAP (the modern, structured replacement for WHOIS)."""
    out: Dict = {"domain": domain, "source": "rdap.org"}
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", headers=UA, timeout=TIMEOUT)
        if r.status_code != 200:
            out["error"] = f"RDAP HTTP {r.status_code}"
            return out
        data = r.json()
    except (requests.RequestException, ValueError) as exc:
        out["error"] = f"RDAP failed: {exc}"
        return out

    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    out["registered"] = events.get("registration")
    out["expires"] = events.get("expiration")
    out["last_changed"] = events.get("last changed")
    out["status"] = data.get("status", [])
    out["nameservers"] = [ns.get("ldhName") for ns in data.get("nameservers", [])]

    registrar, abuse_email, abuse_phone = None, None, None
    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        vcard = ent.get("vcardArray", [None, []])[1]
        fields = {v[0]: v[3] for v in vcard if len(v) >= 4}
        if "registrar" in roles:
            registrar = fields.get("fn") or registrar
        if "abuse" in roles:
            abuse_email = fields.get("email") or abuse_email
            abuse_phone = fields.get("tel") or abuse_phone
        # abuse contact can be nested inside the registrar entity
        for sub in ent.get("entities", []):
            if "abuse" in sub.get("roles", []):
                sv = {v[0]: v[3] for v in sub.get("vcardArray", [None, []])[1] if len(v) >= 4}
                abuse_email = abuse_email or sv.get("email")
                abuse_phone = abuse_phone or sv.get("tel")

    out["registrar"] = registrar
    out["abuse_email"] = abuse_email
    out["abuse_phone"] = abuse_phone
    return out


# --- DNS over HTTPS ----------------------------------------------------------

def dns_records(domain: str) -> Dict[str, List[str]]:
    """Resolve common record types via Google's DoH JSON API."""
    records: Dict[str, List[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            r = requests.get(
                "https://dns.google/resolve",
                params={"name": domain, "type": rtype},
                headers=UA,
                timeout=TIMEOUT,
            )
            answers = r.json().get("Answer", []) if r.status_code == 200 else []
            vals = [a.get("data", "").strip('"') for a in answers if a.get("data")]
            if vals:
                records[rtype] = vals
        except (requests.RequestException, ValueError):
            continue
    return records


# --- TLS certificate ---------------------------------------------------------

def tls_cert(host: str, port: int = 443) -> Dict:
    """Read the TLS certificate the server presents (issuer, subject, validity, SANs)."""
    out: Dict = {"host": host}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except (OSError, ssl.SSLError) as exc:
        out["error"] = str(exc)
        return out

    def _flatten(seq):
        d = {}
        for item in seq:
            for k, v in item:
                d[k] = v
        return d

    out["subject"] = _flatten(cert.get("subject", []))
    out["issuer"] = _flatten(cert.get("issuer", []))
    out["valid_from"] = cert.get("notBefore")
    out["valid_to"] = cert.get("notAfter")
    out["sans"] = [v for (t, v) in cert.get("subjectAltName", []) if t == "DNS"]
    return out


# --- IP geolocation / hosting ------------------------------------------------

def ip_info(ip: str) -> Dict:
    """Geolocation + ISP/hosting org for an IP (free, no key: ip-api.com)."""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,regionName,city,isp,org,as,hosting,query"},
            headers=UA,
            timeout=TIMEOUT,
        )
        data = r.json()
        return data if data.get("status") == "success" else {"ip": ip, "error": data.get("message")}
    except (requests.RequestException, ValueError) as exc:
        return {"ip": ip, "error": str(exc)}


# --- Internet Archive (preservation + history) -------------------------------

def wayback_save(url: str) -> Optional[str]:
    """Trigger 'Save Page Now' so a neutral third party holds a timestamped copy."""
    try:
        r = requests.get(f"https://web.archive.org/save/{url}", headers=UA, timeout=60)
        loc = r.headers.get("Content-Location") or r.headers.get("Location")
        if loc:
            return "https://web.archive.org" + loc if loc.startswith("/") else loc
        return r.url
    except requests.RequestException:
        return None


def wayback_history(url: str, limit: int = 25) -> List[Dict]:
    """List existing Wayback snapshots (shows how long the site has been operating)."""
    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={"url": url, "output": "json", "limit": limit, "collapse": "digest"},
            headers=UA,
            timeout=TIMEOUT,
        )
        rows = r.json()
    except (requests.RequestException, ValueError):
        return []
    if not rows or len(rows) < 2:
        return []
    header, *data = rows
    snaps = []
    for row in data:
        rec = dict(zip(header, row))
        ts = rec.get("timestamp", "")
        rec["snapshot_url"] = f"https://web.archive.org/web/{ts}/{rec.get('original','')}"
        snaps.append(rec)
    return snaps


def full_recon(url: str, do_wayback_save: bool = True) -> Dict:
    """Run every recon step for a target URL and bundle the results."""
    host = host_of(url)
    print(f"  [recon] WHOIS/RDAP for {host} ...")
    rdap = rdap_domain(host)
    print(f"  [recon] DNS records ...")
    dns = dns_records(host)
    print(f"  [recon] TLS certificate ...")
    cert = tls_cert(host)
    print(f"  [recon] IP / hosting ...")
    ips = dns.get("A", [])
    ip_details = [ip_info(ip) for ip in ips]
    print(f"  [recon] Wayback history ...")
    history = wayback_history(host)
    saved = None
    if do_wayback_save:
        print(f"  [recon] asking Internet Archive to snapshot the page ...")
        saved = wayback_save(url)

    return {
        "target_url": url,
        "host": host,
        "rdap": rdap,
        "dns": dns,
        "tls_certificate": cert,
        "ip_details": ip_details,
        "wayback_saved_now": saved,
        "wayback_history": history,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }

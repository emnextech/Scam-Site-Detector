"""
scoring.py — Turn recon/deepdive data into a plain-English scam risk verdict.

Pure functions, NO network calls, so it is fast and easy to unit-test. `assess()`
takes the dict produced by recon.full_recon() (optionally with a "deepdive" key from
deepdive.full_deepdive()) and returns a risk score, a level, human-readable reasons,
and a summary paragraph aimed at ordinary end-users.

IMPORTANT: this is an automated heuristic, not proof. A high score means "looks a lot
like known scam sites — be very careful", not "definitely criminal". The web layer
shows a disclaimer to match.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

# Words that show up in the brand names of investment/task/mining scams.
SCAM_WORD_RE = re.compile(
    r"(earn|task|mining|miner|hash|fund|share|invest|cash|pay|wave|capital|"
    r"profit|daily|coin|crypto|trade|wealth|income|bonus|reward|stake|yield)",
    re.I,
)

# Registrars frequently abused for throwaway scam domains (soft signal only).
HIGH_ABUSE_REGISTRARS = (
    "namecheap", "namesilo", "dominet", "alibaba", "aliyun", "hostinger",
    "porkbun", "gname", "openprovider", "west263", "west.cn",
)

LEVELS = (
    (75, "Critical"),
    (50, "High"),
    (25, "Medium"),
    (0, "Low"),
)


def _level_for(score: int) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "Low"


def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        # try a couple of common non-ISO shapes seen in TLS notBefore etc.
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%d"):
            try:
                return datetime.strptime(str(s), fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def assess(recon: Dict) -> Dict:
    """
    Score the target. Returns:
        {score, level, reasons[], positives[], summary, facts{...}}
    `reasons` and `positives` are plain-English strings for end-users.
    """
    rdap = recon.get("rdap", {}) or {}
    dns = recon.get("dns", {}) or {}
    ip_details = recon.get("ip_details", []) or []
    cert = recon.get("tls_certificate", {}) or {}
    deep = recon.get("deepdive", {}) or {}
    timeline = deep.get("timeline", {}) or {}
    ct = deep.get("certificate_transparency", {}) or {}
    reverse = deep.get("reverse_ip", []) or []

    reasons: List[str] = []
    positives: List[str] = []
    score = 0

    now = datetime.now(timezone.utc)

    # --- domain age ---------------------------------------------------------
    age_days = timeline.get("age_days")
    reg_dt = _parse_dt(rdap.get("registered"))
    if age_days is None and reg_dt is not None:
        age_days = (now - reg_dt).days

    if age_days is not None:
        if age_days <= 7:
            score += 30
            reasons.append(f"Domain was registered only {age_days} day(s) ago — brand new.")
        elif age_days <= 30:
            score += 22
            reasons.append(f"Domain is very new (registered {age_days} days ago).")
        elif age_days <= 90:
            score += 12
            reasons.append(f"Domain is fairly new (registered {age_days} days ago).")
        elif age_days <= 180:
            score += 5
            reasons.append(f"Domain is less than 6 months old ({age_days} days).")
        elif age_days >= 365 * 3:
            positives.append(f"Domain has existed for {age_days // 365}+ years, which is a good sign.")

    # --- short (1-year) registration on a new domain ------------------------
    exp_dt = _parse_dt(rdap.get("expires"))
    if reg_dt and exp_dt:
        reg_years = (exp_dt - reg_dt).days / 365.0
        if reg_years <= 1.2 and (age_days is not None and age_days < 90):
            score += 5
            reasons.append("Registered for only ~1 year — typical of disposable scam domains.")

    # --- hosting ------------------------------------------------------------
    host_country = None
    host_org = None
    for ip in ip_details:
        host_country = host_country or ip.get("country")
        host_org = host_org or (ip.get("org") or ip.get("isp"))
        if ip.get("hosting"):
            score += 6
            reasons.append(
                f"Hosted in a commercial datacenter ({ip.get('org') or ip.get('isp','?')}, "
                f"{ip.get('country','?')}) rather than a normal business host."
            )
            break

    # --- re-registered dropped domain (crt.sh history predates registration) -
    first_seen_years = []
    for name, first in (ct.get("hostnames_with_first_seen", {}) or {}).items():
        fs = _parse_dt(first)
        if fs:
            first_seen_years.append(fs.year)
    if first_seen_years and reg_dt:
        earliest = min(first_seen_years)
        if earliest < reg_dt.year - 1:
            score += 10
            reasons.append(
                f"Certificates for this domain exist since {earliest}, but it was "
                f"re-registered in {reg_dt.year} — a dropped domain reused to fake a long history."
            )

    # --- sibling scam sites on the same server ------------------------------
    scam_siblings: List[str] = []
    base_host = (recon.get("host") or "").lower()
    for nb in reverse:
        for d in nb.get("domains", []) or []:
            dl = d.lower()
            if base_host and base_host in dl:
                continue
            if dl.startswith("ip") or ".ip-" in dl or "in-addr" in dl:
                continue
            if SCAM_WORD_RE.search(dl):
                scam_siblings.append(d)
    scam_siblings = sorted(set(scam_siblings))
    if scam_siblings:
        add = min(len(scam_siblings) * 4, 20)
        score += add
        preview = ", ".join(scam_siblings[:5])
        reasons.append(
            f"Shares a server with {len(scam_siblings)} other site(s) whose names match "
            f"scam patterns (e.g. {preview})."
        )

    # --- TLS cert issued same day as registration ---------------------------
    cert_from = _parse_dt(cert.get("valid_from"))
    if cert_from and reg_dt and abs((cert_from - reg_dt).days) <= 1:
        issuer = (cert.get("issuer", {}) or {}).get("organizationName", "")
        if "let's encrypt" in issuer.lower():
            score += 3
            reasons.append("Free TLS certificate issued the same day the domain was registered.")

    # --- registrar reputation (soft) ----------------------------------------
    registrar = (rdap.get("registrar") or "").lower()
    if any(r in registrar for r in HIGH_ABUSE_REGISTRARS):
        score += 4
        reasons.append(f"Registered through {rdap.get('registrar')}, a registrar often abused for scams.")

    # --- positives ----------------------------------------------------------
    if dns.get("MX"):
        positives.append("Domain has real mail (MX) records configured.")
    if rdap.get("status") and any("transfer prohibited" in s for s in rdap.get("status", [])):
        pass  # neutral

    score = max(0, min(100, score))
    level = _level_for(score)

    facts = {
        "domain": recon.get("host"),
        "registered": rdap.get("registered"),
        "expires": rdap.get("expires"),
        "age_days": age_days,
        "days_until_expiry": timeline.get("days_until_expiry"),
        "registrar": rdap.get("registrar"),
        "host_org": host_org,
        "host_country": host_country,
        "abuse_email": rdap.get("abuse_email"),
        "scam_siblings": scam_siblings,
    }

    summary = _summary(level, score, facts, reasons)

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "positives": positives,
        "summary": summary,
        "facts": facts,
    }


def _summary(level: str, score: int, facts: Dict, reasons: List[str]) -> str:
    """One friendly paragraph for end-users, leading with the facts they asked for."""
    dom = facts.get("domain") or "This website"
    parts: List[str] = []

    verdict_word = {
        "Critical": "looks like a scam. Do NOT send it any money.",
        "High": "has strong warning signs of a scam. Be very careful and do not deposit money.",
        "Medium": "has some warning signs. Treat it with caution.",
        "Low": "does not show the usual scam warning signs, but always stay careful with money online.",
    }[level]
    parts.append(f"{dom} {verdict_word} (risk score {score}/100 — {level}).")

    reg = facts.get("registered")
    age = facts.get("age_days")
    exp = facts.get("expires")
    dexp = facts.get("days_until_expiry")
    if reg:
        reg_s = str(reg)[:10]
        if age is not None:
            parts.append(f"It was registered on {reg_s} ({age} day(s) ago).")
        else:
            parts.append(f"It was registered on {reg_s}.")
    if exp:
        exp_s = str(exp)[:10]
        if dexp is not None:
            parts.append(f"The domain is set to expire on {exp_s} (in {dexp} day(s)).")
        else:
            parts.append(f"The domain is set to expire on {exp_s}.")
    if facts.get("host_org"):
        parts.append(f"It is hosted by {facts['host_org']} in {facts.get('host_country','an unknown country')}.")

    if reasons:
        top = reasons[:3]
        parts.append("Main warning signs: " + " ".join(f"({i+1}) {r}" for i, r in enumerate(top)))

    return " ".join(parts)

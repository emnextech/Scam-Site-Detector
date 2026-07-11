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

    # Two kinds of evidence, scored separately (see module docstring):
    #   hard  = a site actually BEHAVING like a scam (content, reliable siblings).
    #   soft  = priors that genuine new sites also share (age, registrar, cert).
    # Soft priors alone can never lift a site above "Low"; only hard evidence can.
    flags: List[str] = []          # hard, scam-behaviour reasons (shown first)
    notes: List[str] = []          # soft, informational context
    positives: List[str] = []
    hard = 0
    soft = 0

    now = datetime.now(timezone.utc)

    # --- domain age (soft prior) -------------------------------------------
    age_days = timeline.get("age_days")
    reg_dt = _parse_dt(rdap.get("registered"))
    if age_days is None and reg_dt is not None:
        age_days = (now - reg_dt).days

    if age_days is not None:
        if age_days <= 7:
            soft += 30
            notes.append(f"Domain was registered only {age_days} day(s) ago — brand new.")
        elif age_days <= 30:
            soft += 22
            notes.append(f"Domain is very new (registered {age_days} days ago).")
        elif age_days <= 90:
            soft += 12
            notes.append(f"Domain is fairly new (registered {age_days} days ago).")
        elif age_days <= 180:
            soft += 5
            notes.append(f"Domain is less than 6 months old ({age_days} days).")
        elif age_days >= 365 * 3:
            positives.append(f"Domain has existed for {age_days // 365}+ years, which is a good sign.")

    # --- short (1-year) registration on a new domain (soft) -----------------
    exp_dt = _parse_dt(rdap.get("expires"))
    if reg_dt and exp_dt:
        reg_years = (exp_dt - reg_dt).days / 365.0
        if reg_years <= 1.2 and (age_days is not None and age_days < 90):
            soft += 5
            notes.append("Registered for only ~1 year, which is common for disposable domains.")

    # --- hosting: recorded for the facts table, but NOT scored --------------
    # Almost every legitimate site now sits behind AWS/Cloudflare/DO, so "hosted in
    # a datacenter" is noise — it flagged every genuine site. Keep it as context only.
    host_country = None
    host_org = None
    host_is_cdn = False
    for ip in ip_details:
        host_country = host_country or ip.get("country")
        host_org = host_org or (ip.get("org") or ip.get("isp"))
        if _looks_like_cdn(ip.get("org") or ip.get("isp") or ""):
            host_is_cdn = True

    # --- re-registered dropped domain (hard) --------------------------------
    first_seen_years = []
    for name, first in (ct.get("hostnames_with_first_seen", {}) or {}).items():
        fs = _parse_dt(first)
        if fs:
            first_seen_years.append(fs.year)
    if first_seen_years and reg_dt:
        earliest = min(first_seen_years)
        if earliest < reg_dt.year - 1:
            hard += 10
            flags.append(
                f"Certificates for this domain exist since {earliest}, but it was "
                f"re-registered in {reg_dt.year} — a dropped domain reused to fake a long history."
            )

    # --- sibling scam sites on the same server (hard, but gated) ------------
    # Reverse-IP is only meaningful on a dedicated host. On a CDN (Cloudflare) or on
    # shared hosting, one IP fronts hundreds of unrelated sites, so word-matches there
    # are coincidence, not evidence. Require a dedicated host and >=2 matches.
    scam_siblings: List[str] = []
    base_host = (recon.get("host") or "").lower()
    total_neighbours = sum(len(nb.get("domains", []) or []) for nb in reverse)
    shared_hosting = host_is_cdn or total_neighbours > 50
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
    if scam_siblings and not shared_hosting and len(scam_siblings) >= 2:
        hard += min(len(scam_siblings) * 4, 20)
        preview = ", ".join(scam_siblings[:5])
        flags.append(
            f"Shares a dedicated server with {len(scam_siblings)} other site(s) whose names "
            f"match scam patterns (e.g. {preview})."
        )

    # --- TLS cert issued same day as registration (soft) --------------------
    cert_from = _parse_dt(cert.get("valid_from"))
    if cert_from and reg_dt and abs((cert_from - reg_dt).days) <= 1:
        issuer = (cert.get("issuer", {}) or {}).get("organizationName", "")
        if "let's encrypt" in issuer.lower():
            soft += 3
            notes.append("Free TLS certificate issued the same day the domain was registered.")

    # --- registrar reputation (soft) ----------------------------------------
    registrar = (rdap.get("registrar") or "").lower()
    if any(r in registrar for r in HIGH_ABUSE_REGISTRARS):
        soft += 4
        notes.append(f"Registered through {rdap.get('registrar')}, a registrar often abused for scams.")

    # --- page content signals: the strongest hard evidence ------------------
    hard += _score_content(recon, flags)

    # --- positives ----------------------------------------------------------
    if dns.get("MX"):
        positives.append("Domain has real mail (MX) records configured.")

    # --- combine ------------------------------------------------------------
    if hard > 0:
        # There is real scam behaviour: full score, show hard flags then soft context.
        score = max(0, min(100, hard + soft))
        reasons = flags + notes
    else:
        # No scam behaviour detected. Soft priors alone stay in "Low"; give a gentle,
        # non-alarming note if the domain is simply new so users still verify first.
        score = min(soft, 20)
        reasons = []
        if age_days is not None and age_days <= 90:
            reasons = ["This website is fairly new. That alone is NOT a sign of a scam — "
                       "many honest businesses are new — but always verify before sending money."]
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


# URL-level referral funnel: ?invite_code=, /register?ref=, /invite/..., etc.
REFERRAL_RE = re.compile(r"(invite|referr?al)[_-]?(code|id)?=|/(invite|signup)\b|/register\?", re.I)

# CDN / shared-hosting providers where one IP fronts many unrelated sites, so
# reverse-IP "neighbours" prove nothing about who runs the target.
CDN_PROVIDERS = (
    "cloudflare", "incapsula", "imperva", "fastly", "akamai", "cloudfront",
    "sucuri", "stackpath", "bunnycdn", "ddos-guard", "qrator", "gcore",
)

# Cap how much page content alone can add. Content is real behavioural evidence, so
# the cap is generous, but a domain still needs some age/registrar prior to reach the
# very top of the scale.
CONTENT_CAP = 42


def _looks_like_cdn(org: str) -> bool:
    o = (org or "").lower()
    return any(p in o for p in CDN_PROVIDERS)


def _score_content(recon: Dict, reasons: List[str]) -> int:
    """Score scam-app fingerprints found in the landing page + its JS/CSS bundles.

    Weak signals (VIP tiers, a Chinese codebase, a Telegram link) are only counted
    when the site ALSO shows a money mechanic, so an ordinary site that merely links
    to Telegram or uses the word "level" in its CSS is not flagged."""
    page = recon.get("page", {}) or {}
    url = recon.get("target_url") or ""
    kc = page.get("keyword_counts", {}) or {}
    added = 0

    money_app = bool(kc.get("recharge", 0) and (kc.get("withdraw", 0) or kc.get("withdrawal", 0)))
    wallet = bool(page.get("wallet_tron_usdt") or page.get("wallet_btc") or page.get("wallet_eth"))
    invite_words = kc.get("invite", 0) + kc.get("invitation", 0) + kc.get("referral", 0)
    referral = bool(REFERRAL_RE.search(url)) or invite_words > 0
    any_money_signal = money_app or wallet or referral

    # Recruitment / referral funnel — the strongest tell of these apps.
    if referral:
        added += 10
        reasons.append("Sign-up runs through a referral/invite code — a recruitment funnel "
                       "typical of 'invite friends to earn' investment scams.")

    # Deposit-and-withdraw money app: mentions BOTH 'recharge' and 'withdraw'.
    if money_app:
        added += 16
        reasons.append("The site is a deposit-and-withdraw money app (it repeatedly references "
                       "'recharge' and 'withdraw') — the core mechanic of task/investment scams.")

    # Crypto cash-out wallet on the page.
    if wallet:
        added += 8
        reasons.append("Asks for payment to a cryptocurrency wallet — money sent there is "
                       "almost impossible to recover.")

    # VIP tiers — only meaningful alongside the deposit/withdraw mechanic.
    if kc.get("vip", 0) and money_app:
        added += 6
        reasons.append("Uses paid 'VIP' tiers that promise higher earnings — a common scam structure.")

    # Chinese-language codebase behind an English-facing money site.
    if page.get("cjk_count", 0) >= 20 and any_money_signal:
        added += 8
        reasons.append("Built from a Chinese-language codebase although presented to "
                       "English-speaking users — common for these off-the-shelf scam kits.")

    # Telegram as the contact channel for a money site.
    if page.get("telegram") and any_money_signal:
        added += 5
        reasons.append("Primary contact is Telegram — scammers prefer it because it is anonymous "
                       "and hard to trace.")

    return min(added, CONTENT_CAP)


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

"""
content.py — Lightweight page-content signals for the fast web scan.

Most modern investment/task scams are single-page apps: the landing HTML is an empty
"Loading..." shell and all the real logic (recharge, withdraw, invite, VIP levels,
the backend API, Chinese source strings) lives in the JavaScript bundle it loads.
So to actually *read* what a site does we fetch the landing page AND its same-origin
script/style bundles, then keyword/entity-scan the combined text.

Safety: this only ever fetches the **same host** that the caller already validated
(SSRF guard in webapp.security). Redirects are NOT followed, downloads are size- and
count-capped, and every request has a short timeout so a scan stays fast.
"""

from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urljoin, urlparse

import requests

from . import extractors

UA = {"User-Agent": "Mozilla/5.0 (compatible; scaminvestigator/1.0; defensive OSINT)"}
PAGE_TIMEOUT = 8
MAX_ASSETS = 3            # how many JS/CSS bundles to pull
MAX_BYTES = 2_000_000     # per-asset download cap (~2 MB)

# Scam-app vocabulary we count in the combined page+JS text.
KEYWORDS = (
    "recharge", "withdraw", "withdrawal", "deposit", "invite", "invitation",
    "referral", "profit", "daily", "income", "vip", "level", "bonus", "reward",
    "balance", "telegram", "usdt", "trc20", "guarantee", "commission",
)

SRC_RE = re.compile(r"""<(?:script|link)[^>]+(?:src|href)\s*=\s*['"]([^'"]+)['"]""", re.I)
CJK_RE = re.compile(r"[一-鿿]")


def _same_host(target_host: str, url: str) -> bool:
    h = (urlparse(url).hostname or "").lower()
    return h == (target_host or "").lower()


def _get(url: str) -> str:
    """One capped, non-redirecting GET. Returns decoded text or ''."""
    try:
        r = requests.get(url, headers=UA, timeout=PAGE_TIMEOUT,
                         allow_redirects=False, stream=True)
        if r.status_code != 200:
            return ""
        chunks, total = [], 0
        for chunk in r.iter_content(8192):
            chunks.append(chunk)
            total += len(chunk)
            if total >= MAX_BYTES:
                break
        r.close()
        return b"".join(chunks).decode(r.encoding or "utf-8", errors="replace")
    except requests.RequestException:
        return ""


def fetch_signals(url: str, host: str) -> Dict:
    """
    Fetch the landing page + its same-origin bundles and derive scam-content signals.
    Never raises; returns {"fetched": False, ...} on any failure.
    """
    out: Dict = {"fetched": False, "target_url": url}

    html = _get(url)
    if not html:
        return out

    combined = html
    fetched_assets: List[str] = []
    for rel in SRC_RE.findall(html):
        if len(fetched_assets) >= MAX_ASSETS:
            break
        asset = urljoin(url, rel.split("#")[0])
        if not asset.startswith(("http://", "https://")):
            continue
        if not _same_host(host, asset):     # stay on the validated host (SSRF guard)
            continue
        if not re.search(r"\.(js|css)(\?|$)", asset, re.I):
            continue
        text = _get(asset)
        if text:
            combined += "\n" + text
            fetched_assets.append(asset)

    low = combined.lower()
    counts = {kw: low.count(kw) for kw in KEYWORDS}
    extracted = extractors.extract_all(combined, source_url=url)

    out.update({
        "fetched": True,
        "assets": fetched_assets,
        "combined_len": len(combined),
        "keyword_counts": {k: v for k, v in counts.items() if v},
        "cjk_count": len(CJK_RE.findall(combined)),
        "telegram": extracted.get("telegram", [])[:10],
        "wallet_tron_usdt": extracted.get("wallet_tron_usdt", [])[:10],
        "wallet_btc": extracted.get("wallet_btc", [])[:10],
        "wallet_eth": extracted.get("wallet_eth", [])[:10],
    })
    return out

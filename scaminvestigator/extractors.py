"""
extractors.py — Pull the "money trail" and identifiers out of captured text.

Investment/task scams have to tell victims where to send money and how to reach
them. That means their pages and JavaScript usually leak:
    - phone numbers (esp. Zambian mobile-money: Airtel/MTN/Zamtel)
    - WhatsApp / Telegram handles
    - e-mail addresses
    - crypto wallet addresses (USDT-TRC20 is the favourite)
    - bank / mobile-money account numbers
    - the backend API domain (who really hosts the operation)

Those are the leads police and mobile-money providers can act on, because the
cash-out account belongs to a real, identifiable person.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List

# --- regex library -----------------------------------------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Zambian numbers: +260 9x/7x XXXXXXX, or local 09/07XXXXXXXX.
ZM_PHONE_RE = re.compile(r"(?:\+?260[\s-]?|0)(?:9[567]|7[567])\d{7}\b")

# Generic international phone (broad; filtered later against junk).
INTL_PHONE_RE = re.compile(r"\+\d[\d\s().-]{7,16}\d")

TELEGRAM_RE = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me)/([A-Za-z0-9_+]{3,})", re.I)
TELEGRAM_AT_RE = re.compile(r"(?<![\w./])@([A-Za-z][A-Za-z0-9_]{4,31})\b")

# CSS at-rules and other noise that look like "@handle" but aren't Telegram.
AT_HANDLE_STOPWORDS = {
    "media", "keyframes", "import", "charset", "font-face", "fontface",
    "supports", "namespace", "document", "page", "layer", "container",
    "property", "scope", "counter-style", "font-feature-values", "apply",
    "tailwind", "screen", "include", "mixin", "extend", "function", "return",
    "webkit", "moz", "keyframe", "media_",
}

WHATSAPP_RE = re.compile(
    r"(?:https?://)?(?:wa\.me/|api\.whatsapp\.com/send\?phone=|chat\.whatsapp\.com/)([A-Za-z0-9]+)",
    re.I,
)

# Crypto wallets.
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TRON_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")  # TRC20 USDT lives here

# Money keywords that flag account numbers in surrounding text.
MOMO_KEYWORDS = re.compile(
    r"\b(airtel|mtn|zamtel|mobile\s*money|momo|account\s*(?:no|number|name)?|"
    r"bank|iban|swift|beneficiary|deposit|recharge|withdraw)\b",
    re.I,
)

# Backend API / endpoint hints (relative and absolute).
API_RE = re.compile(r"""["'(]\s*(/?[\w./-]*(?:ashx|api|service|server|json|php)[\w./?=-]*)""", re.I)
ABS_URL_RE = re.compile(r"https?://[A-Za-z0-9.\-]+(?:/[^\s\"'<>)]*)?")

# Chinese characters — a strong origin/attribution signal for these kits.
CJK_RE = re.compile(r"[一-鿿]{1,}")


def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen, out = set(), []
    for it in items:
        key = it.strip()
        if key and key.lower() not in seen:
            seen.add(key.lower())
            out.append(key)
    return out


def _clean_phone(num: str) -> str:
    return re.sub(r"[\s().-]", "", num)


# Obvious template placeholders that are not real leads.
PLACEHOLDER_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net", "email.com", "domain.com",
    "yourdomain.com", "test.com", "sample.com", "mail.com",
}
PLACEHOLDER_PHONE_SUBSTR = ("1234567", "0000000", "1111111", "9999999", "12345678")


def _is_placeholder_email(e: str) -> bool:
    dom = e.split("@")[-1].lower()
    return dom in PLACEHOLDER_EMAIL_DOMAINS or e.lower().startswith(("you@", "your@", "name@", "example@"))


def _is_placeholder_phone(p: str) -> bool:
    return any(s in p for s in PLACEHOLDER_PHONE_SUBSTR)


def extract_all(text: str, source_url: str = "") -> Dict[str, List[str]]:
    """Run every extractor over one blob of text. Returns category -> [hits]."""
    found: Dict[str, List[str]] = defaultdict(list)

    found["emails"] += [e for e in EMAIL_RE.findall(text) if not _is_placeholder_email(e)]
    found["phones_zambia"] += [
        p for p in (_clean_phone(m) for m in ZM_PHONE_RE.findall(text)) if not _is_placeholder_phone(p)
    ]
    found["phones_intl"] += [
        p for p in (_clean_phone(m) for m in INTL_PHONE_RE.findall(text)) if not _is_placeholder_phone(p)
    ]
    found["telegram"] += [f"t.me/{h}" for h in TELEGRAM_RE.findall(text)]
    found["telegram"] += [
        f"@{h}" for h in TELEGRAM_AT_RE.findall(text)
        if h.lower() not in AT_HANDLE_STOPWORDS and not h.lower().startswith("webkit")
    ]
    found["whatsapp"] += WHATSAPP_RE.findall(text)
    found["wallet_btc"] += BTC_RE.findall(text)
    found["wallet_eth"] += ETH_RE.findall(text)
    found["wallet_tron_usdt"] += TRON_RE.findall(text)
    found["api_endpoints"] += [m for m in API_RE.findall(text)]
    found["absolute_urls"] += ABS_URL_RE.findall(text)

    # Chinese snippets (context matters, so keep short unique lines).
    cjk = _dedupe_keep_order(CJK_RE.findall(text))
    found["chinese_strings"] += cjk[:50]

    # Lines that mention money keywords AND contain a long digit run
    # (candidate bank / mobile-money account numbers).
    for line in text.splitlines():
        if MOMO_KEYWORDS.search(line) and re.search(r"\d{6,}", line):
            snippet = line.strip()
            if len(snippet) <= 200:
                found["money_context_lines"].append(snippet)

    # Clean up.
    for k in list(found.keys()):
        found[k] = _dedupe_keep_order(found[k])

    return dict(found)


def merge(target: Dict[str, List[str]], new: Dict[str, List[str]]) -> None:
    """Merge extractor output from another page into a running total."""
    for k, vals in new.items():
        target.setdefault(k, [])
        target[k] = _dedupe_keep_order(target[k] + vals)

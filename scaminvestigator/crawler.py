"""
crawler.py — Polite, shallow, same-site crawler.

Goal: collect the PUBLIC pages, JavaScript and CSS of the target so we can (a)
preserve them as evidence and (b) mine them for the money trail. It stays on the
target's own domain, obeys a depth limit, waits between requests, and never tries
to log in, guess URLs, or touch anything it wasn't linked to. This is ordinary
browsing, automated — not an attack.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .evidence import EvidenceStore


def same_site(a: str, b: str) -> bool:
    ha, hb = urlparse(a).hostname or "", urlparse(b).hostname or ""
    # treat www. and bare domain as the same site
    return ha.lstrip("www.") == hb.lstrip("www.")


def crawl(
    store: EvidenceStore,
    seed_urls: List[str],
    max_pages: int = 40,
    max_depth: int = 2,
    delay: float = 1.0,
) -> Tuple[Dict[str, str], List[str]]:
    """
    Breadth-first crawl starting from seed_urls.

    Returns:
        texts:  {url -> decoded text}  for every HTML/JS/CSS object captured
        visited: ordered list of URLs captured
    """
    if not seed_urls:
        return {}, []

    base = seed_urls[0]
    queue: deque[Tuple[str, int]] = deque((u, 0) for u in seed_urls)
    seen: Set[str] = set(seed_urls)
    texts: Dict[str, str] = {}
    visited: List[str] = []

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        print(f"  [crawl] ({len(visited)+1}/{max_pages}) depth {depth}: {url}")
        item, text = store.capture_text(url)
        if item is None:
            continue
        visited.append(url)
        if text:
            texts[url] = text
        time.sleep(delay)

        ctype = (item.content_type or "").lower()
        if "html" not in ctype or depth >= max_depth:
            continue

        # Parse links + referenced scripts/styles, queue same-site ones.
        soup = BeautifulSoup(text, "html.parser")
        candidates: List[str] = []
        for tag, attr in (("a", "href"), ("script", "src"), ("link", "href"), ("iframe", "src")):
            for el in soup.find_all(tag):
                val = el.get(attr)
                if val:
                    candidates.append(urljoin(url, val))

        for link in candidates:
            link = link.split("#")[0]
            if not link.startswith("http"):
                continue
            if link in seen or not same_site(base, link):
                continue
            seen.add(link)
            # scripts/styles fetched at depth+1 but not recursed further meaningfully
            queue.append((link, depth + 1))

    return texts, visited

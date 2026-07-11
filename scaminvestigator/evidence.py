"""
evidence.py — Chain-of-custody evidence capture.

Every network object we download (HTML page, JS file, image, API response) is:
  1. saved to disk byte-for-byte,
  2. hashed with SHA-256 so anyone can later prove the file was not altered,
  3. logged with the exact UTC time it was captured and where it came from.

That log (evidence_log.jsonl) is what turns "I saw a scam website" into
"here is a tamper-evident record a court can rely on".
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    Retry = None

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def utc_now_iso() -> str:
    """UTC timestamp, e.g. 2026-07-07T14:03:11.512Z — unambiguous across time zones."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(url: str) -> str:
    """Turn a URL into a filesystem-safe file name (kept readable for humans)."""
    name = re.sub(r"^https?://", "", url)
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name[:120].strip("_") or "index"


@dataclass
class EvidenceItem:
    url: str
    captured_at_utc: str
    http_status: Optional[int]
    content_type: Optional[str]
    sha256: str
    size_bytes: int
    saved_as: str
    final_url: Optional[str] = None          # after redirects
    server_header: Optional[str] = None
    note: str = ""


class EvidenceStore:
    """Owns the evidence/ directory and the append-only evidence log."""

    def __init__(self, out_dir: str | os.PathLike, cookie: Optional[str] = None):
        self.root = Path(out_dir)
        self.raw_dir = self.root / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.root / "evidence_log.jsonl"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        # Optional: your OWN logged-in session cookie, so member-only pages (your
        # deposit/withdrawal/team pages) can be captured. This is accessing your
        # own account — legal and where the money-trail evidence actually lives.
        if cookie:
            self.session.headers["Cookie"] = cookie.strip()
        # Retry slow/flaky scam hosts a few times with backoff before giving up.
        if Retry is not None:
            retry = Retry(
                total=4,
                connect=4,
                read=4,
                backoff_factor=1.5,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset(["GET", "HEAD"]),
            )
            adapter = HTTPAdapter(max_retries=retry)
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)

    def _append_log(self, item: EvidenceItem) -> None:
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(item), ensure_ascii=False) + "\n")

    def capture(self, url: str, timeout: int = 45, note: str = "") -> Optional[EvidenceItem]:
        """
        Download a URL, save the raw bytes, hash + timestamp it, log it.
        Returns the EvidenceItem (or None on network failure).
        """
        try:
            # (connect timeout, read timeout) — scam hosts are often slow to respond.
            resp = self.session.get(url, timeout=(15, timeout), allow_redirects=True)
        except requests.RequestException as exc:
            print(f"  [!] could not fetch {url}: {exc}")
            return None

        data = resp.content
        digest = sha256_bytes(data)
        ctype = resp.headers.get("Content-Type", "")

        # Choose a sensible extension from content-type or the URL.
        ext = mimetypes.guess_extension((ctype.split(";")[0] or "").strip()) or ""
        if not ext:
            url_ext = os.path.splitext(url.split("?")[0])[1]
            ext = url_ext if len(url_ext) <= 6 else ".bin"

        fname = f"{_safe_name(url)}__{digest[:12]}{ext}"
        saved_path = self.raw_dir / fname
        saved_path.write_bytes(data)

        item = EvidenceItem(
            url=url,
            captured_at_utc=utc_now_iso(),
            http_status=resp.status_code,
            content_type=ctype,
            sha256=digest,
            size_bytes=len(data),
            saved_as=str(saved_path.name),
            final_url=resp.url if resp.url != url else None,
            server_header=resp.headers.get("Server"),
            note=note,
        )
        self._append_log(item)
        return item

    def capture_text(self, url: str, timeout: int = 45) -> tuple[Optional[EvidenceItem], str]:
        """Convenience: capture + return decoded text (for HTML/JS parsing)."""
        item = self.capture(url, timeout=timeout)
        if item is None:
            return None, ""
        path = self.raw_dir / item.saved_as
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        return item, text

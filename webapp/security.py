"""
security.py — Guards for a PUBLIC-facing scanner.

Two jobs:
  1. validate_target_url(): stop the server being tricked into scanning private /
     internal addresses (SSRF). We only allow http/https public hostnames and reject
     anything that resolves to a private, loopback, link-local or reserved IP (this
     includes the cloud metadata address 169.254.169.254).
  2. RateLimiter: a simple per-IP throttle so one visitor can't hammer the scanner.

Note: the rate limiter is in-memory, so it is per-process. For a multi-worker
deployment use a shared store (Redis / flask-limiter). For a single waitress process
(our default) it is fine.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, None}  # None = default for scheme


def normalize_url(raw: str) -> str:
    """Accept 'example.com' or 'https://example.com/x' and return a full URL."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    return raw


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_target_url(raw: str) -> Tuple[bool, str, str]:
    """
    Returns (ok, normalized_url, message).
    On success message is "". On failure normalized_url may be "" and message
    explains why (safe to show to the user).
    """
    url = normalize_url(raw)
    if not url:
        return False, "", "Please enter a website address."

    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, "", "Only http:// and https:// addresses can be checked."

    host = parsed.hostname
    if not host:
        return False, "", "That does not look like a valid website address."

    if parsed.port is not None and parsed.port not in ALLOWED_PORTS:
        return False, "", "Only standard web ports (80/443) are allowed."

    # Reject raw IP literals that are non-public, and resolve hostnames.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, "", "That website address could not be found (DNS lookup failed)."

    resolved = {info[4][0] for info in infos}
    if not resolved:
        return False, "", "That website address could not be resolved."

    for ip in resolved:
        if not _is_public_ip(ip):
            return False, "", "For safety, internal or private addresses cannot be checked."

    return True, url, ""


class RateLimiter:
    """Sliding-window per-key limiter: max `limit` events per `window` seconds."""

    def __init__(self, limit: int = 10, window: int = 300):
        self.limit = limit
        self.window = window
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True

    def retry_after(self, key: str) -> int:
        """Seconds until the oldest hit ages out (for a friendly message)."""
        with self._lock:
            q = self._hits.get(key)
            if not q:
                return 0
            return max(0, int(self.window - (time.time() - q[0])))

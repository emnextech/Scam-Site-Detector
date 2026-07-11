"""
analyze.py — Thin orchestrator shared by the web app (and usable from scripts).

`quick_scan(url)` runs the fast infrastructure checks (no page crawl, no slow
Wayback-save) and returns a single normalized dict with a scam risk assessment.
Designed to finish quickly (~10-25s) so it can back a synchronous web request.

It performs only public lookups. Callers (the web layer) are responsible for
validating the URL first (SSRF guard).
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, List

from . import recon as R
from . import deepdive as D
from . import scoring
from . import content as C

# crt.sh and reverse-IP can be huge/slow for big legit domains; cap them tightly so a
# web scan stays snappy. On timeout the scan just proceeds without that signal.
CRTSH_TIMEOUT = 10
REVERSE_IP_TIMEOUT = 10
# Hard ceiling on how long we wait for the whole parallel batch. Anything not done by
# then is dropped (its signal is simply missing) so the response time stays predictable.
BATCH_DEADLINE = 16


def _safe(fn, default):
    """Run fn(), returning `default` on any error so one slow/broken lookup can't
    sink the whole scan."""
    try:
        return fn()
    except Exception:
        return default


def _quick_ipv4(host: str) -> List[str]:
    """Fast IPv4 resolution via the local resolver; [] on failure."""
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
    except OSError:
        return []
    return list(dict.fromkeys(info[4][0] for info in infos))


def _result_by(future, default, deadline: float):
    """future.result() but bounded by an absolute wall-clock `deadline`."""
    if future is None:
        return default
    remaining = max(0.1, deadline - time.monotonic())
    try:
        return future.result(timeout=remaining)
    except Exception:
        return default


def quick_scan(url: str, do_deep: bool = True) -> Dict:
    """
    Fast scan: WHOIS/RDAP + DNS + TLS + hosting + (optional) deep pivot + scoring.

    The independent lookups run in parallel, so the total wall-time is roughly the
    slowest single lookup rather than the sum. Returns:
        {url, domain, scanned_at, recon, assessment}
    """
    host = R.host_of(url)

    # Fast A-record resolution via the local resolver (~100ms) so the IP-dependent
    # lookups can join the batch. The FULL DNS record set is fetched inside the batch.
    first_ips = _quick_ipv4(host)[:1]

    # One parallel batch under a hard deadline. We only look up the FIRST IP (that's all
    # the scoring uses) to avoid multiplying time across many A-records.
    ex = ThreadPoolExecutor(max_workers=8)
    try:
        f_dns = ex.submit(_safe, lambda: R.dns_records(host), {})
        f_rdap = ex.submit(_safe, lambda: R.rdap_domain(host), {})
        f_tls = ex.submit(_safe, lambda: R.tls_cert(host), {})
        f_wb = ex.submit(_safe, lambda: R.wayback_history(host), [])
        f_ipinfo = ex.submit(_safe, lambda: [R.ip_info(ip) for ip in first_ips], [])
        f_page = ex.submit(_safe, lambda: C.fetch_signals(url, host), {})
        f_ct = ex.submit(_safe, lambda: D.crtsh(host, timeout=CRTSH_TIMEOUT), {}) if do_deep else None
        f_rev = (ex.submit(_safe, lambda: [D.reverse_ip(ip, timeout=REVERSE_IP_TIMEOUT)
                                           for ip in first_ips], [])
                 if do_deep else None)

        deadline = time.monotonic() + BATCH_DEADLINE
        dns = _result_by(f_dns, {}, deadline)
        rdap = _result_by(f_rdap, {}, deadline)
        tls = _result_by(f_tls, {}, deadline)
        wayback = _result_by(f_wb, [], deadline)
        ip_details = _result_by(f_ipinfo, [], deadline)
        page = _result_by(f_page, {}, deadline)
        ct = _result_by(f_ct, {}, deadline) if do_deep else {}
        reverse = _result_by(f_rev, [], deadline) if do_deep else []
    finally:
        # Don't block the response waiting on stragglers; their own request timeouts
        # (≤ a few seconds) will let the orphaned threads finish on their own.
        ex.shutdown(wait=False)

    recon = {
        "target_url": url,
        "host": host,
        "rdap": rdap,
        "dns": dns,
        "tls_certificate": tls,
        "ip_details": ip_details,
        "page": page,
        "wayback_saved_now": None,
        "wayback_history": wayback,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    if do_deep:
        recon["deepdive"] = {
            "certificate_transparency": ct,
            "reverse_ip": reverse,
            "timeline": D.domain_timeline(rdap),
        }

    assessment = scoring.assess(recon)

    return {
        "url": url,
        "domain": host,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "recon": recon,
        "assessment": assessment,
    }

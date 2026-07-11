"""
app.py — Flask front-end for the scam-site detector.

Routes:
    GET  /               homepage: URL form + recently checked sites
    POST /scan           validate + rate-limit + cache + scan + save + show result
    GET  /site/<domain>  shareable last result for a domain
    GET  /catalog        recently checked + highest-risk sites
    GET  /about          how it works + disclaimer
    GET  /health         "ok"

Kept deliberately simple and server-rendered (old-school). No JS frameworks.
"""

from __future__ import annotations

import sys
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for, abort, Response
)

# Make the sibling package importable when run directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scaminvestigator.analyze import quick_scan          # noqa: E402
from webapp import db                                     # noqa: E402
from webapp.security import validate_target_url, RateLimiter  # noqa: E402

app = Flask(__name__)

# One scan is heavy; keep the per-IP limit modest.
limiter = RateLimiter(limit=10, window=300)

db.init_db()


def _client_ip() -> str:
    # Respect a single proxy hop if present; fall back to remote_addr.
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


@app.route("/")
def index():
    return render_template("index.html", recent=db.recent_scans(limit=8))


@app.route("/scan", methods=["POST"])
def scan():
    raw = request.form.get("url", "")

    ok, url, message = validate_target_url(raw)
    if not ok:
        return render_template("index.html", recent=db.recent_scans(limit=8),
                               error=message, prefill=raw), 400

    domain = url.split("://", 1)[1].split("/", 1)[0].split(":")[0]

    # Serve a fresh cached result if we have one (throttles abuse + instant).
    cached = db.get_cached(domain)
    if cached:
        return render_template("result.html", r=cached, cached=True)

    # Rate-limit only actual (uncached) scans.
    ip = _client_ip()
    if not limiter.allow(ip):
        wait = limiter.retry_after(ip)
        return render_template("index.html", recent=db.recent_scans(limit=8),
                               error=f"Too many checks from your connection. "
                                     f"Please wait about {wait} seconds and try again.",
                               prefill=raw), 429

    try:
        result = quick_scan(url)
    except Exception as exc:  # keep the site up even if a lookup explodes
        return render_template("index.html", recent=db.recent_scans(limit=8),
                               error=f"Sorry, the check could not be completed: {exc}",
                               prefill=raw), 502

    db.save_scan(result)
    return render_template("result.html", r=result, cached=False)


@app.route("/site/<path:domain>")
def site(domain):
    data = db.get_latest_for_domain(domain.lower())
    if not data:
        abort(404)
    return render_template("result.html", r=data, cached=True)


@app.route("/catalog")
def catalog():
    return render_template(
        "catalog.html",
        recent=db.recent_scans(limit=30),
        high_risk=db.high_risk_scans(limit=30),
    )


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/health")
def health():
    return Response("ok", mimetype="text/plain")


@app.errorhandler(404)
def not_found(_e):
    return render_template("index.html", recent=db.recent_scans(limit=8),
                           error="Page not found."), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)

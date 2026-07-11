#!/usr/bin/env python3
"""
run_web.py — Start the Scam Site Detector website with a production server.

Uses waitress (pure-Python, works on Windows) instead of Flask's dev server.

    python run_web.py                 # http://127.0.0.1:8080
    python run_web.py --host 0.0.0.0 --port 8000   # expose on your network

For a public deployment, put this behind a reverse proxy (nginx/Caddy) that adds
HTTPS and sets X-Forwarded-For, and keep it to a single process (the in-memory rate
limiter is per-process).
"""

from __future__ import annotations

import argparse

from waitress import serve

from webapp.app import app


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the Scam Site Detector web app.")
    ap.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8080, help="Port (default 8080)")
    args = ap.parse_args()

    print(f"Scam Site Detector running at http://{args.host}:{args.port}  (Ctrl+C to stop)")
    # threads: allow a few concurrent visitors; each scan is I/O-bound (network waits).
    serve(app, host=args.host, port=args.port, threads=8)


if __name__ == "__main__":
    main()

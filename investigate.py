#!/usr/bin/env python3
"""
investigate.py — one-command scam-site investigator.

Usage:
    python investigate.py https://crazyamg.com/main/index.html
    python investigate.py https://crazyamg.com/main/index.html --out evidence --max-pages 60
    python investigate.py https://crazyamg.com/main/index.html --no-archive   # skip Wayback save

What it does (all legal / public-info only):
    1. Runs infrastructure OSINT (WHOIS/RDAP, DNS, TLS cert, IP hosting, Wayback).
    2. Crawls the site's PUBLIC pages/JS, saving each as tamper-evident evidence.
    3. Extracts the money trail (phones, mobile-money, wallets, Telegram, e-mails).
    4. Writes a dossier.md + findings.json you can hand to authorities.

It does NOT log in, attack, brute force, or access anything non-public.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scaminvestigator.crawler import crawl
from scaminvestigator.deepdive import full_deepdive
from scaminvestigator.evidence import EvidenceStore
from scaminvestigator.extractors import extract_all, merge
from scaminvestigator.recon import full_recon
from scaminvestigator.report import build_report


def main() -> int:
    ap = argparse.ArgumentParser(description="Defensive OSINT investigator for scam websites.")
    ap.add_argument("url", help="Target URL, e.g. https://example.com/index.html")
    ap.add_argument("--out", default="evidence", help="Output directory (default: evidence)")
    ap.add_argument("--max-pages", type=int, default=40, help="Max pages to capture (default: 40)")
    ap.add_argument("--max-depth", type=int, default=2, help="Crawl depth (default: 2)")
    ap.add_argument("--delay", type=float, default=1.0, help="Seconds between requests (default: 1.0)")
    ap.add_argument("--no-archive", action="store_true", help="Do not trigger Internet Archive save")
    ap.add_argument("--no-deep", action="store_true",
                    help="Skip deep pivoting (crt.sh sibling domains + reverse-IP neighbours)")
    ap.add_argument("--also", nargs="*", default=[],
                    help="Extra URLs to also crawl, e.g. member pages: --also https://site/center/user.html")
    ap.add_argument("--cookie", default=None,
                    help="Your OWN logged-in Cookie header (in quotes) to capture member-only pages.")
    ap.add_argument("--cookie-file", default=None,
                    help="File containing your Cookie header (safer than putting it on the command line).")
    args = ap.parse_args()

    cookie = args.cookie
    if args.cookie_file:
        cookie = Path(args.cookie_file).read_text(encoding="utf-8").strip()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n=== scaminvestigator ===\nTarget : {args.url}\nOutput : {out_dir.resolve()}\n")

    # 1. Infrastructure recon -------------------------------------------------
    print("[1/5] Infrastructure OSINT ...")
    recon = full_recon(args.url, do_wayback_save=not args.no_archive)

    # 1b. Deep pivoting: sibling domains + co-hosted neighbours ---------------
    if not args.no_deep:
        print("\n[2/5] Deep pivoting (sibling domains, co-hosted sites, timeline) ...")
        ips = recon.get("dns", {}).get("A", [])
        recon["deepdive"] = full_deepdive(recon["host"], ips, recon.get("rdap", {}))
        ct = recon["deepdive"]["certificate_transparency"]
        tl = recon["deepdive"]["timeline"]
        if tl.get("age_days") is not None:
            print(f"    domain age: {tl['age_days']} days | expires in: {tl.get('days_until_expiry','?')} days")
        print(f"    hostnames on certs: {len(ct.get('hostnames', []))}")
        for nb in recon["deepdive"]["reverse_ip"]:
            print(f"    co-hosted on {nb.get('ip')}: {len(nb.get('domains', []))} domain(s)")

    # 2. Crawl + capture evidence --------------------------------------------
    mode = "AUTHENTICATED (your own session)" if cookie else "public only"
    print(f"\n[3/5] Capturing pages as evidence [{mode}] ...")
    store = EvidenceStore(out_dir, cookie=cookie)
    texts, visited = crawl(
        store,
        seed_urls=[args.url, *args.also],
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        delay=args.delay,
    )

    # 3. Extract indicators ---------------------------------------------------
    print("\n[4/5] Extracting money trail & identifiers ...")
    extracted: dict = {}
    for url, text in texts.items():
        merge(extracted, extract_all(text, source_url=url))
    # quick console summary
    for key in ("phones_zambia", "wallet_tron_usdt", "telegram", "whatsapp", "emails"):
        vals = extracted.get(key, [])
        if vals:
            print(f"    {key}: {len(vals)} -> {', '.join(vals[:5])}")

    # 4. Build dossier --------------------------------------------------------
    print("\n[5/5] Writing dossier ...")
    paths = build_report(
        out_dir=str(out_dir),
        target_url=args.url,
        recon=recon,
        extracted=extracted,
        visited=visited,
        evidence_log_path=str(store.log_path),
    )

    print("\n=== DONE ===")
    print(f"  Dossier   : {paths['markdown']}")
    print(f"  Findings  : {paths['json']}")
    print(f"  Raw files : {store.raw_dir}")
    print(f"  Evidence  : {store.log_path}")
    print("\nNext: read dossier.md, then report to the authorities listed in section 7.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
scaminvestigator
================

A defensive OSINT + evidence-preservation toolkit for documenting fraudulent
"investment" / "task" websites so the evidence can be handed to law enforcement.

This package ONLY uses publicly available information and legal techniques:
  - fetching pages the same way any browser would
  - reading public DNS / WHOIS(RDAP) / TLS certificate / IP registry data
  - preserving copies with cryptographic hashes + UTC timestamps (chain of custody)

It performs NO attacks, NO brute forcing, NO exploitation, and NO unauthorised
access. It is meant to build a report, not to break into anything.
"""

__version__ = "1.0.0"

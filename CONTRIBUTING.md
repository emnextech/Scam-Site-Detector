# Contributing to Scam Site Detector

Thank you for helping protect people from online investment scams. This project is a
community effort and contributions of all kinds are welcome.

## Ways to contribute

- **New warning-sign heuristics** — if you know a signal that distinguishes scam sites
  from real ones, add it to [`scaminvestigator/scoring.py`](scaminvestigator/scoring.py).
- **Translations** — the interface text lives in `webapp/templates/`. Localising it into
  languages spoken by targeted communities is very valuable.
- **Bug fixes and reliability** — the tool depends on several public services; making it
  degrade gracefully when they are slow or down is always useful.
- **Documentation** — clearer explanations help non-technical users stay safe.

## Ground rules

This project only ever uses **public information and legal techniques**. Pull requests
that add hacking, exploitation, brute-forcing, denial-of-service, scraping behind
authentication you don't own, or any form of "hacking back" **will not be accepted**.
The goal is to inform and to preserve evidence for authorities — not to attack anyone.

Please also keep the tool's framing responsible: it produces an automated **risk
estimate**, never an accusation against a named person.

## Development setup

```bash
git clone https://github.com/emnextech/Scam-Site-Detector.git
cd Scam-Site-Detector
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
```

Run the website locally:

```bash
python run_web.py         # http://127.0.0.1:8080
```

The scoring engine is pure and network-free, so you can test heuristics quickly:

```python
from scaminvestigator.scoring import assess
# build a small recon-shaped dict and check the resulting level/score
```

## Submitting changes

1. Create a branch: `git checkout -b my-improvement`
2. Keep changes focused and match the existing code style (clear names, short comments
   explaining *why*).
3. Make sure everything still imports and compiles:
   `python -m py_compile investigate.py run_web.py scaminvestigator/*.py webapp/*.py`
4. Open a pull request describing what you changed and why.

## Reporting issues

Found a false positive (a real site flagged as a scam) or a false negative (a scam that
scored Low)? Please open an issue with the details so we can improve the heuristics.

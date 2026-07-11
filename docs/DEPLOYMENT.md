# Deployment

This guide covers running Scam Site Detector as a real, public website. If you only want
to use it locally, `python run_web.py` and opening `http://127.0.0.1:8080` is enough.

## 1. Server

The app is served by **waitress**, a pure-Python production WSGI server that works on
Windows, Linux and macOS:

```bash
python run_web.py --host 127.0.0.1 --port 8080
```

Bind it to `127.0.0.1` and put a reverse proxy in front of it (recommended) rather than
exposing waitress directly to the internet.

## 2. HTTPS reverse proxy

Run a reverse proxy such as **Caddy** or **nginx** in front of the app to provide HTTPS
and to pass the visitor's real IP. Example with Caddy:

```
scamdetector.example.org {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy obtains and renews TLS certificates automatically. The proxy should set the
`X-Forwarded-For` header; the app already reads the first hop from it for rate limiting.

## 3. Keep it to a single process

The rate limiter and the short-term cache are **in-memory / per-process**. For a small
public site, run **one** waitress process (its internal threads handle concurrent
visitors, since each scan mostly waits on the network).

If you need multiple worker processes or multiple machines, move the rate limiter to a
shared store (for example, `flask-limiter` backed by Redis) so limits are enforced
globally. This is intentionally left out to keep the default deployment simple.

## 4. Run it as a service

### Linux (systemd)

```ini
# /etc/systemd/system/scamdetector.service
[Unit]
Description=Scam Site Detector
After=network.target

[Service]
WorkingDirectory=/opt/Scam-Site-Detector
ExecStart=/usr/bin/python3 run_web.py --host 127.0.0.1 --port 8080
Restart=on-failure
User=www-data

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now scamdetector
```

### Windows

Run `python run_web.py` under a process manager such as **NSSM** to install it as a
Windows service, or schedule it to start at boot.

## 5. The database

Scans are stored in `webapp/scans.db` (SQLite), which is created automatically and is
git-ignored. Back it up if you want to keep your catalogue of checked sites. To reset the
catalogue, stop the app and delete the file.

## 6. Operational notes

- **Outbound access.** The server makes outbound HTTPS requests to public services
  (RDAP, DNS-over-HTTPS, crt.sh, ip-api, the Internet Archive). Allow these in any egress
  firewall.
- **SSRF protection is on by default.** `webapp/security.py` refuses to scan private,
  loopback, link-local and reserved addresses (including the cloud metadata endpoint).
  Do not disable this on a public deployment.
- **Rate limiting.** The default is 10 uncached scans per IP per 5 minutes; adjust in
  `webapp/app.py` if needed.
- **Be a good neighbour.** The free public services this tool depends on have their own
  limits. Caching and rate limiting help you stay within them.

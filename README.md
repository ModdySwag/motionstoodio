# motionstoodio.com

The coming-soon page for **motionstoodio** — window animations for Windows 11.

Single static page: `index.html` plus self-hosted Archivo and IBM Plex Mono (`fonts/`) and the
real app icon (`assets/`). No build step, no third-party requests, no analytics.

Served by GitHub Pages at https://motionstoodio.com, with a Let's Encrypt certificate issued
automatically for the custom domain.

The product itself lives at [moddys.net](https://moddys.net).

## SSL watch

`ssl-check.py` checks one domain live — DNS, the served page, the certificate, the HTTP→HTTPS
redirect and HSTS — and exits non-zero if anything fails:

    python3 ssl-check.py motionstoodio.com

`ssl-watch.py` runs it for motionstoodio.com and moddys.net, writes `ssl-status.txt` and
`ssl-status.json` next to itself, and messages Discord only when something needs a human. It is
made for Windows Task Scheduler with `pythonw.exe`, so no console window appears.

The two files have to live in the same directory: the watcher calls its sibling by path and reads
its output, so it looks for lines starting `VERDICT:`, `blocking:` and `INFO  issuer:`. Miss the
checker and every domain reports `VERDICT: no output`.

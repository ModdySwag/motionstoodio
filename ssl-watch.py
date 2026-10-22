#!/usr/bin/env python3
"""Daily SSL watch for the two live sites.

Runs ssl-check.py for each domain, writes a short human report plus a JSON summary:

    C:/Users/Moddy/motionstoodio-site/ssl-status.txt
    C:/Users/Moddy/motionstoodio-site/ssl-status.json

Designed to be run by Windows Task Scheduler with pythonw.exe (no console window).
Exit code is 0 when every site passes, 1 when anything needs attention.
"""
import datetime
import json
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.request

SITE = pathlib.Path(__file__).resolve().parent
OUT_TXT = SITE / "ssl-status.txt"
OUT_JSON = SITE / "ssl-status.json"
DOMAINS = ["motionstoodio.com", "moddys.net"]
CHECK = SITE / "ssl-check.py"

# Discord: reuse the running Hermes bot (Modbot, deepseek profile) — no second token.
ENV = pathlib.Path(r"C:/Users/Moddy/AppData/Local/hermes/profiles/deepseek/.env")
API = "https://discord.com/api/v10"


def discord_targets():
    """Return (token, channel_id) from the Hermes .env without printing either."""
    vals = {}
    try:
        for line in ENV.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        return None, None
    return vals.get("DISCORD_BOT_TOKEN"), vals.get("DISCORD_HOME_CHANNEL")


def post_discord(token, channel, content):
    req = urllib.request.Request(
        f"{API}/channels/{channel}/messages",
        data=json.dumps({"content": content[:1900], "allowed_mentions": {"parse": []}}).encode(),
        headers={
            "Authorization": f"Bot {token}",
            "User-Agent": "moddys-ssl-watch/1.0",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return json.load(r).get("id")
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}: {e.read()[:160].decode('utf-8', 'replace')}"
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"


def discord_message(summary, ok_all):
    head = "SSL watch — " + datetime.date.today().isoformat()
    icon = "🔐" if ok_all else "⚠️"
    rows = [f"{icon} **{head}**"]
    for domain, s in summary["sites"].items():
        mark = "✓" if s["ok"] else "✗"
        left = f" · {s['days_left']}d left" if s.get("days_left") is not None else ""
        rows.append(f"**{domain}** — {s['verdict']} {mark}{left}")
        if s.get("days_left") is not None and s["days_left"] < 21:
            rows.append("  ↳ certificate renewal due soon — check the IONOS panel")
        for b in s.get("blocking", []):
            rows.append(f"  ↳ {b}")
    rows.append("ALL GREEN" if ok_all else "NEEDS ATTENTION")
    return "\n".join(rows)


def parse_expiry(text):
    m = re.search(r"not expired\s+until (.+?) GMT", text)
    return m.group(1).strip() if m else None


def main():
    stamp = datetime.datetime.now().astimezone()
    lines = [f"SSL watch — {stamp:%Y-%m-%d %H:%M %Z}", ""]
    summary = {"checked_at": stamp.isoformat(timespec="seconds"), "sites": {}}
    ok_all = True

    for domain in DOMAINS:
        try:
            proc = subprocess.run(
                [sys.executable, str(CHECK), domain],
                capture_output=True, text=True, timeout=240,
            )
            text = proc.stdout + proc.stderr
            verdict = next((l.strip() for l in text.splitlines() if l.startswith("VERDICT")),
                           "VERDICT: no output")
            blocking = [l.strip() for l in text.splitlines() if l.startswith("blocking:")]
            ok = proc.returncode == 0
        except Exception as exc:  # noqa: BLE001 - report, never crash the task
            text, verdict, blocking, ok = "", f"VERDICT: runner failed ({exc})", [], False
            proc = None

        ok_all = ok_all and ok
        expiry = parse_expiry(text)
        days = None
        if expiry:
            try:
                when = datetime.datetime.strptime(expiry, "%b %d %H:%M:%S %Y").replace(
                    tzinfo=datetime.timezone.utc)
                days = (when - datetime.datetime.now(datetime.timezone.utc)).days
            except ValueError:
                pass
        issuer = None
        m = re.search(r"INFO  issuer: (.+)", text)
        if m:
            issuer = m.group(1).strip()

        summary["sites"][domain] = {
            "ok": ok,
            "verdict": verdict.replace("VERDICT: ", ""),
            "expires": expiry,
            "days_left": days,
            "issuer": issuer,
            "blocking": blocking,
        }

        flag = "" if ok else "    <-- ATTENTION"
        lines.append(f"{domain}")
        lines.append(f"  {verdict}{flag}")
        if expiry:
            left = f" ({days} days left)" if days is not None else ""
            lines.append(f"  certificate until {expiry} GMT{left}")
            if days is not None and days < 21:
                lines.append("  RENEWAL DUE SOON — IONOS should renew automatically; check the panel")
        if issuer:
            lines.append(f"  issuer {issuer}")
        for b in blocking:
            lines.append(f"  {b}")
        lines.append("")

    lines.append("ALL GREEN" if ok_all else "NEEDS ATTENTION")

    # Notify Discord when something needs a human (never a daily green ping unless asked).
    renewal_due = any(
        s["days_left"] is not None and s["days_left"] < 21 for s in summary["sites"].values()
    )
    wants = {"--test", "--always"} & set(sys.argv[1:])
    if wants or not ok_all or renewal_due:
        token, channel = discord_targets()
        if not token or not channel:
            lines.append("discord: skipped (DISCORD_BOT_TOKEN / DISCORD_HOME_CHANNEL missing)")
        else:
            sent = post_discord(token, channel, discord_message(summary, ok_all))
            lines.append(f"discord: message {sent}")

    report = "\n".join(lines) + "\n"
    OUT_TXT.write_text(report, encoding="utf-8")
    OUT_JSON.write_text(json.dumps(summary, indent=1), encoding="utf-8")
    print(report)
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())

"""SSL / HTTPS readiness check for motionstoodio.com.

Runs without any credentials. Checks DNS, the served page, the TLS certificate
(issuer, names, dates), the HTTP->HTTPS redirect and HSTS.

    python3 ssl-check.py

Exit 0 only when every check passes.
"""
import hashlib
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "motionstoodio.com"
WWW = "www." + DOMAIN
MARKERS = {
    "motionstoodio.com": "Windows that move like they weigh something.",
    "moddys.net": "SPRAY IT LOUD",
}
MARKER = MARKERS.get(DOMAIN, DOMAIN)
PAGE_MARKER_ALT = DOMAIN

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name:34s} {detail}")


def doh(name, rtype):
    req = urllib.request.Request(
        f"https://cloudflare-dns.com/dns-query?name={name}&type={rtype}",
        headers={"accept": "application/dns-json"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        d = json.load(r)
    return [a["data"] for a in d.get("Answer", []) if a.get("type") == {"A": 1, "AAAA": 28}.get(rtype)]


def fetch(url, timeout=20, follow=True):
    req = urllib.request.Request(url, headers={"User-Agent": "motionstoodio-ssl-check"})
    if follow:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


print(f"\nSSL check — {DOMAIN}\n")
print("DNS")
apex = doh(DOMAIN, "A")
www_a = doh(WWW, "A")
check("apex A record", bool(apex), ", ".join(apex) or "none")
check("www A/CNAME", bool(www_a), ", ".join(www_a) or "NXDOMAIN")

print("\nHTTP")
try:
    status, body, headers = fetch(f"http://{DOMAIN}/?cb=sslcheck", follow=False)
    text = body.decode("utf-8", "replace")
    ours = MARKER in text or ("motionstoodio" in text and "Diese Domain" not in text)
    loc = headers.get("Location", "")
    check("http answers", status in (200, 301, 302), str(status))
    check("redirects to https", status in (301, 302) and loc.startswith("https://"),
          loc or "no redirect")
    if status == 200:
        check("serves the page", ours,
              "our page" if ours else "PARKING PAGE — domain not bound to the webspace")
except Exception as e:
    check("http reachable", False, f"{type(e).__name__}: {e}")

print("\nTLS")
try:
    ctx = ssl.create_default_context()
    with socket.create_connection((DOMAIN, 443), timeout=15) as s:
        with ctx.wrap_socket(s, server_hostname=DOMAIN) as ss:
            cert = ss.getpeercert()
            proto = ss.version()
            cipher = ss.cipher()[0]
    subj = dict(x[0] for x in cert["subject"])
    issuer = dict(x[0] for x in cert["issuer"])
    sans = [v for k, v in cert.get("subjectAltName", [])]
    check("handshake", True, f"{proto} {cipher}")
    org = issuer.get("organizationName", "")
    print(f"  INFO  issuer: {org} / {issuer.get('commonName')}")
    check("covers apex", DOMAIN in sans or subj.get("commonName") == DOMAIN, ", ".join(sans[:6]))
    check("covers www", WWW in sans or f"*.{DOMAIN}" in sans, "wildcard" if f"*.{DOMAIN}" in sans else "")
    check("not expired", ssl.cert_time_to_seconds(cert["notAfter"]) > __import__("time").time(),
          f"until {cert['notAfter']}")
    check("browser-trusted chain", True, "verified by default context")
except Exception as e:
    check("handshake", False, f"{type(e).__name__}: {e}")

print("\nHTTPS")
try:
    status, body, headers = fetch(f"https://{DOMAIN}/?cb=sslcheck")
    check("https 200", status == 200, str(status))
    check("serves the page", MARKER in body.decode("utf-8", "replace"), f"marker {MARKER!r}")
    hsts = headers.get("Strict-Transport-Security")
    print(f"  INFO  HSTS{' set: ' + hsts if hsts else ' not sent'}")
except Exception as e:
    check("https reachable", False, f"{type(e).__name__}: {e}")

www_status = None
try:
    s2, b2, _ = fetch(f"https://{WWW}/?cb=sslcheck")
    www_status = s2
    check("www serves (redirect or page)", s2 in (200, 301, 302), str(s2))
except Exception as e:
    check("www serves (redirect or page)", False, f"{type(e).__name__}: {e}")

bad = [r for r in results if not r[1]]
print(f"\nVERDICT: {len(results) - len(bad)}/{len(results)} passed")
if bad:
    print("blocking:", "; ".join(r[0] for r in bad))
sys.exit(1 if bad else 0)

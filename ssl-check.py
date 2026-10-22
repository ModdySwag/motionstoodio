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
import time
import urllib.error
import urllib.request

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "motionstoodio.com"
WWW = "www." + DOMAIN
MARKERS = {
    "motionstoodio.com": "Windows that move like they weigh something.",
    "moddys.net": "SPRAY IT LOUD",
}
# None means this domain has no marker yet: the page checks say so instead of
# passing on any text that happens to contain the domain name.
MARKER = MARKERS.get(DOMAIN)

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
    """Return (status, body, headers, final_url) — final_url is where the chain ended."""
    req = urllib.request.Request(url, headers={"User-Agent": "motionstoodio-ssl-check"})
    if follow:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers), r.geturl()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers), getattr(e, "url", url)


def header(headers, name):
    """Case-insensitive lookup — servers are free to send Location / HSTS in any case."""
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def peer_cert(host):
    """The certificate that host actually presents, verified by the default context."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=15) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            return ss.getpeercert()


print(f"\nSSL check — {DOMAIN}\n")
print("DNS")
dns_checks = (("apex A record", DOMAIN), ("www A/CNAME", WWW))
for label, name in dns_checks:
    try:
        addrs = doh(name, "A")
        check(label, bool(addrs), ", ".join(addrs) or "NXDOMAIN")
    except Exception as e:  # a DNS hiccup must not hide the HTTP/TLS results
        check(label, False, f"lookup failed: {type(e).__name__}: {e}")

print("\nHTTP")
try:
    status, body, headers, _ = fetch(f"http://{DOMAIN}/?cb=sslcheck", follow=False)
    text = body.decode("utf-8", "replace")
    loc = header(headers, "Location") or ""
    check("http answers", status in (200, 301, 302, 307, 308), str(status))
    check("redirects to https", status in (301, 302, 307, 308) and loc.startswith("https://"),
          loc or "no redirect")
    if status == 200:
        if MARKER is None:
            print(f"  INFO  no page marker for {DOMAIN} — content not checked")
        else:
            check("serves the page", MARKER in text,
                  "our page" if MARKER in text else "PARKING PAGE — domain not bound to the webspace")
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
    check("handshake", True, f"{proto} {cipher} (chain verified by the default context)")
    org = issuer.get("organizationName", "")
    print(f"  INFO  issuer: {org} / {issuer.get('commonName')}")
    check("covers apex", DOMAIN in sans or subj.get("commonName") == DOMAIN, ", ".join(sans[:6]))
    check("not expired", ssl.cert_time_to_seconds(cert["notAfter"]) > time.time(),
          f"until {cert['notAfter']}")
    check("already valid", ssl.cert_time_to_seconds(cert["notBefore"]) <= time.time(),
          f"from {cert['notBefore']}")
except Exception as e:
    check("handshake", False, f"{type(e).__name__}: {e}")

try:
    www_cert = peer_cert(WWW)
    www_sans = [v for k, v in www_cert.get("subjectAltName", [])]
    wildcard = f"*.{DOMAIN}" in www_sans
    check("www host certificate", WWW in www_sans or wildcard,
          "wildcard" if wildcard else ", ".join(www_sans[:4]))
    print(f"  INFO  www certificate until {www_cert['notAfter']}")
except Exception as e:
    check("www host certificate", False, f"{type(e).__name__}: {e}")

print("\nHTTPS")
try:
    status, body, headers, final = fetch(f"https://{DOMAIN}/?cb=sslcheck")
    check("https 200", status == 200, str(status))
    check("https stays encrypted", final.startswith("https://"), final)
    if MARKER is None:
        print(f"  INFO  no page marker for {DOMAIN} — content not checked")
    else:
        check("serves the page", MARKER in body.decode("utf-8", "replace"), f"marker {MARKER!r}")
    hsts = header(headers, "Strict-Transport-Security")
    print(f"  INFO  HSTS{' set: ' + hsts if hsts else ' not sent'}")
except Exception as e:
    check("https reachable", False, f"{type(e).__name__}: {e}")

try:
    s2, b2, _, final2 = fetch(f"https://{WWW}/?cb=sslcheck")
    page_ok = True if MARKER is None else MARKER in b2.decode("utf-8", "replace")
    if MARKER is None:
        print(f"  INFO  no page marker for {WWW} — content not checked")
    check("www serves (redirect or page)",
          s2 in (200, 301, 302) and final2.startswith("https://") and page_ok, f"{s2} {final2}")
except Exception as e:
    check("www serves (redirect or page)", False, f"{type(e).__name__}: {e}")

bad = [r for r in results if not r[1]]
print(f"\nVERDICT: {len(results) - len(bad)}/{len(results)} passed")
if bad:
    print("blocking:", "; ".join(r[0] for r in bad))
sys.exit(1 if bad else 0)

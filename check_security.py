"""
Web Security Baseline Checker
------------------------------
Checks basic security settings of a website I own and maps each finding
to compliance controls (ISO 27001:2022, NIST CSF 2.0 and LGPD).

Only run this against systems you own or have written permission to test.

Usage:
    python check_security.py https://your-site.com
"""

import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

TIMEOUT = 10

# Security headers we expect, why they matter, and which controls they support
HEADERS = {
    "Strict-Transport-Security": {
        "risk": "High",
        "why": "Forces browsers to always use HTTPS, protecting data in transit.",
        "controls": "ISO 27001 A.8.24 | NIST CSF PR.DS-02 | LGPD Art. 46",
    },
    "Content-Security-Policy": {
        "risk": "Medium",
        "why": "Limits which scripts can run, reducing cross-site scripting (XSS) risk.",
        "controls": "ISO 27001 A.8.26 | NIST CSF PR.PS-01",
    },
    "X-Frame-Options": {
        "risk": "Medium",
        "why": "Prevents the site from being embedded in other pages (clickjacking).",
        "controls": "ISO 27001 A.8.26 | NIST CSF PR.PS-01",
    },
    "X-Content-Type-Options": {
        "risk": "Low",
        "why": "Stops browsers from guessing file types (MIME sniffing).",
        "controls": "ISO 27001 A.8.9 | NIST CSF PR.PS-01",
    },
    "Referrer-Policy": {
        "risk": "Low",
        "why": "Controls how much URL information is shared with other sites.",
        "controls": "ISO 27001 A.8.9 | LGPD Art. 46",
    },
}


def check_https_redirect(host):
    """Does http:// automatically redirect to https://?"""
    try:
        r = requests.get(f"http://{host}", timeout=TIMEOUT, allow_redirects=True)
        ok = r.url.startswith("https://")
        return ok, "HTTP redirects to HTTPS" if ok else "HTTP does not redirect to HTTPS"
    except requests.RequestException as e:
        return None, f"Could not test HTTP redirect ({type(e).__name__})"


def check_certificate(host, port=443):
    """How many days until the TLS certificate expires?"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days = (expires.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
        return days, version
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def get_set_cookie_headers(response):
    """Return every Set-Cookie header as a separate string."""
    try:
        return response.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        value = response.headers.get("Set-Cookie")
        return [value] if value else []


def run(url):
    if not url.startswith("http"):
        url = "https://" + url
    host = urlparse(url).hostname
    findings = []  # (check, status, risk, detail, controls)

    # 1. HTTPS redirect
    ok, detail = check_https_redirect(host)
    status = "PASS" if ok else ("FAIL" if ok is False else "N/A")
    findings.append(("HTTPS redirect", status, "High", detail,
                     "ISO 27001 A.8.24 | NIST CSF PR.DS-02 | LGPD Art. 46"))

    # 2. TLS certificate
    days, info = check_certificate(host)
    if days is None:
        findings.append(("TLS certificate", "FAIL", "High",
                         f"Could not validate certificate: {info}",
                         "ISO 27001 A.8.24 | NIST CSF PR.DS-02"))
    else:
        status = "PASS" if days > 30 else "WARN"
        findings.append(("TLS certificate", status, "High" if days <= 30 else "Low",
                         f"Valid, expires in {days} days ({info})",
                         "ISO 27001 A.8.24 | NIST CSF PR.DS-02"))

    # 3. Security headers
    try:
        resp = requests.get(url, timeout=TIMEOUT)
    except requests.RequestException as e:
        print(f"Could not reach {url}: {e}")
        sys.exit(1)

    for name, meta in HEADERS.items():
        present = name in resp.headers
        findings.append((name, "PASS" if present else "FAIL",
                         meta["risk"], meta["why"], meta["controls"]))

    # 4. Information disclosure (server reveals its software/version)
    leaks = [f"{h}: {resp.headers[h]}" for h in ("Server", "X-Powered-By") if h in resp.headers]
    findings.append(("Technology disclosure", "WARN" if leaks else "PASS", "Low",
                     "; ".join(leaks) if leaks else "No software/version exposed",
                     "ISO 27001 A.8.9 | NIST CSF PR.PS-01"))

    # 5. Cookie flags
    for cookie in get_set_cookie_headers(resp):
        name = cookie.split("=", 1)[0].strip()
        lower = cookie.lower()
        missing = [f for f in ("secure", "httponly", "samesite") if f not in lower]
        findings.append((f"Cookie '{name}'", "WARN" if missing else "PASS", "Medium",
                         f"Missing flags: {', '.join(missing)}" if missing else "Secure, HttpOnly, SameSite set",
                         "ISO 27001 A.8.26 | LGPD Art. 46"))

    write_report(url, findings)


def write_report(url, findings):
    today = datetime.now().strftime("%Y-%m-%d")
    passed = sum(1 for f in findings if f[1] == "PASS")
    lines = [
        f"# Security Baseline Report",
        f"",
        f"- **Target:** {url}",
        f"- **Date:** {today}",
        f"- **Result:** {passed} of {len(findings)} checks passed",
        f"",
        f"| Check | Status | Risk | Details | Related controls |",
        f"|---|---|---|---|---|",
    ]
    for check, status, risk, detail, controls in findings:
        controls = controls.replace(" | ", " · ")  # keep the Markdown table intact
        lines.append(f"| {check} | {status} | {risk} | {detail} | {controls} |")

    report = "\n".join(lines)
    filename = f"report_{urlparse(url).hostname}_{today}.md"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report + "\n")

    print(report)
    print(f"\nReport saved to {filename}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python check_security.py https://your-site.com")
        sys.exit(1)
    run(sys.argv[1])

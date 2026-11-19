# Web Security Baseline Checker

A small Python tool that checks the basic security settings of a web application and maps each finding to compliance frameworks: **ISO 27001:2022**, **NIST Cybersecurity Framework 2.0** and Brazil's data protection law (**LGPD**).

I built it to assess my own SaaS (a scheduling platform for clinics and salons) from a Governance, Risk and Compliance (GRC) perspective.

![Before and after remediation](images/before_after_terminal.png)

## Why this project

I'm an accountant with 13+ years of experience in regulatory compliance and internal controls, transitioning into GRC. In accounting, every control needs evidence. This tool applies the same idea to security: it collects technical evidence and links it to the control it supports.

## What it checks

| Check | Why it matters | Related controls |
|---|---|---|
| HTTP → HTTPS redirect | Protects data in transit | ISO A.8.24 · NIST PR.DS-02 · LGPD Art. 46 |
| TLS certificate validity | Expired certificates break encryption and trust | ISO A.8.24 · NIST PR.DS-02 |
| Security headers (HSTS, CSP, X-Frame-Options, etc.) | Reduce common web attacks such as XSS and clickjacking | ISO A.8.26 · NIST PR.PS-01 |
| Technology disclosure | Exposed software versions help attackers | ISO A.8.9 · NIST PR.PS-01 |
| Cookie flags (Secure, HttpOnly, SameSite) | Protect user sessions | ISO A.8.26 · LGPD Art. 46 |

Each finding gets a status (PASS / WARN / FAIL) and a risk level (High / Medium / Low).

## How to run

```bash
pip install -r requirements.txt
python check_security.py https://your-site.com
```

The tool prints the results and saves a Markdown report.

> ⚠️ Only scan systems you own or have written permission to test.

## Results from my own system

- **First scan:** 5 of 9 checks passed, with one high-risk gap ([report_before.md](report_before.md))
- **After remediation:** 6 of 9 checks passed, with **no high-risk findings open** ([report_after.md](report_after.md))

The remaining items were assessed and either planned or formally accepted. The URL of the system is redacted on purpose.

## Remediation plan

| Finding | Risk | Action | Status |
|---|---|---|---|
| No HTTPS redirect | High | Enabled "Force HTTPS" on the hosting platform | Done |
| CSRF cookie without Secure flag | Medium | Set `CSRF_COOKIE_SECURE` and `SESSION_COOKIE_SECURE` in Django | Done |
| CSRF cookie without HttpOnly | Low | Accepted: Django docs note limited benefit; JavaScript needs to read the token | Risk accepted |
| No Content-Security-Policy | Medium | Deploy CSP in report-only mode, review violations, then enforce | Planned |
| Server header shows hosting provider | Low | Accepted: set by the platform, no version disclosed | Risk accepted |

## Lesson learned: continuous monitoring

When I ran the tool again the next day, the score dropped to 2 of 8: the security headers and the session cookie had disappeared. The tool had caught that my application was down and the hosting platform was answering instead. I investigated, fixed it and confirmed the score was back to 6 of 9. A control checked once is not a control; it needs continuous monitoring.

## Skills demonstrated

Python · Web security fundamentals · Risk assessment · ISO 27001 · NIST CSF 2.0 · LGPD · Control mapping · Remediation planning · Risk acceptance

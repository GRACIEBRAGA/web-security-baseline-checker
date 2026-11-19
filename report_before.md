# Security Baseline Report

- **Target:** My scheduling SaaS (URL redacted)
- **Date:** 2026-11-17
- **Result:** 5 of 9 checks passed

| Check | Status | Risk | Details | Related controls |
|---|---|---|---|---|
| HTTPS redirect | FAIL | High | HTTP does not redirect to HTTPS | ISO 27001 A.8.24 · NIST CSF PR.DS-02 · LGPD Art. 46 |
| TLS certificate | PASS | Low | Valid, expires in 33 days (TLSv1.3) | ISO 27001 A.8.24 · NIST CSF PR.DS-02 |
| Strict-Transport-Security | PASS | High | Forces browsers to always use HTTPS, protecting data in transit. | ISO 27001 A.8.24 · NIST CSF PR.DS-02 · LGPD Art. 46 |
| Content-Security-Policy | FAIL | Medium | Limits which scripts can run, reducing cross-site scripting (XSS) risk. | ISO 27001 A.8.26 · NIST CSF PR.PS-01 |
| X-Frame-Options | PASS | Medium | Prevents the site from being embedded in other pages (clickjacking). | ISO 27001 A.8.26 · NIST CSF PR.PS-01 |
| X-Content-Type-Options | PASS | Low | Stops browsers from guessing file types (MIME sniffing). | ISO 27001 A.8.9 · NIST CSF PR.PS-01 |
| Referrer-Policy | PASS | Low | Controls how much URL information is shared with other sites. | ISO 27001 A.8.9 · LGPD Art. 46 |
| Technology disclosure | WARN | Low | Server: PythonAnywhere | ISO 27001 A.8.9 · NIST CSF PR.PS-01 |
| Cookie 'csrftoken' | WARN | Medium | Missing flags: secure, httponly | ISO 27001 A.8.26 · LGPD Art. 46 |

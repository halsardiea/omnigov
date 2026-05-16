# OmniGov

A vulnerability scanning and compliance management platform for security teams. OmniGov scans networks using Greenbone Vulnerability Manager, maps findings to industry frameworks, and generates actionable compliance reports.
 
## What it does

- **Scan** — Run vulnerability scans against targets via GVM, with real-time status updates over WebSocket
- **Correlate** — Automatically map findings to controls across ISO 27001, NIST CSF 2.0, CIS Controls v8, OWASP Top 10, and the Jordan National Cybersecurity Framework — using heuristic and AI-assisted (Claude) correlation
- **Report** — Generate executive and technical compliance reports in PDF and CSV formats, with per-framework scoring
- **Manage** — Role-based access control with OTP authentication

## Getting Started

See **[SETUP.md](./SETUP.md)** for the full guide on running this project locally and in production.

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Django 5.1, Django REST Framework |
| Task Queue | Celery 5, Redis |
| Real-time | Django Channels 4, Daphne |
| Scanner | Greenbone (python-gvm) |
| AI | Anthropic Claude |
| Reports | WeasyPrint, xhtml2pdf, pypdf |
| Database | PostgreSQL (production), SQLite (development) |
| Auth | Django-OTP |

## Dependencies

```
# Core
Django>=5.1,<5.2
djangorestframework>=3.15,<4.0
python-decouple>=3.8

# Async & WebSocket
channels>=4.0,<5.0
channels-redis>=4.2,<5.0
daphne>=4.1,<5.0

# Task Queue
celery>=5.4,<6.0
django-celery-results>=2.5,<3.0
redis>=5.0,<6.0

# Database
psycopg2-binary>=2.9,<3.0

# Auth & OTP
django-otp>=1.4,<2.0

# Rate Limiting
django-ratelimit>=4.1,<5.0

# Scanner
python-gvm>=24.0,<25.0

# PDF Generation
weasyprint>=62,<63
xhtml2pdf>=0.2.16,<0.3
pypdf>=5.0,<6.0

# AI Correlation
anthropic>=0.37,<2.0

# XML Parsing
lxml>=5.0
defusedxml>=0.7,<1.0

# Testing
pytest>=8.0
pytest-django>=4.8
pytest-cov>=5.0
pytest-asyncio>=0.23
```

---

> Built as part of a graduation project.

# OmniGov — Complete Run + Shutdown Guide

Everything you need to boot OmniGov from zero, run real scans, and shut everything down cleanly.

---

## What Is This

OmniGov runs locally in WSL using Django + SQLite.

- Docker is not required for the app runtime.
- Redis is not required in development mode.
- Real scans can run through local GVM via Unix socket.

This guide matches the known-good baseline validated in May 2026.

- **SQLite** — built-in, no server needed
- **In-memory channels** — no Redis needed
- **Celery eager mode** — tasks run inline in development
- **Detached scan recovery worker** — long scans recover safely after reloads
- **GVM support** — via Unix socket

Use one terminal for the app; GVM services run in the background when using real scans.

---

## Prerequisites (one-time check)

Open WSL and verify:

```bash
python3 --version    # needs 3.11+
```

If missing:
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv
```

---

## First-Time Setup

Run these steps once. After that, use the "Full Ignition" section each time you resume.

### 1 — Enter the project

```bash
cd /mnt/c/Users/halsa/Desktop/GP/GP2
```

### 2 — Create the virtual environment

```bash
python3 -m venv /home/halsardiea/omnigov/.venv
source /home/halsardiea/omnigov/.venv/bin/activate
```

### 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### 4 — Create your .env file

```bash
cp .env.example .env
```

Open `.env` and fill in this value (leave everything else as-is):

```
DJANGO_SECRET_KEY=any-random-string-at-least-50-characters-long
```

### 5 — Run database migrations

```bash
export DJANGO_SETTINGS_MODULE=omnigov.settings.development
python manage.py migrate
```

### 6 — Load compliance frameworks

```bash
python manage.py load_compliance_fixtures
```

Expected output:
```
Created CIS Controls (v8.1): 149 controls loaded
Created ISO/IEC 27001 Annex A Controls (2022): 93 controls loaded
Created Jordan National Cybersecurity Framework: 47 controls loaded
Created NIST Cybersecurity Framework (2.0): 106 controls loaded
Created OWASP Top 10 (2025): 10 controls loaded
Successfully loaded 5 frameworks and 405 controls.
```

### 7 — Create the admin account

```bash
python manage.py createsuperuser --username admin --email admin@omnigov.local
```

When prompted for password, enter: `Admin@omnigov123`

---

## Full Ignition (Known-Good Startup)

Use this when resuming later and you want the entire project stack ready for real scans.

### 1 — Enter project and activate venv

```bash
cd /mnt/c/Users/halsa/Desktop/GP/GP2
source /home/halsardiea/omnigov/.venv/bin/activate
export DJANGO_SETTINGS_MODULE=omnigov.settings.development
```

### 2 — Start scanner services

```bash
sudo systemctl start gvmd ospd-openvas notus-scanner
```

Optional readiness check:

```bash
while [ ! -S /run/gvmd/gvmd.sock ]; do echo "waiting for gvmd.sock..."; sleep 3; done; echo "GVM ready"
```

### 3 — Run migrations if needed

```bash
python manage.py migrate
```

### 4 — Start OmniGov web app

```bash
python manage.py runserver 0.0.0.0:8000
```

Open: **http://localhost:8000**

### 5 — Quick validation

1. Log in.
2. Open **Scans → Create**.
3. Pick `CIS Controls` and `NIST Cybersecurity Framework`.
4. Use `Full and Fast`.
5. Target example: `192.168.1.100`.

---

## Login Credentials

| Field    | Value                 |
|----------|-----------------------|
| Email    | `admin@omnigov.local` |
| Password | `Admin@omnigov123`    |

---

## Core Workflow

1. **Log in** at http://localhost:8000
2. **Compliance** — all 5 frameworks pre-loaded (CIS, ISO 27001, JNCF, NIST CSF, OWASP)
3. **Scans → New Scan**
   - Enter a name and target IP or CIDR (e.g. `192.168.1.1`)
   - Select one or more frameworks
   - Choose scan config:
     - **Full and Fast** — recommended
     - **Discovery**
     - **Host Discovery**
     - **System Discovery**
     - **Log4Shell**
   - Click **Start Scan**
4. **Scan detail** — watch real-time progress
5. When status shows **Correlation Complete** — AI has mapped all findings to your selected frameworks
6. **Reports** — download Executive PDF or Technical CSV

---

## GVM Setup

OmniGov connects to GVM via a Unix socket. Make sure your `.env` has the correct values:

```
GVM_USE_MOCK=False
GVM_SOCKET_PATH=/run/gvmd/gvmd.sock
GVM_ADMIN_USER=admin
GVM_ADMIN_PASSWORD=admin
```

Start GVM services:

```bash
sudo systemctl start gvmd ospd-openvas notus-scanner
```

Wait for the socket to be ready:

```bash
while [ ! -S /run/gvmd/gvmd.sock ]; do echo "waiting..."; sleep 3; done && echo "GVM ready"
```

Then start the app normally — it connects directly via the socket.

## Close Everything (when pausing work)

Use this to fully stop OmniGov runtime processes.

```bash
pkill -f 'manage.py runserver 0.0.0.0:8000' || true
pkill -f 'manage.py run_scan_worker' || true
pkill -f 'daphne' || true
```

Optional: also stop scanner services if you are done scanning for now.

```bash
sudo systemctl stop gvmd ospd-openvas notus-scanner
```

---

## Reset Everything (fresh start)

Wipes the database and recreates everything:

```bash
cd /mnt/c/Users/halsa/Desktop/GP/GP2
source /home/halsardiea/omnigov/.venv/bin/activate
export DJANGO_SETTINGS_MODULE=omnigov.settings.development

rm -f db.sqlite3
python manage.py migrate
python manage.py load_compliance_fixtures
python manage.py createsuperuser --username admin --email admin@omnigov.local
python manage.py runserver 0.0.0.0:8000
```

---

## Troubleshooting

**AI correlation not running**
Leave `ANTHROPIC_API_KEY` blank in `.env` to use local heuristic matching only. Set it to a real Anthropic API key to enable Claude-backed correlation.

**`OperationalError: no such table`**
```bash
python manage.py migrate
```

**Frameworks show 0 controls**
```bash
python manage.py load_compliance_fixtures
```

**`NoReverseMatch` / template crash**
Stop the server (`Ctrl+C`) and restart.

**Forgot admin password**
```bash
python manage.py changepassword admin
```

**Force-stop all app runtime processes**
```bash
pkill -9 -f 'manage.py runserver|manage.py run_scan_worker|daphne' || true
```

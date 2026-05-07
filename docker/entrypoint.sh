#!/bin/bash
# OmniGov — Docker entrypoint for the web container
# Runs on every container start. Idempotent (safe to re-run).
set -e

# ── 1. Wait for PostgreSQL ──────────────────────────────────
echo "==> Waiting for PostgreSQL at ${DB_HOST:-postgres}..."
until pg_isready -h "${DB_HOST:-postgres}" -U "${DB_USER:-omnigov}" -q; do
    printf "."
    sleep 2
done
echo ""
echo "    PostgreSQL is ready."

# ── 2. Apply database migrations ───────────────────────────
echo "==> Running database migrations..."
python manage.py migrate --noinput

# ── 3. Collect static files ────────────────────────────────
echo "==> Collecting static files..."
python manage.py collectstatic --noinput --clear -v 0

# ── 4. Load compliance framework corpora ──────────────────
echo "==> Loading compliance frameworks..."
python manage.py load_compliance_fixtures

# ── 5. Create the Django admin superuser (first run only) ──
echo "==> Ensuring admin user exists..."
python manage.py shell << 'PYEOF'
from apps.accounts.models import User

EMAIL    = "admin@omnigov.local"
USERNAME = "admin"
PASSWORD = "Admin@omnigov123"

if not User.objects.filter(email=EMAIL).exists():
    u = User.objects.create_superuser(
        username=USERNAME,
        email=EMAIL,
        password=PASSWORD,
    )
    u.save()
    print(f"  Created admin user: {EMAIL}  /  {PASSWORD}")
else:
    print("  Admin user already exists — skipping.")
PYEOF

# ── 6. Start the ASGI server ───────────────────────────────
echo "==> Starting OmniGov on port 8000..."
exec daphne -b 0.0.0.0 -p 8000 omnigov.asgi:application

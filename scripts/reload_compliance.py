"""Cleans up old/duplicate framework entries and reloads all corpus files."""
import os, sys, django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "omnigov.settings.development")
sys.path.insert(0, "/mnt/c/Users/halsa/Desktop/GP/GP2")
django.setup()

from apps.compliance.models import Framework
from apps.compliance.corpus import load_all_framework_corpora

# --- 1. Show current state ---
print("=== Current DB state ===")
for f in Framework.objects.all().order_by("name", "version"):
    print(f"  [{f.pk}] {f.name!r}  v={f.version!r}  controls={f.controls.count()}")

# --- 2. Deactivate known stale / duplicate entries (can't delete if FK-protected) ---
stale_names = ["ISO 27001"]   # old 40-control entry with a different name
for name in stale_names:
    qs = Framework.objects.filter(name=name)
    count = qs.count()
    if count:
        qs.update(is_active=False)
        print(f"\nDeactivated {count} stale framework(s) named {name!r}")

# --- 3. Reload all corpus files ---
print("\n=== Loading corpus files ===")
results = load_all_framework_corpora()
for r in results:
    action = "created" if r.framework_created else "updated"
    print(f"  {action}: {r.label!r}  => {r.controls_loaded} controls (replaced {r.controls_replaced})")

# --- 4. Show final state ---
print("\n=== Final DB state ===")
for f in Framework.objects.all().order_by("name", "version"):
    print(f"  [{f.pk}] {f.name!r}  v={f.version!r}  controls={f.controls.count()}")

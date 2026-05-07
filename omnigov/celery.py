# ---
# LOCATION : omnigov/celery.py
# PURPOSE  : Bootstraps the Celery task queue that runs heavy background work
#            (scan orchestration, finding parsing, report generation) outside
#            the web-server process so the UI never blocks on long-running jobs.
#
# CONNECTS TO:
#   - omnigov/settings/base.py         → CELERY_* settings (broker, result backend)
#   - omnigov/settings/development.py  → overrides broker to in-memory so no
#                                        Redis is needed locally; TASK_ALWAYS_EAGER
#                                        makes tasks run synchronously in dev
#   - apps/interceptor/tasks.py        → process_scan_findings — parse + correlate
#   - apps/reports/tasks.py            → generate_reports_pipeline — PDF/CSV creation
#   - apps/scanner/tasks.py            → run_scan — the scan lifecycle worker
# ---
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'omnigov.settings.development')

# Create the Celery application instance.
# The name 'omnigov' is used as a prefix on all task names in the broker.
app = Celery('omnigov')

# Pull Celery configuration from Django settings using the 'CELERY_' namespace.
# This means CELERY_BROKER_URL, CELERY_RESULT_BACKEND, etc. are all read from
# settings/base.py (or the active environment override).
app.config_from_object('django.conf:settings', namespace='CELERY')

# Automatically discover tasks in every INSTALLED_APP's tasks.py module so we
# never have to manually register them here.
app.autodiscover_tasks()


# A minimal diagnostic task — useful during development to verify the Celery
# worker is running and connected. Never called in production flows.
@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f'Request: {self.request!r}')

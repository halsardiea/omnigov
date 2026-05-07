# ---
# LOCATION : apps/scanner/runtime.py
# PURPOSE  : Makes scan execution durable across web-server restarts and Celery
#            worker failures. The key idea is that scans run as completely
#            separate OS processes (spawned by spawn_scan_worker) rather than
#            inside the web server or a Celery worker, so a server reload never
#            interrupts a running scan.
#            ensure_scan_worker() is called on every page load of any scan-related
#            view, acting as a lightweight watchdog that auto-recovers stalled jobs.
#
# CONNECTS TO:
#   - apps/scanner/views.py          → ScanListView and ScanDetailView call
#                                       ensure_scan_worker() on every page load
#   - apps/scanner/tasks.py          → spawn_scan_worker() runs the management
#                                       command that calls _run_scan_pipeline()
#   - apps/scanner/models.py         → ScanTask.status and .updated_at read here
#                                       to diagnose stalled jobs
#   - omnigov/settings/base.py       → SCAN_POLL_INTERVAL used to calculate the
#                                       staleness threshold
# ---
"""Runtime helpers for durable scan execution and recovery."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from django.conf import settings
from django.utils import timezone


PENDING_RECOVERY_GRACE_SECONDS = 30
STALE_SCAN_GRACE_SECONDS = 60
ANALYSIS_RECOVERY_GRACE_SECONDS = 300


# Each scan gets its own log file at logs/scanner/scan-<id>.log.
# This separates per-scan output from the main application log so a
# noisy or long-running scan does not flood the general log.
def _log_path(scan_task_id: int) -> Path:
    log_dir = Path(settings.BASE_DIR) / 'logs' / 'scanner'
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / f'scan-{scan_task_id}.log'


def spawn_scan_worker(scan_task_id: int, *, resume: bool = False) -> None:
    """Launch a detached worker process that survives web-server reloads."""
    manage_py = Path(settings.BASE_DIR) / 'manage.py'
    command = [sys.executable, str(manage_py), 'run_scan_worker', str(scan_task_id)]
    if resume:
        command.append('--resume')

    log_handle = _log_path(scan_task_id).open('ab')
    env = os.environ.copy()
    env.setdefault(
        'DJANGO_SETTINGS_MODULE',
        os.environ.get('DJANGO_SETTINGS_MODULE', 'omnigov.settings.development'),
    )

    subprocess.Popen(  # noqa: S603,S607 - internal command only
        command,
        cwd=settings.BASE_DIR,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    log_handle.close()


# Returns True if a pending scan has been waiting for a worker longer than
# PENDING_RECOVERY_GRACE_SECONDS. A short grace period avoids spawning a
# duplicate worker for a scan that was just created and whose first worker
# is still starting up.
def pending_scan_needs_worker(scan_task) -> bool:
    if scan_task.status != scan_task.Status.PENDING:
        return False
    age = timezone.now() - scan_task.created_at
    return age.total_seconds() >= PENDING_RECOVERY_GRACE_SECONDS


# Returns True if an apparently active scan has not written a progress update
# for longer than the expected poll interval, suggesting its worker has crashed
# or been killed and needs to be restarted.
def scan_is_stale(scan_task) -> bool:
    if scan_task.status not in {scan_task.Status.RUNNING, scan_task.Status.ANALYZING, scan_task.Status.COMPLETED}:
        return False

    age = timezone.now() - scan_task.updated_at
    if scan_task.status == scan_task.Status.RUNNING:
        threshold = max(settings.SCAN_POLL_INTERVAL * 3, STALE_SCAN_GRACE_SECONDS)
    else:
        threshold = ANALYSIS_RECOVERY_GRACE_SECONDS
    return age.total_seconds() >= threshold


def ensure_scan_worker(scan_task) -> bool:
    """Start or resume a detached worker when a scan appears stalled."""
    if scan_task.status in {
        scan_task.Status.FAILED,
        scan_task.Status.STOPPED,
        scan_task.Status.ANALYZED,
    }:
        return False

    if pending_scan_needs_worker(scan_task):
        scan_task.updated_at = timezone.now()
        scan_task.save(update_fields=['updated_at'])
        spawn_scan_worker(scan_task.id)
        return True

    if scan_is_stale(scan_task):
        scan_task.updated_at = timezone.now()
        scan_task.save(update_fields=['updated_at'])
        spawn_scan_worker(scan_task.id, resume=True)
        return True

    return False
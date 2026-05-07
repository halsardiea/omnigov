from django.core.management.base import BaseCommand, CommandError

from apps.scanner.tasks import _run_scan_pipeline


class Command(BaseCommand):
    help = 'Run or resume a scan pipeline in a detached worker process.'

    def add_arguments(self, parser):
        parser.add_argument('scan_task_id', type=int)
        parser.add_argument('--resume', action='store_true', default=False)

    def handle(self, *args, **options):
        scan_task_id = options['scan_task_id']
        resume = options['resume']

        try:
            _run_scan_pipeline(scan_task_id, resume=resume)
        except Exception as exc:
            raise CommandError(str(exc)) from exc
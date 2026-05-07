from django.core.management.base import BaseCommand

from apps.compliance.corpus import CorpusLoadError, load_all_framework_corpora
from apps.compliance.models import Framework, FrameworkControl


class Command(BaseCommand):
    help = 'Load compliance framework controls from JSON fixture files.'

    def handle(self, *args, **options):
        try:
            results = load_all_framework_corpora()
        except CorpusLoadError as exc:
            self.stderr.write(self.style.ERROR(str(exc)))
            return

        controls_loaded = sum(result.controls_loaded for result in results)
        frameworks_loaded = len(results)

        for result in results:
            action = 'Created' if result.framework_created else 'Updated'
            self.stdout.write(
                f"{action} {result.label} from {result.source_file}: "
                f"{result.controls_loaded} controls loaded"
            )

        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully loaded {frameworks_loaded} frameworks and {controls_loaded} controls.'
            )
        )

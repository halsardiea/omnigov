"""
Management command to load compliance framework fixtures from JSON.

Usage:
    python manage.py load_compliance_fixtures
"""
import json
import logging
from pathlib import Path

from django.core.management.base import BaseCommand

from apps.compliance.models import Framework, FrameworkControl

logger = logging.getLogger(__name__)

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent / 'data' / 'corpus'


class Command(BaseCommand):
    help = 'Load compliance framework controls from JSON fixture files.'

    def handle(self, *args, **options):
        fixture_file = CORPUS_DIR / 'iso27001_controls.json'
        if not fixture_file.exists():
            self.stderr.write(self.style.ERROR(f'Fixture file not found: {fixture_file}'))
            return

        with open(fixture_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        controls_loaded = 0

        for entry in data:
            model_name = entry.get('model', '')
            fields = entry.get('fields', {})

            if model_name == 'compliance.Framework':
                framework, created = Framework.objects.update_or_create(
                    pk=entry.get('pk'),
                    defaults={
                        'name': fields['name'],
                        'version': fields['version'],
                        'description': fields.get('description', ''),
                        'is_active': fields.get('is_active', True),
                    },
                )
                action = 'Created' if created else 'Updated'
                self.stdout.write(f'{action} framework: {framework}')

            elif model_name == 'compliance.FrameworkControl':
                framework_id = fields.get('framework')
                FrameworkControl.objects.update_or_create(
                    framework_id=framework_id,
                    control_id=fields['control_id'],
                    defaults={
                        'title': fields['title'],
                        'description': fields.get('description', ''),
                        'category': fields.get('category', ''),
                        'keywords': fields.get('keywords', []),
                        'guidance': fields.get('guidance', ''),
                    },
                )
                controls_loaded += 1

        self.stdout.write(self.style.SUCCESS(f'Successfully loaded {controls_loaded} controls.'))

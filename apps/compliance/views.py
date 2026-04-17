import json
import logging
from pathlib import Path

from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.views.generic import ListView, DetailView

from .models import Framework, FrameworkControl

logger = logging.getLogger(__name__)

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / 'data' / 'corpus'


class FrameworkListView(LoginRequiredMixin, ListView):
    model = Framework
    template_name = 'compliance/framework_list.html'
    context_object_name = 'frameworks'
    queryset = Framework.objects.filter(is_active=True)


class FrameworkDetailView(LoginRequiredMixin, DetailView):
    model = Framework
    template_name = 'compliance/framework_detail.html'
    context_object_name = 'framework'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        framework = self.get_object()
        context['controls'] = FrameworkControl.objects.filter(
            framework=framework,
        ).order_by('control_id')
        return context


@login_required
@user_passes_test(lambda u: u.is_admin)
def load_fixtures(request):
    """Load ISO 27001 controls from JSON fixture into the database."""
    if request.method != 'POST':
        return redirect('compliance:framework-list')

    fixture_file = CORPUS_DIR / 'iso27001_controls.json'
    if not fixture_file.exists():
        messages.error(request, 'Fixture file not found.')
        return redirect('compliance:framework-list')

    try:
        with open(fixture_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        framework_created = False
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
                framework_created = True
                logger.info(f"Framework {'created' if created else 'updated'}: {framework}")

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

        messages.success(request, f'Loaded {controls_loaded} controls successfully.')
        logger.info(f"Compliance fixtures loaded: {controls_loaded} controls")

    except Exception as e:
        logger.exception(f"Error loading compliance fixtures: {e}")
        messages.error(request, f'Error loading fixtures: {str(e)}')

    return redirect('compliance:framework-list')

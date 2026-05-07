# ---
# LOCATION : apps/compliance/views.py
# PURPOSE  : Lets users browse the compliance framework catalogue — see which
#            frameworks are loaded, how many controls each contains, and read the
#            full control text. Also exposes the admin-only fixture loader that
#            imports framework JSON files into the database.
#
# CONNECTS TO:
#   - apps/compliance/models.py    → Framework and FrameworkControl — all data comes here
#   - apps/compliance/corpus.py    → load_all_framework_corpora() called by load_fixtures
#   - apps/compliance/urls.py      → maps URL paths to these views
#   - templates/compliance/        → framework_list.html and framework_detail.html
#                                    consume the context dicts built here
# ---
import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.shortcuts import redirect
from django.views.generic import ListView, DetailView

from .corpus import CorpusLoadError, load_all_framework_corpora
from .models import Framework, FrameworkControl

logger = logging.getLogger(__name__)


# Lists all active frameworks with their control counts pre-annotated in one query.
# The 'metadata only' vs 'full catalog' distinction shown on the template is derived
# here by comparing control_total against zero.
class FrameworkListView(LoginRequiredMixin, ListView):
    model = Framework
    template_name = 'compliance/framework_list.html'
    context_object_name = 'frameworks'
    queryset = Framework.objects.filter(is_active=True).annotate(control_total=Count('controls'))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        frameworks = list(context['frameworks'])
        context['frameworks'] = frameworks
        context['total_frameworks'] = len(frameworks)
        context['total_controls'] = sum(framework.control_total for framework in frameworks)
        context['frameworks_ready'] = sum(1 for framework in frameworks if framework.control_total)
        context['frameworks_metadata_only'] = sum(1 for framework in frameworks if not framework.control_total)
        return context


# Displays the full control catalogue for a single framework.
# Groups controls by category so the page can render a breakdown table
# showing how many controls fall under 'Access Control', 'Cryptography', etc.
class FrameworkDetailView(LoginRequiredMixin, DetailView):
    model = Framework
    template_name = 'compliance/framework_detail.html'
    context_object_name = 'framework'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        framework = self.get_object()
        controls = list(FrameworkControl.objects.filter(
            framework=framework,
        ).order_by('id'))
        category_totals = []
        seen_categories = {}
        for control in controls:
            if control.category not in seen_categories:
                seen_categories[control.category] = {'name': control.category, 'count': 0}
                category_totals.append(seen_categories[control.category])
            seen_categories[control.category]['count'] += 1

        context['controls'] = controls
        context['control_count'] = len(controls)
        context['category_breakdown'] = category_totals
        context['catalog_status'] = 'Full catalog' if controls else 'Metadata only'
        return context


@login_required
@user_passes_test(lambda u: u.is_admin)
def load_fixtures(request):
    """Load all framework corpora from local JSON files into the database."""
    if request.method != 'POST':
        return redirect('compliance:framework-list')

    try:
        results = load_all_framework_corpora()
        controls_loaded = sum(result.controls_loaded for result in results)
        frameworks_loaded = len(results)
        messages.success(
            request,
            f'Loaded {frameworks_loaded} frameworks and {controls_loaded} controls successfully.',
        )
        logger.info(
            'Compliance corpora loaded: %s frameworks, %s controls',
            frameworks_loaded,
            controls_loaded,
        )

    except CorpusLoadError as exc:
        messages.error(request, f'Error loading corpora: {exc}')
    except Exception as exc:
        logger.exception('Error loading compliance corpora: %s', exc)
        messages.error(request, f'Error loading corpora: {exc}')

    return redirect('compliance:framework-list')

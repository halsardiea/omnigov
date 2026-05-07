# ---
# LOCATION : apps/scanner/views.py
# PURPOSE  : All HTTP views for the scan management workflow: creating a scan,
#            listing scans, inspecting a single scan's findings, stopping a running
#            scan, and polling live status. This is the primary user-facing entry
#            point for the scanning subsystem.
#
# CONNECTS TO:
#   - apps/scanner/models.py         → ScanTask and ApprovedTargetRange — read/written
#                                       on every POST and GET
#   - apps/scanner/runtime.py        → spawn_scan_worker() launches the detached
#                                       background process; ensure_scan_worker() recovers
#                                       stalled jobs on the list and detail pages
#   - apps/accounts/access.py        → user_can_manage_scans() and user_can_view_all_data()
#                                       control data scope and action visibility
#   - apps/compliance/models.py      → Framework queryset populated in ScanCreateForm
#   - apps/interceptor/models.py     → TechnicalFinding queryset shown on ScanDetailView
#   - apps/scanner/urls.py           → URL patterns that route requests to these views
#   - omnigov/settings/base.py       → security_logger routes to logs/security.log via
#                                       the LOGGING dict's 'django.security' handler
# ---
import ipaddress
import logging

from django import forms
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.views import View
from django.views.generic import ListView, DetailView

from apps.accounts.access import user_can_manage_scans, user_can_view_all_data
from .models import ScanTask, ApprovedTargetRange
from .runtime import ensure_scan_worker, spawn_scan_worker
from apps.compliance.models import Framework

logger = logging.getLogger(__name__)

# Security audit events route to the dedicated security.log file
security_logger = logging.getLogger('django.security')


class ScanCreateForm(forms.Form):
    name = forms.CharField(
        max_length=200,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'Scan name'}),
    )
    target = forms.CharField(
        max_length=500,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'Target IP or CIDR (e.g. 192.168.1.0/24)'}),
        help_text='IP address or CIDR range to scan.',
    )
    frameworks = forms.ModelMultipleChoiceField(
        queryset=Framework.objects.filter(is_active=True),
        widget=forms.CheckboxSelectMultiple,
    )
    scan_config = forms.ChoiceField(
        choices=[
            ('full_and_fast',     'Full and Fast (recommended)'),
            ('discovery',         'Discovery'),
            ('host_discovery',    'Host Discovery'),
            ('system_discovery',  'System Discovery'),
            ('log4shell',         'Log4Shell'),
        ],
        initial='full_and_fast',
        widget=forms.Select(attrs={'class': 'form-input'}),
    )

    def clean_target(self):
        raw_target = self.cleaned_data['target'].strip()

        # Step 1 — Validate that the input is a real IP address or CIDR range.
        # This rejects hostnames, free-text, command injection strings, and typos
        # before they ever reach the GVM scanner.
        try:
            submitted_network = ipaddress.ip_network(raw_target, strict=False)
        except ValueError:
            raise forms.ValidationError(
                'Enter a valid IP address or CIDR range (e.g. 192.168.1.1 or 192.168.1.0/24).'
            )

        # Step 2 — Check the target against the admin-approved allowlist.
        # If no approved ranges exist yet, we allow the scan so the app works
        # out of the box. Once ranges are configured, only targets inside them
        # are accepted — this prevents scanning external or unauthorised networks.
        approved_ranges = ApprovedTargetRange.objects.all()
        if approved_ranges.exists():
            target_is_approved = self._target_falls_within_an_approved_range(
                submitted_network, approved_ranges
            )
            if not target_is_approved:
                raise forms.ValidationError(
                    'This target is outside the approved scan ranges. '
                    'Contact an administrator to add it to the allowlist.'
                )

        return str(submitted_network)

    @staticmethod
    def _target_falls_within_an_approved_range(submitted_network, approved_ranges):
        """Return True if the submitted network is a subnet of any approved range.

        For example, 192.168.1.100/32 passes if 192.168.1.0/24 is approved.
        """
        for approved in approved_ranges:
            try:
                approved_network = ipaddress.ip_network(approved.cidr, strict=False)
                if submitted_network.subnet_of(approved_network):
                    return True
            except ValueError:
                # Skip any approved range with a malformed CIDR — don't crash
                continue
        return False


# Builds a descriptive label for the scan progress bar displayed on the detail page.
# Maps the scan's current status and progress percentage to a human-readable sentence
# so the user always knows what stage their scan is in, not just a raw number.
def get_scan_progress_label(scan):
    if scan.status == ScanTask.Status.ANALYZED:
        return 'Analysis complete and reports are ready for download.'
    if scan.status == ScanTask.Status.COMPLETED:
        return 'Scan complete. Correlating findings and generating reports...'
    if scan.status == ScanTask.Status.FAILED:
        return scan.error_message or 'Scan failed before report generation.'
    if scan.status == ScanTask.Status.STOPPED:
        return 'Scan stopped before the analysis pipeline finished.'

    progress = scan.progress or 0
    if progress < 15:
        return 'Target discovery and reachability validation in progress...'
    if progress < 60:
        return 'Scanner collection and evidence gathering in progress...'
    if progress < 85 or scan.status == ScanTask.Status.RUNNING:
        return 'Normalizing findings and preparing the remediation register...'
    if scan.framework_count == 1:
        return 'Mapping findings into the selected framework corpus...'
    return 'Mapping findings into the selected framework corpora...'


# Scopes the ScanTask queryset to what the requesting user is allowed to see.
# Superusers get the full table; everyone else sees only their own scans.
# This helper is called by every view to enforce the same ownership rule consistently.
def _scan_queryset_for_user(user):
    queryset = ScanTask.objects.select_related('created_by', 'framework').prefetch_related('selected_frameworks').order_by('-created_at')
    if user_can_view_all_data(user):
        return queryset
    return queryset.filter(created_by=user)


# Displays the paginated list of all scans the user can see.
# Calls ensure_scan_worker() for the first 10 results to automatically recover
# any scans that appear stalled — this is the project's self-healing mechanism.
class ScanListView(LoginRequiredMixin, ListView):
    model = ScanTask
    template_name = 'scanner/scan_list.html'
    context_object_name = 'scans'
    ordering = ['-created_at']

    def get_queryset(self):
        return _scan_queryset_for_user(self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        scans = context['scans']
        for scan in list(scans[:10]):
            ensure_scan_worker(scan)
        context['status_counts'] = {
            'all': scans.count(),
            'pending': scans.filter(status=ScanTask.Status.PENDING).count(),
            'running': scans.filter(status=ScanTask.Status.RUNNING).count(),
            'analyzing': scans.filter(status=ScanTask.Status.ANALYZING).count(),
            'completed': scans.filter(status__in=[ScanTask.Status.ANALYZED, ScanTask.Status.COMPLETED]).count(),
            'failed': scans.filter(status=ScanTask.Status.FAILED).count(),
            'stopped': scans.filter(status=ScanTask.Status.STOPPED).count(),
        }
        context['can_manage_scans'] = user_can_manage_scans(self.request.user)
        return context


# Shows the full detail page for a single scan: findings table, severity breakdown,
# linked reports, and the live progress bar.
# Also triggers worker recovery and refreshes from DB so the page always reflects
# the latest state even if the user hits F5 mid-scan.
class ScanDetailView(LoginRequiredMixin, DetailView):
    model = ScanTask
    template_name = 'scanner/scan_detail.html'
    context_object_name = 'scan'

    def get_queryset(self):
        return _scan_queryset_for_user(self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        scan = self.object
        ensure_scan_worker(scan)
        scan.refresh_from_db()
        from apps.interceptor.models import TechnicalFinding

        findings = TechnicalFinding.objects.none()
        if scan.status in [ScanTask.Status.ANALYZED, ScanTask.Status.COMPLETED]:
            findings = TechnicalFinding.objects.filter(scan_task=scan).select_related('analysis').order_by('-cvss_score', 'severity')

        context['findings'] = findings
        context['reports'] = scan.reports.all().order_by('-generated_at')
        context['severity_counts'] = {
            'total': findings.count(),
            'critical': findings.filter(severity='Critical').count(),
            'high': findings.filter(severity='High').count(),
            'medium': findings.filter(severity='Medium').count(),
            'low': findings.filter(severity='Low').count(),
            'log': findings.filter(severity='Log').count(),
        }
        context['progress_label'] = get_scan_progress_label(scan)
        context['can_manage_scans'] = user_can_manage_scans(self.request.user)
        return context


# The scan submission form view.
# GET: renders the blank form with active frameworks and scan-config choices.
# POST: validates the target IP/CIDR against the approved allowlist, creates the
#       ScanTask row, sets selected frameworks, and spawns the detached worker process.
class ScanCreateView(LoginRequiredMixin, View):

    @staticmethod
    def _build_context(form):
        return {'form': form}

    def get(self, request):
        form = ScanCreateForm()
        return render(request, 'scanner/scan_create.html', self._build_context(form))

    def post(self, request):
        form = ScanCreateForm(request.POST)
        if form.is_valid():
            target = form.cleaned_data['target']
            selected_frameworks = list(form.cleaned_data['frameworks'])

            scan_task = ScanTask.objects.create(
                name=form.cleaned_data['name'],
                target=target,
                framework=selected_frameworks[0],
                scan_config=form.cleaned_data['scan_config'],
                created_by=request.user,
            )
            scan_task.selected_frameworks.set(selected_frameworks)

            spawn_scan_worker(scan_task.id)

            # Record who created this scan and from where — supports incident investigation
            client_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', 'unknown'))
            security_logger.info(
                'Scan %s created by user %s from %s',
                scan_task.id, request.user.id, client_ip,
            )

            messages.success(request, f'Scan "{scan_task.name}" started with {len(selected_frameworks)} compliance framework(s).')
            return redirect('scanner:scan-detail', pk=scan_task.pk)

        return render(request, 'scanner/scan_create.html', self._build_context(form))


# POST-only endpoint to request a graceful halt of a running scan.
# The worker process polls ScanTask.status every SCAN_POLL_INTERVAL seconds and
# calls client.stop_task() on GVM when it sees 'stopped' here.
class ScanStopView(LoginRequiredMixin, View):

    def post(self, request, pk):
        scan_task = get_object_or_404(_scan_queryset_for_user(request.user), pk=pk)
        if scan_task.status == 'running':
            scan_task.mark_stopped()
            messages.info(request, f'Scan "{scan_task.name}" stop requested.')
            # Record who stopped this scan — supports audit and incident response
            client_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', 'unknown'))
            security_logger.info(
                'Scan %s stopped by user %s from %s',
                pk, request.user.id, client_ip,
            )
        return redirect('scanner:scan-detail', pk=pk)


class ScanStatusView(LoginRequiredMixin, View):

    def get(self, request, pk):
        scan_task = get_object_or_404(_scan_queryset_for_user(request.user), pk=pk)
        recovered = ensure_scan_worker(scan_task)
        scan_task.refresh_from_db()

        return JsonResponse({
            'status': scan_task.status,
            'progress': scan_task.progress or 0,
            'progress_label': get_scan_progress_label(scan_task),
            'error_message': scan_task.error_message,
            'reports_count': scan_task.reports.count(),
            'recovered': recovered,
        })

from django import forms
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.views import View
from django.views.generic import ListView, DetailView

from .models import ScanTask, ApprovedTargetRange
from apps.compliance.models import Framework


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
    framework = forms.ModelChoiceField(
        queryset=Framework.objects.filter(is_active=True),
        widget=forms.Select(attrs={'class': 'form-input'}),
    )
    scan_config = forms.ChoiceField(
        choices=[
            ('full_and_fast', 'Full and Fast (Recommended)'),
            ('full_and_fast_ultimate', 'Full and Fast Ultimate'),
            ('full_and_deep', 'Full and Very Deep'),
            ('full_and_deep_ultimate', 'Full and Very Deep Ultimate'),
        ],
        initial='full_and_fast',
        widget=forms.Select(attrs={'class': 'form-input'}),
    )


class ScanListView(LoginRequiredMixin, ListView):
    model = ScanTask
    template_name = 'scanner/scan_list.html'
    context_object_name = 'scans'
    ordering = ['-created_at']

    def get_queryset(self):
        return ScanTask.objects.select_related('created_by', 'framework').order_by('-created_at')


class ScanDetailView(LoginRequiredMixin, DetailView):
    model = ScanTask
    template_name = 'scanner/scan_detail.html'
    context_object_name = 'scan'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        scan = self.get_object()
        # Include findings if scan is analyzed
        if scan.status in ['analyzed', 'completed']:
            from apps.interceptor.models import TechnicalFinding
            context['findings'] = TechnicalFinding.objects.filter(
                scan_task=scan,
            ).order_by('-cvss_score')
        return context


class ScanCreateView(LoginRequiredMixin, View):
    def get(self, request):
        form = ScanCreateForm()
        return render(request, 'scanner/scan_create.html', {'form': form})

    def post(self, request):
        form = ScanCreateForm(request.POST)
        if form.is_valid():
            target = form.cleaned_data['target']

            # Validate target against approved ranges
            if not ApprovedTargetRange.is_target_approved(target):
                messages.error(request, f'Target "{target}" is not in any approved scanning range. Contact an admin.')
                return render(request, 'scanner/scan_create.html', {'form': form})

            scan_task = ScanTask.objects.create(
                name=form.cleaned_data['name'],
                target=target,
                framework=form.cleaned_data['framework'],
                scan_config=form.cleaned_data['scan_config'],
                created_by=request.user,
            )

            # Run scan in a background thread so the request doesn't block
            import threading
            from apps.scanner.tasks import run_scan
            thread = threading.Thread(
                target=run_scan.apply,
                kwargs={'args': [scan_task.id]},
                daemon=True,
            )
            thread.start()

            messages.success(request, f'Scan "{scan_task.name}" started.')
            return redirect('scanner:scan-detail', pk=scan_task.pk)

        return render(request, 'scanner/scan_create.html', {'form': form})


class ScanStopView(LoginRequiredMixin, View):
    def post(self, request, pk):
        scan_task = get_object_or_404(ScanTask, pk=pk)
        if scan_task.status == 'running':
            scan_task.mark_stopped()
            messages.info(request, f'Scan "{scan_task.name}" stop requested.')
        return redirect('scanner:scan-detail', pk=pk)

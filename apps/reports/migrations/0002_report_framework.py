import django.db.models.deletion
from django.db import migrations, models


def copy_scan_framework_to_report_framework(apps, schema_editor):
    Report = apps.get_model('reports', 'Report')

    for report in Report.objects.select_related('scan_task').iterator():
        if report.framework_id is None:
            report.framework_id = report.scan_task.framework_id
            report.save(update_fields=['framework'])


def reverse_copy_scan_framework_to_report_framework(apps, schema_editor):
    Report = apps.get_model('reports', 'Report')
    Report.objects.update(framework_id=None)


class Migration(migrations.Migration):

    dependencies = [
        ('reports', '0001_initial'),
        ('compliance', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='report',
            name='framework',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='reports', to='compliance.framework'),
        ),
        migrations.RunPython(copy_scan_framework_to_report_framework, reverse_copy_scan_framework_to_report_framework),
    ]
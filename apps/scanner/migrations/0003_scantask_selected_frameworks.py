from django.db import migrations, models


def copy_primary_framework_to_selected_frameworks(apps, schema_editor):
    ScanTask = apps.get_model('scanner', 'ScanTask')

    for scan in ScanTask.objects.exclude(framework_id__isnull=True).iterator():
        scan.selected_frameworks.add(scan.framework_id)


def reverse_copy_primary_framework_to_selected_frameworks(apps, schema_editor):
    ScanTask = apps.get_model('scanner', 'ScanTask')

    for scan in ScanTask.objects.iterator():
        scan.selected_frameworks.clear()


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0002_alter_scantask_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='scantask',
            name='selected_frameworks',
            field=models.ManyToManyField(blank=True, related_name='selected_scan_tasks', to='compliance.framework'),
        ),
        migrations.RunPython(copy_primary_framework_to_selected_frameworks, reverse_copy_primary_framework_to_selected_frameworks),
    ]
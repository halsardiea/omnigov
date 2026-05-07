from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('interceptor', '0003_alter_technicalfinding_severity'),
    ]

    operations = [
        migrations.CreateModel(
            name='FindingAnalysis',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('matched_controls', models.JSONField(default=list, help_text='Ordered list of matched framework controls with correlation metadata.')),
                ('executive_summary', models.TextField(blank=True)),
                ('technical_remediation', models.TextField(blank=True)),
                ('analysis_method', models.CharField(choices=[('heuristic', 'Heuristic'), ('ai_hybrid', 'AI Hybrid')], default='heuristic', max_length=20)),
                ('confidence_score', models.FloatField(blank=True, help_text='Correlation confidence between 0.0 and 1.0', null=True)),
                ('raw_provider_response', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('technical_finding', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='analysis', to='interceptor.technicalfinding')),
            ],
            options={
                'verbose_name': 'Finding Analysis',
                'verbose_name_plural': 'Finding Analyses',
                'db_table': 'finding_analyses',
                'ordering': ['technical_finding_id'],
            },
        ),
    ]
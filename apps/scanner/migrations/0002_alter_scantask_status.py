from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scantask',
            name='status',
            field=models.CharField(
                choices=[
                    ('pending', 'Pending'),
                    ('running', 'Running'),
                    ('completed', 'Scan Completed'),
                    ('analyzing', 'Correlating Findings'),
                    ('analyzed', 'Correlation Complete'),
                    ('failed', 'Failed'),
                    ('stopped', 'Stopped'),
                ],
                default='pending',
                max_length=20,
            ),
        ),
    ]
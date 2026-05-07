import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0004_remove_approvedtargetrange'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ApprovedTargetRange',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cidr', models.CharField(help_text='CIDR notation, e.g. 192.168.1.0/24 or 10.0.0.0/8', max_length=43)),
                ('description', models.TextField(blank=True, help_text='Purpose of this target range (e.g. "Lab network")')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='approved_targets',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'verbose_name': 'Approved Target Range',
                'verbose_name_plural': 'Approved Target Ranges',
                'db_table': 'approved_target_ranges',
            },
        ),
    ]

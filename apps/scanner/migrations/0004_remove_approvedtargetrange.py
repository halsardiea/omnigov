from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0003_scantask_selected_frameworks'),
    ]

    operations = [
        migrations.DeleteModel(
            name='ApprovedTargetRange',
        ),
    ]

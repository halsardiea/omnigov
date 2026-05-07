from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_alter_user_managers'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='role',
        ),
        migrations.RemoveField(
            model_name='user',
            name='is_email_verified',
        ),
        migrations.RemoveField(
            model_name='user',
            name='otp_code',
        ),
        migrations.RemoveField(
            model_name='user',
            name='otp_created_at',
        ),
    ]

# Generated by Django 5.0.4 on 2024-04-25 12:38

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0011_alter_match_location'),
    ]

    operations = [
        migrations.AddField(
            model_name='match',
            name='schedule',
            field=models.DateTimeField(default=django.utils.timezone.now),
            preserve_default=False,
        ),
    ]
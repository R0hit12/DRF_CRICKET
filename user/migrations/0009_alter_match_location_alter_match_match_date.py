# Generated by Django 5.0.4 on 2024-04-25 10:49

import django.utils.timezone
import location_field.models.plain
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0008_match_location_alter_match_match_date_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='match',
            name='location',
            field=location_field.models.plain.PlainLocationField(default=django.utils.timezone.now, max_length=63),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='match',
            name='match_date',
            field=models.DateField(),
        ),
    ]

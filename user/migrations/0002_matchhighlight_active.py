# Generated by Django 5.0.4 on 2024-04-26 06:24

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('user', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='matchhighlight',
            name='active',
            field=models.BooleanField(default=False),
        ),
    ]
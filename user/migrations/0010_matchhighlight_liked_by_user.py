# Generated by Django 5.0.4 on 2024-04-29 10:38

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0009_alter_matchhighlight_views'),
    ]

    operations = [
        migrations.AddField(
            model_name='matchhighlight',
            name='liked_by_user',
            field=models.ManyToManyField(blank=True, related_name='liked_highlights', to=settings.AUTH_USER_MODEL),
        ),
    ]
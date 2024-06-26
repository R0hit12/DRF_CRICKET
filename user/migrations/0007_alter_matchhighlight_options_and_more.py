# Generated by Django 5.0.4 on 2024-04-25 07:27

import user.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0006_match_team_matchhighlight_player_match_team1_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='matchhighlight',
            options={'verbose_name': 'Match Highlight', 'verbose_name_plural': 'Match Highlights'},
        ),
        migrations.AddField(
            model_name='matchhighlight',
            name='highlight',
            field=models.FileField(null=True, upload_to=user.models.highlight_file_path),
        ),
        migrations.AlterField(
            model_name='matchhighlight',
            name='highlight_url',
            field=models.URLField(blank=True),
        ),
    ]

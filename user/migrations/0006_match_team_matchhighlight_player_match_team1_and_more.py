# Generated by Django 5.0.4 on 2024-04-25 07:02

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0005_user_otp_alter_blog_description'),
    ]

    operations = [
        migrations.CreateModel(
            name='Match',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('match_date', models.DateTimeField()),
            ],
        ),
        migrations.CreateModel(
            name='Team',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('team_name', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='MatchHighlight',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('highlight_url', models.URLField()),
                ('upload_date', models.DateTimeField(auto_now_add=True)),
                ('match', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='highlights', to='user.match')),
                ('uploaded_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Player',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('player_name', models.CharField(max_length=20)),
                ('team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='players', to='user.team')),
            ],
        ),
        migrations.AddField(
            model_name='match',
            name='team1',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='team_1', to='user.team'),
        ),
        migrations.AddField(
            model_name='match',
            name='team2',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='team_2', to='user.team'),
        ),
    ]

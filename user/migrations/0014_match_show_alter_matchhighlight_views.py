# Generated by Django 5.0.4 on 2024-05-01 04:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0013_remove_matchhighlight_highlight_url_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='match',
            name='show',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='matchhighlight',
            name='views',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]
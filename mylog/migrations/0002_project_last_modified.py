# Generated by Django 4.1.4 on 2023-02-21 07:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("mylog", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="project",
            name="last_modified",
            field=models.DateTimeField(auto_now=True, null=True),
        ),
    ]
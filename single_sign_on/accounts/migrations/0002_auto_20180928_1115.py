# Generated by Django 2.1.1 on 2018-09-28 11:15

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('sessions', '0001_initial'),
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='accessinfo',
            name='user',
        ),
        migrations.AddField(
            model_name='accessinfo',
            name='session',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='sessions.Session'),
            preserve_default=False,
        ),
    ]

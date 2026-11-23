from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vulns', '0005_scale_rebuild'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='stagedrow',
            name='file',
        ),
        migrations.RemoveField(
            model_name='stagedrow',
            name='run',
        ),
        migrations.RemoveField(
            model_name='importfile',
            name='errors',
        ),
        migrations.DeleteModel(
            name='StagedRow',
        ),
        migrations.RunSQL("ALTER TABLE vulns_stagedalert SET UNLOGGED", migrations.RunSQL.noop),
        migrations.RunSQL("ALTER TABLE vulns_plannedremediation SET UNLOGGED", migrations.RunSQL.noop),
    ]

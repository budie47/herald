#!/bin/sh
set -e

python - <<'PY'
import os, sys, time
import psycopg
for attempt in range(60):
    try:
        psycopg.connect(
            host=os.environ["POSTGRES_HOST"], port=os.environ.get("POSTGRES_PORT", "5432"),
            dbname=os.environ["POSTGRES_DB"], user=os.environ["POSTGRES_USER"],
            password=os.environ["POSTGRES_PASSWORD"], connect_timeout=3,
        ).close()
        break
    except psycopg.OperationalError:
        print("Waiting for database...", flush=True)
        time.sleep(2)
else:
    sys.exit("Database is not reachable")
PY

python manage.py migrate --noinput
python manage.py bootstrap

exec "$@"

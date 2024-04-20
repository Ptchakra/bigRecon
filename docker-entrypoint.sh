#!/bin/sh

if [ "$DATABASE" = "postgres" ]
then
    echo "Waiting for postgres..."

    while ! nc -z db 5432; do
      sleep 0.1
    done

    echo "PostgreSQL started"
fi
python3 manage.py makemigrations
echo "---------------------------------------a"
python3 manage.py migrate
echo "---------------------------------------------"
python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py collectstatic --no-input --clear
# Load default engine types
python3 manage.py loaddata fixtures/default_scan_engines.yaml --app scanEngine.EngineType
python3 manage.py runserver 0.0.0.0:8000

exec "$@"

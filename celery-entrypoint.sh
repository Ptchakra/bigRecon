#!/bin/bash

python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py collectstatic --no-input --clear

celery -A bigRecon worker -l INFO -Q doScan,doJaelesScan,subdomain_file_task,run_xray,



from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse, HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django_celery_beat.models import PeriodicTask, IntervalSchedule, ClockedSchedule
from notification.models import NotificationHooks
from targetApp.models import Domain
from scanEngine.models import EngineType, Configuration
from django.utils import timezone
from django.conf import settings
from datetime import datetime
from bigRecon.tasks import doScan
from bigRecon.celery import app
import os
from django.core.files.storage import FileSystemStorage
import requests
from pathlib import Path
import mimetypes
import os.path
from os import path
from dev.models import Dev

from bigRecon.tasks import subdomain_file_task, run_xray
from bigRecon.celery import app


def dev(request):
    print(request)
    context = {"path": "/dev/download/scan_results/app_tools_run-xray.html"}
    return render(request, "dev/temp.html", context)


def download_file(request, filepath):
    # fill these variables with real values
    print("-----------------------------------------------")
    print(filepath)
    filepath = filepath.split("_")
    filepath = "/".join(filepath)
    filepath = "/" + filepath
    fl = open(filepath, "r")
    filename = "output.html"
    mime_type, _ = mimetypes.guess_type(filepath)
    response = HttpResponse(fl, content_type=mime_type)
    response["Content-Disposition"] = "attachment; filename=%s" % filename
    return response


def upload_subdomain_file(request):
    print()
    print("upload_subdomain_file")
    if request.method == "POST":
        if "txtFile" in request.FILES:
            txt_file = request.FILES["txtFile"]
            now = datetime.now()
            newName = now.strftime("%d%m%Y%H%M%S")
            if not path.exists("/app/tools/scan_results/dev_results/"):
                os.mkdir("/app/tools/scan_results/dev_results/")
            print("/app/tools/scan_results/dev_results/")
            os.mkdir("/app/tools/scan_results/dev_results/" + newName)
            #            txt_file.save('/app/dev/results'+newName+'/'+txt_file.name)
            fs = FileSystemStorage()
            filename = fs.save(
                "/app/tools/scan_results/dev_results/" + newName + "/" + txt_file.name,
                txt_file,
            )

            dir_path = "/app/tools/scan_results/dev_results/" + newName
            output = f"/app/tools/scan_results/dev_results/{newName}/output.html"
            Dev.objects.create(
                File_name=filename, Status="running", Path=dir_path, Date=timezone.now()
            )
            print("file name ", filename)
            # run_xray.apply_async(args=([dir_path]),queue='run_xray',routing_key='run_xray')
            celery_task = subdomain_file_task.apply_async(
                args=(txt_file.name, dir_path),
                queue="subdomain_file_task",
                routing_key="subdomain_file_task",
            )
            return HttpResponseRedirect(reverse("scan_history"))
    else:
        return render(request, "dev/temp.html", context)

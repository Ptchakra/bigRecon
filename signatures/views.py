from django.shortcuts import get_object_or_404, render
from django.conf import settings
from django.http import JsonResponse
from yaml import loader
from .models import Signatures
from .forms import DoScanForm, EditSignatureForm
from bigRecon.tasks import doJaelesScan
from django.utils import timezone
from django import http
from django.shortcuts import render
from django.urls import reverse
import yaml, json, io, os, tempfile


def add(request):
    context = {"sign_data_active": "true"}
    if request.method == "POST":
        folder_location = settings.SIGN_DIR
        if request.POST.get("data", None):
            data = request.POST["data"]
            data = json.loads(data)
            sign_id = data.get("id", None)
            if not sign_id:
                return JsonResponse(
                    {"success": False, "error": "Please insert signature id!"}
                )
            file_name = folder_location + sign_id + ".yaml"
            if not os.path.exists(folder_location):
                os.makedirs(folder_location)
            with io.open(file_name, "w") as outfile:
                yaml.dump(data, outfile, sort_keys=False, width=1000)
            with io.open(file_name, "r") as signfile:
                gen_text = signfile.read()
                if gen_text:
                    save_sign(data, file_name)
            return JsonResponse({"success": True, "gen_sign": gen_text})
        elif request.POST.get("raw", None):
            content = request.POST["raw"]
            with tempfile.TemporaryFile(mode="r+") as f:
                f.write(content)
                f.seek(0)
                try:
                    data = yaml.load(f, Loader=yaml.FullLoader)
                    print(data)
                    sign_id = data.get("id", None)
                    if not sign_id:
                        return JsonResponse(
                            {"success": False, "error": "Please insert signature id!"}
                        )
                    file_name = folder_location + sign_id + ".yaml"
                    with io.open(file_name, "w") as outfile:
                        outfile.write(content)
                        save_sign(data, file_name)
                        return JsonResponse(
                            {"success": True, "error": "Signature created!"}
                        )

                except Exception as e:
                    return JsonResponse(
                        {"success": False, "error": "Can't read signature!"}
                    )
    return render(request, "genSign/index.html", context)


def save_sign(data, path):
    try:
        obj = Signatures.objects.get(sign_id=data["id"])
    except Exception as e:
        obj = None
    info_obj = data.get("info", None)
    severity_dict = {
        "Info": Signatures.INFO,
        "Low": Signatures.LOW,
        "Medium": Signatures.MEDIUM,
        "High": Signatures.HIGH,
        "Critical": Signatures.CRITICAL,
    }
    severity = info_obj.get("risk", None)
    if severity:
        severity = severity_dict[severity]
    else:
        severity = 0
    type_dict = {
        "list": Signatures.LIST,
        "fuzz": Signatures.FUZZ,
        "routine": Signatures.ROUTINE,
    }
    type = data.get("type", None)
    if type:
        type = type_dict[type]
    else:
        type = 0
    references = data.get("references", None)
    desc = ""
    if references:
        desc = ",".join(references)
    if not obj:
        Signatures.objects.create(
            sign_id=data.get("id", None),
            sign_name=info_obj.get("name", None),
            type_sign=type,
            severity=severity,
            os=info_obj.get("os", None),
            target_for=info_obj.get("tech", None),
            description=desc,
            last_modified=timezone.now(),
            sign_path=path,
        )
    else:
        obj.sign_name = info_obj.get("name", None)
        obj.severity = severity
        obj.type_sign = type
        obj.os = info_obj.get("os", None)
        obj.target_for = info_obj.get("tech", None)
        obj.description = desc
        obj.last_modified = timezone.now()
        obj.sign_path = path
        obj.save()

    all = Signatures.objects.all()
    print(all)


def list_sign(request):
    context = {"list_sign_li": "active", "sign_data_active": "true"}
    return render(request, "listSign/list.html", context)


def scan(request):
    form = DoScanForm(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            celery_task = doJaelesScan.apply_async(
                args=(form.cleaned_data["url"], form.cleaned_data["signature_file"])
            )
            return http.HttpResponseRedirect(reverse("list_sign"))
    context = {"scan_vuln_li": "active", "sign_data_active": "true", "form": form}
    return render(request, "scanVuln/scan.html", context)


def edit(request, sign_id):
    obj = get_object_or_404(Signatures, sign_id=sign_id)
    folder_location = settings.SIGN_DIR
    file_name = obj.sign_path
    with io.open(file_name, "r") as sign:
        content = sign.read()
        form = EditSignatureForm(initial={"content": content})
    if request.method == "POST":
        content = request.POST["content"]
        with tempfile.TemporaryFile(mode="r+") as f:
            f.write(content)
            f.seek(0)
            try:
                data = yaml.load(f, Loader=yaml.FullLoader)
                sign_id = data.get("id", None)
                if sign_id != obj.sign_id:
                    return JsonResponse(
                        {
                            "success": False,
                            "error": "You can't change the signature id!",
                        }
                    )
                with io.open(obj.sign_path, "w") as outfile:
                    outfile.write(content)
                    save_sign(data, file_name)
                    return http.HttpResponseRedirect(reverse("list_sign"))
            except Exception as e:
                return JsonResponse(
                    {"success": False, "error": "Can't read signature!"}
                )
    context = {
        "list_sign_li": "active",
        "sign_data_active": "true",
        "form": form,
        "sign_name": obj.sign_name,
    }
    return render(request, "editSign/edit.html", context)


def delete(request, sign_id):
    obj = get_object_or_404(Signatures, sign_id=sign_id)
    folder_location = settings.SIGN_DIR
    file_name = folder_location + obj.sign_id + ".yaml"
    if request.method == "DELETE":
        try:
            os.remove(file_name)
            obj.delete()
            responseData = {"success": True}
        except Exception as e:
            responseData = {"success": False}
    else:
        responseData = {"success": False}
    return http.JsonResponse(responseData)


def delete_all(request):
    if request.method == "DELETE":
        try:
            Signatures.objects.all().delete()
            responseData = {"success": True}
        except Exception as e:
            responseData = {"success": False}
    else:
        responseData = {"success": False}
    return http.JsonResponse(responseData)


def reload_all(request):
    if request.method == "POST":
        total_sign = 0
        sign_dir = settings.SIGN_DIR
        directory = os.fsencode(sign_dir)
        for file in os.listdir(directory):
            filename = os.fsdecode(file)
            if filename.endswith(".yaml"):
                full_name = os.path.join(sign_dir, filename)
                with io.open(full_name, "r") as f:
                    try:
                        data = yaml.load(f, Loader=yaml.FullLoader)
                        print(data)
                        save_sign(data, full_name)
                        total_sign += 1
                    except Exception as e:
                        continue
        return http.JsonResponse({"numSignLoaded": total_sign})

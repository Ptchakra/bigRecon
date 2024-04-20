from datetime import datetime
import os
from django.db.models.fields import IPAddressField
import yaml
import json

# from startScan.views import scan_history
import validators
import requests
import time
import re
import ipaddress

from celery import shared_task
from bigRecon.celery import app
from startScan.models import (
    ScanHistory,
    ScannedHost,
    ScanActivity,
    WayBackEndPoint,
    VulnerabilityScan,
)
from targetApp.models import Domain
from notification.models import NotificationHooks
from scanEngine.models import EngineType, Configuration
from signatures.models import Signatures
from django.conf import settings
from django.utils import timezone, dateformat
from django.shortcuts import get_object_or_404
import telegram

base_message = """
WARNING!!! BigRecon found a vulnerability!
URL: {url}
Name: {id}
Severity: {severity}
Please check scan result page for more information!
"""
"""
tool check dir scan result
"""


def get_length(line):
    return int(line.split("    ")[1])


def get_cloudflare_ips():
    ipv4 = str(requests.get(url="https://www.cloudflare.com/ips-v4").content)[2:-1]
    ipv4 = str(ipv4).split("\\n")
    ipv6 = str(requests.get(url="https://www.cloudflare.com/ips-v6").content)[2:-1]
    ipv6 = str(ipv6).split("\\n")
    return ipv4[0 : len(ipv4) - 1], ipv6[0 : len(ipv6) - 1]


def check_cloudflare_ip(ipv4, ipv6, ip):
    if ":" not in ip:
        for ip_cf in ipv4:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_cf):
                return True
        return False
    else:
        for ip_cf in ipv6:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_cf):
                return True
        return False


def check_dirs_result(dirs_results, default_size):
    lines = dirs_results.split("\n")
    true_result = []
    for line in lines:
        if len(line.split("    ")) != 3:
            continue
        if (
            int(line.split("    ")[1]) != default_size
            and int(line.split("    ")[1]) != 0
            and int(line.split("    ")[1]) < 100
        ):
            true_result.append(line)
    return sorted(true_result, key=get_length)


"""
task for background scan
"""


@app.task(name="doJaelesScan")
def doJaelesScan(url, signature_id):
    sign = Signatures.objects.get(sign_id=signature_id)
    print(sign)
    current_scan_dir = (
        url.replace("/", "_").replace(":", "_")
        + "_"
        + str(datetime.strftime(timezone.now(), "%Y_%m_%d_%H_%M_%S"))
    )
    result_dir = settings.TOOL_LOCATION + "scan_results/" + current_scan_dir
    os.mkdir(result_dir)
    run_scan_cmd = "jaeles scan -s {sign_file} -u {url} -o {out} --debug".format(
        sign_file=sign.sign_path, url=url, out=result_dir
    )
    print("Start Scan Jaeles")
    print(run_scan_cmd)
    os.system(run_scan_cmd)
    print("Finished Scan")
    vuln_summary = result_dir + "/vuln-summary.txt"
    if os.path.isfile(vuln_summary):
        read_and_send_notification(vuln_summary)
    # s = time.time()
    # target_tech = signature_id.split(',')
    # current_scan_dir = url.replace('/', '_').replace(':', '_') + '_' + \
    #         str(datetime.strftime(timezone.now(), '%Y_%m_%d_%H_%M_%S'))
    # result_dir = settings.TOOL_LOCATION + 'scan_results/jaeles/' + current_scan_dir
    # command_to_run = 'jaeles scan -u ' + url \
    #                 + ' -o ' + result_dir
    # signature_part = ''
    # common_sign = Signatures.objects.filter(target_for__contains='common')
    # signature_paths = set(x.sign_path for x in common_sign)
    # for tech in target_tech:
    #     tech_sign = Signatures.objects.filter(target_for__contains=tech)
    #     tech_sign_paths = set(x.sign_path for x in tech_sign)
    #     signature_paths = signature_paths.union(tech_sign_paths)
    # for sign_path in signature_paths:
    #     signature_part += ' -s ' + sign_path
    # if signature_part:
    #     command_to_run += signature_part
    #     e = time.time()
    #     print('Initial execute time: ', e-s)
    #     s=time.time()
    #     os.system(command_to_run)
    #     e=time.time()
    #     print('Command execute time: ', e-s)
    #     s=time.time()
    #     vuln_summary = result_dir + '/vuln-summary.txt'
    #     if os.path.isfile(vuln_summary):
    #         read_and_send_notification(vuln_summary)
    #     else:
    #         print('Something happened')
    #     e=time.time()
    #     print('Read and send notification execute time: ', e-s)
    #     print(f'Scanned with {len(signature_paths)} signatures!')


def subdomain_scan(yaml_configuration, domain, current_scan_dir):
    try:
        if "all" in yaml_configuration["subdomain_discovery"]["uses_tool"]:
            tools = "amass-active amass-passive assetfinder sublist3r subfinder"
        else:
            tools = " ".join(
                str(tool)
                for tool in yaml_configuration["subdomain_discovery"]["uses_tool"]
            )

        # check for thread, by default should be 10
        if yaml_configuration["subdomain_discovery"]["thread"] > 0:
            threads = yaml_configuration["subdomain_discovery"]["thread"]
        else:
            threads = 10

        if "amass-active" in tools:
            if (
                "wordlist" not in yaml_configuration["subdomain_discovery"]
                or not yaml_configuration["subdomain_discovery"]["wordlist"]
                or "default" in yaml_configuration["subdomain_discovery"]["wordlist"]
            ):
                wordlist_location = (
                    settings.TOOL_LOCATION
                    + "wordlist/default_wordlist/deepmagic.com-prefixes-top50000.txt"
                )
            else:
                wordlist_location = (
                    settings.TOOL_LOCATION
                    + "wordlist/"
                    + yaml_configuration["subdomain_discovery"]["wordlist"]
                    + ".txt"
                )
                if not os.path.exists(wordlist_location):
                    wordlist_location = (
                        settings.TOOL_LOCATION
                        + "wordlist/default_wordlist/deepmagic.com-prefixes-top50000.txt"
                    )
            # check if default amass config is to be used
            if (
                "amass_config" not in yaml_configuration["subdomain_discovery"]
                or not yaml_configuration["subdomain_discovery"]["amass_config"]
                or "default" in yaml_configuration["subdomain_discovery"]["wordlist"]
            ):
                amass_config = settings.AMASS_CONFIG
            else:
                """
                amass config setting exixts but we need to check if it
                exists in database
                """
                short_name = yaml_configuration["subdomain_discovery"]["amass_config"]
                config = get_object_or_404(Configuration, short_name=short_name)
                if config:
                    """
                    if config exists in db then write the config to
                    scan location, and send path to script location
                    """
                    with open(current_scan_dir + "/config.ini", "w") as config_file:
                        config_file.write(config.content)
                    amass_config = current_scan_dir + "/config.ini"
                else:
                    """
                    if config does not exist in db then
                    use default for failsafe
                    """
                    amass_config = settings.AMASS_CONFIG

            # all subdomain scan happens here
            print("scan subdomain command")
            print(
                settings.TOOL_LOCATION
                + "get_subdomain.sh %s %s %s %s %s %s"
                % (
                    threads,
                    domain.domain_name,
                    current_scan_dir,
                    wordlist_location,
                    amass_config,
                    tools,
                )
            )
            os.system(
                settings.TOOL_LOCATION
                + "get_subdomain.sh %s %s %s %s %s %s"
                % (
                    threads,
                    domain.domain_name,
                    current_scan_dir,
                    wordlist_location,
                    amass_config,
                    tools,
                )
            )
        else:
            os.system(
                settings.TOOL_LOCATION
                + "get_subdomain.sh %s %s %s %s"
                % (threads, domain.domain_name, current_scan_dir, tools)
            )
        return True
    except Exception as exception:
        print("╒" + "-" * 15 + "Start Scan subdomain Exception" + "-" * 15 + "╕")
        print(exception)
        print("╘" + "-" * 15 + "End Scan subdomain Exception" + "-" * 15 + "╛")
        return False


def run_httpx(target_result_dir):
    # run httpx
    httpx_results_file = target_result_dir + "/httpx.json"
    subdomain_file_location = target_result_dir + "/alive_subdomain.txt"

    httpx_command = "cat {} | httpx -cdn -json -o {}".format(
        subdomain_file_location, httpx_results_file
    )
    os.system(httpx_command)

    # http subdomains from httpx
    http_file_location = target_result_dir + "/http_subdomain.txt"
    http_alive_file = open(http_file_location, "w")

    # writing httpx results to alive
    httpx_json_result = open(httpx_results_file, "r")
    lines = httpx_json_result.readlines()
    for line in lines:
        json_st = json.loads(line.strip())
        try:
            http_alive_file.write(json_st["url"] + "\n")
        except Exception as e:
            print("╒" + "-" * 15 + "Start run httpx Exception" + "-" * 15 + "╕")
            print(e)
            print("╘" + "-" * 15 + "End run httpx Exception" + "-" * 15 + "╛")
            return False

    httpx_json_result.close()
    http_alive_file.close()
    return True


@app.task(name="doScan")
def doScan(domain_id, scan_history_id, scan_type, engine_type):
    # get current time
    current_scan_time = timezone.now()
    """
    scan_type = 0 -> immediate scan, need not create scan object
    scan_type = 1 -> scheduled scan
    """
    task = ScanHistory()
    domain = Domain.objects.get(pk=domain_id)
    if not domain:
        print("Domain not found")
        return {"status": False}
    if scan_type == 1:
        engine_object = EngineType.objects.get(pk=engine_type)
        task = ScanHistory()
        task.domain_name = domain
        task.scan_status = -1
        task.scan_type = engine_object
        task.celery_id = doScan.request.id
        task.last_scan_date = current_scan_time
        task.save()
    elif scan_type == 0:
        task = ScanHistory.objects.get(pk=scan_history_id)

    # save the last scan date for domain model
    domain.last_scan_date = current_scan_time
    domain.save()

    # once the celery task starts, change the task status to Started
    task.scan_status = 1
    task.last_scan_date = current_scan_time
    task.save()

    activity_id = create_scan_activity(task, "Scanning Started", 2)
    tools_dir = settings.TOOL_LOCATION
    results_dir = settings.TOOL_LOCATION + "scan_results/"
    target_result_dir = (
        results_dir
        + domain.domain_name
        + "_"
        + str(datetime.strftime(timezone.now(), "%Y_%m_%d_%H_%M_%S"))
    )
    os.mkdir(target_result_dir)

    # All Files can be created here

    """
    For subdomain scan
    """
    subdomain_scan_results_file = (
        target_result_dir + "/sorted_subdomain_collection.txt"
    )  # all subdomain
    alive_subdomain_file_location = (
        target_result_dir + "/alive_subdomain.txt"
    )  # alive subdomain
    massdns_results_file = target_result_dir + "/massdns.out"  # massdns result file

    httpx_results_file = target_result_dir + "/httpx.json"  # httpx result file
    port_results_file = target_result_dir + "/ports.txt"  # port scan result
    output_aquatone_path = target_result_dir + "/aquascreenshots"
    alive_ip_file = target_result_dir + "/alive_ip.txt"
    jaeles_result_dir = target_result_dir + "/jaeles-vuln"

    url_results_file = target_result_dir + "/final_httpx_urls.json"
    try:
        yaml_configuration = yaml.load(
            task.scan_type.yaml_configuration, Loader=yaml.FullLoader
        )
        excluded_subdomains = ""

        # Excluded subdomains
        if "excluded_subdomains" in yaml_configuration:
            excluded_subdomains = yaml_configuration["excluded_subdomains"]
        if task.scan_type.subdomain_discovery:

            is_get_subdomain = subdomain_scan(
                yaml_configuration, domain, target_result_dir
            )
            if not is_get_subdomain:
                raise Exception("Subdomain scan failed")
        else:
            only_subdomain_file = open(
                target_result_dir + "/sorted_subdomain_collection.txt",
                "w",
            )
            only_subdomain_file.write(domain.domain_name + "\n")
            only_subdomain_file.close()

        """
        Dns resolution for check alive subdomains
        """
        masscan_command = settings.TOOL_LOCATION + "do_masscan.sh"
        masscan_command = (
            masscan_command
            + " "
            + subdomain_scan_results_file
            + " "
            + target_result_dir
        )
        print(masscan_command)
        os.system(masscan_command)

        """
        Save the alive subdomains to db
        """
        with open(massdns_results_file) as subdomain_list:
            dns_resolve_results = subdomain_list.read().splitlines()

        ipv4_cf, ipv6_cf = get_cloudflare_ips()
        for dns_record in dns_resolve_results:
            subdomain = dns_record.split(". ")[0]
            dns_type = dns_record.split(" ")[1]
            ip_address = dns_record.split(" ")[2]

            if subdomain in excluded_subdomains:
                continue
            scanned = ScannedHost()
            scanned.subdomain = subdomain
            scanned.scan_history = task
            scanned.target_domain = domain
            if dns_type != "CNAME":
                if check_cloudflare_ip(ipv4_cf, ipv6_cf, ip_address):
                    scanned.technology_stack = "Cloudflare"
                else:
                    scanned.ip_address = ip_address
            else:
                scanned.cname = ip_address
                scanned.ip_address = "cname " + ip_address
            scanned.save()

        # """
        # Run httpx to get alive subdomains
        # """
        is_run_httpx = run_httpx(target_result_dir)
        if not is_run_httpx:
            raise Exception("httpx scan failed")

        """
        Save the subdomain results to db
        """
        print("save to db")
        httpx_json_result = open(httpx_results_file, "r")
        lines = httpx_json_result.readlines()
        for line in lines:
            print(line)
            json_st = json.loads(line.strip())
            print(json_st["input"])
            scanned = ScannedHost.objects.get(
                scan_history__id=task.id,
                subdomain=json_st["input"],
            )
            print(scanned)
            scanned.http_url = json_st["url"]
            scanned.subdomain = json_st["url"].split("//")[-1].strip()
            scanned.discovered_date = timezone.now()
            scanned.scan_history = task
            scanned.http_status = json_st.get("status_code")
            scanned.page_title = "" if "title" not in json_st else json_st["title"]
            scanned.content_length = (
                0 if "content-length" not in json_st else json_st["content-length"]
            )
            # if "host" in json_st:
            #     print(f"host {json_st['url']}")
            #     print(json_st["host"])
            #     scanned.ip_address = json_st["host"]
            # else:
            #     print("json_st['a'] fail")
            if "cdn" in json_st:
                scanned.is_ip_cdn = json_st["cdn"]
            if "cnames" in json_st:
                cname_list = ",".join(json_st["cnames"])
                if scanned.cname:
                    scanned.cname = scanned.cname + "," + cname_list
                scanned.cname = cname_list

            scanned.save()
        httpx_json_result.close()

        """
        HTTP Crawlwer and screenshot will run by default
        """

        # once port scan is complete then run httpx, TODO this has to run in
        # background thread later

        activity_id = create_scan_activity(task, "Subdomain Scanning", 1)

        """
        Port scan
        """

        if task.scan_type.port_scan:
            update_last_activity(activity_id, 2)
            activity_id = create_scan_activity(task, "Port Scanning", 1)
            all_ports = yaml_configuration["port_scan"]["ports"]
            print(all_ports)
            if "full" in all_ports:
                nmap_command = f"nmap -sV -p - -Pn -sT --open --max-rate 5000 -iL {alive_ip_file} -oN {port_results_file}"
            elif "top-100" in all_ports:
                nmap_command = f"nmap -sV --top-ports 100 -Pn -sT --open --max-rate 5000 -iL {alive_ip_file} -oN {port_results_file}"
            elif "top-1000" in all_ports:
                nmap_command = f"nmap -sV --top-ports 1000 -Pn -sT --open --max-rate 5000 -iL {alive_ip_file} -oN {port_results_file}"
            else:
                nmap_command = f"nmap -sV -p - -Pn -sT --open --max-rate 5000 -iL {alive_ip_file} -oN {port_results_file}"
            if yaml_configuration["port_scan"]["exclude_ports"]:
                exclude_ports = ",".join(
                    str(port)
                    for port in yaml_configuration["port_scan"]["exclude_ports"]
                )
                nmap_command = nmap_command + f" --exclude-ports {exclude_ports}"

            os.system(nmap_command)

            with open(port_results_file) as port_list:
                port_results = port_list.read().splitlines()
                scanned_host = None
                for line in port_results:
                    if "Nmap scan report for" in line:
                        ip_address = line.split(" ")[-1].split("(")[-1].split(")")[0]
                        scanned_host = ScannedHost.objects.filter(
                            scan_history__id=task.id, ip_address=ip_address
                        )
                    if "/tcp" in line or "/udp" in line:
                        port = line.split("/")[0].strip()
                        if len(line.split("open")[-1].strip().split(" ")) < 2:
                            tech_list_arr = [
                                line.split("open")[-1].strip().split(" ")[0],
                                " ".join(line.split("open")[-1].strip().split(" ")[1:]),
                            ]
                            tech_list = [x.split("?")[0] for x in tech_list_arr]
                            tech_list = ",".join(tech_list)
                        else:
                            tech_list = line.split("open")[-1].strip()
                        if not scanned_host:
                            continue
                        for host in scanned_host:
                            if host.open_ports:
                                host.open_ports = host.open_ports + "," + port
                            else:
                                host.open_ports = port
                            if host.technology_stack:
                                host.technology_stack = (
                                    host.technology_stack + "," + tech_list
                                )
                            else:
                                host.technology_stack = tech_list
                            host.save()

        # writing port results
        # if task.scan_type.port_scan:
        #     update_last_activity(activity_id, 2)
        #     activity_id = create_scan_activity(task, "Port Scanning", 1)
        #
        #     # after all subdomain has been discovered run naabu to discover the
        #     # ports
        #     port_results_file = target_result_dir + "/ports.json"
        #     # check the yaml_configuration and choose the ports to be scanned
        #
        #     all_ports = yaml_configuration["port_scan"]["ports"]
        #     print(all_ports)
        #     if "full" in all_ports:
        #         naabu_command = "cat {} | naabu -json -o {} -p {}".format(
        #             alive_ip_file, port_results_file, "-"
        #         )
        #     elif "top-100" in all_ports:
        #         naabu_command = "cat {} | naabu -json -o {} -top-ports 100".format(
        #             alive_ip_file, port_results_file
        #         )
        #     elif "top-1000" in all_ports:
        #         naabu_command = "cat {} | naabu -json -o {} -top-ports 1000".format(
        #             alive_ip_file, port_results_file
        #         )
        #     else:
        #         naabu_command = "cat {} | naabu -json -o {} -p {}".format(
        #             alive_ip_file, port_results_file, "-"
        #         )
        #     if yaml_configuration["port_scan"]["exclude_ports"]:
        #         exclude_ports = ",".join(
        #             str(port)
        #             for port in yaml_configuration["port_scan"]["exclude_ports"]
        #         )
        #         naabu_command = naabu_command + " -exclude-ports {}".format(
        #             exclude_ports
        #         )
        #
        #     if yaml_configuration["subdomain_discovery"]["thread"] > 0:
        #         naabu_command = naabu_command + " -c {}".format(
        #             yaml_configuration["subdomain_discovery"]["thread"]
        #         )
        #     else:
        #         naabu_command = naabu_command + " -c 10"
        #     os.system(naabu_command)
        """
        HTTP Crawlwer and screenshot will run by default
        """

        update_last_activity(activity_id, 2)
        activity_id = create_scan_activity(task, "HTTP Crawler", 1)
        try:
            port_json_result = open(port_results_file, "r")
            lines = port_json_result.readlines()
            for line in lines:
                try:
                    json_st = json.loads(line.strip())
                except Exception as exception:
                    print("-" * 30)
                    print(exception)
                    print("-" * 30)
                    continue
                print(json_st)
                sub_domains = ScannedHost.objects.filter(
                    scan_history=task, ip_address=json_st["ip"]
                )
                print(f"sub_d {sub_domains}")
                for sub_domain in sub_domains:
                    print(f"op {sub_domain.open_ports}")
                    if (
                        sub_domain.open_ports
                        and str(json_st["port"]) not in sub_domain.open_ports
                    ):
                        sub_domain.open_ports = (
                            sub_domain.open_ports + "," + str(json_st["port"])
                        )
                    else:
                        sub_domain.open_ports = str(json_st["port"])
                    sub_domain.save()
        except Exception as exception:
            print("-" * 30)
            print(exception)
            print("-" * 30)
            update_last_activity(activity_id, 0)

        update_last_activity(activity_id, 2)
        activity_id = create_scan_activity(task, "Visual Recon - Screenshot", 1)

        # after subdomain discovery run aquatone for visual identification

        scan_port = yaml_configuration["visual_identification"]["port"]
        # check if scan port is valid otherwise proceed with default xlarge
        # port
        if scan_port not in ["small", "medium", "large", "xlarge"]:
            scan_port = "xlarge"

        if yaml_configuration["visual_identification"]["thread"] > 0:
            threads = yaml_configuration["visual_identification"]["thread"]
        else:
            threads = 10

        # aquatone_command = 'cat {} | /app/tools/aquatone --threads {} ' + \
        #     '-screenshot-timeout 60000 -http-timeout 10000 -out {}'.format(
        #     alive_file_location, threads, output_aquatone_path)

        aquatone_command = f"cat {alive_subdomain_file_location} | {tools_dir}aquatone --threads {threads} -ports {scan_port} -screenshot-timeout 60000 -http-timeout 10000 -out {output_aquatone_path}"
        os.system(aquatone_command)
        os.system(f"chmod -R 607 {tools_dir}scan_results/*")
        aqua_json_path = output_aquatone_path + "/aquatone_session.json"
        print(aqua_json_path)
        try:
            with open(aqua_json_path, "r") as json_file:
                data = json.load(json_file)
            for host in data["pages"]:
                print(host)
                print(task.id)
                print(data["pages"][host]["hostname"])
                sub_domain = ScannedHost.objects.get(
                    scan_history__id=task.id,
                    subdomain=data["pages"][host]["hostname"],
                )
                print(sub_domain)
                sub_domain.screenshot_path = (
                    target_result_dir
                    + "/aquascreenshots/"
                    + data["pages"][host]["screenshotPath"]
                )
                sub_domain.http_header_path = (
                    target_result_dir
                    + "/aquascreenshots/"
                    + data["pages"][host]["headersPath"]
                )
                tech_list = []
                if data["pages"][host]["tags"] is not None:
                    for tag in data["pages"][host]["tags"]:
                        tech_list.append(tag["text"])
                tech_string = ",".join(tech_list)
                sub_domain.technology_stack = tech_string
                sub_domain.save()
        except Exception as exception:
            print("-" * 30)
            print("aqua json")
            print(exception)
            print("-" * 30)
            update_last_activity(activity_id, 0)

        """
        Directory search is not provided by default, check for conditions
        """
        if task.scan_type.dir_file_search:
            update_last_activity(activity_id, 2)
            activity_id = create_scan_activity(task, "Directory Search", 1)
            # scan directories for all the alive subdomain with http status >
            # 200
            alive_subdomains = ScannedHost.objects.filter(
                scan_history__id=task.id
            ).exclude(http_url="")
            dirs_results = target_result_dir + "/dirs.json"

            # check the yaml settings
            extensions = ",".join(
                str(port)
                for port in yaml_configuration["dir_file_search"]["extensions"]
            )

            # find the threads from yaml
            if yaml_configuration["dir_file_search"]["thread"] > 0:
                threads = yaml_configuration["dir_file_search"]["thread"]
            else:
                threads = 10

            for subdomain in alive_subdomains:
                # /app/tools/dirsearch/db/dicc.txt
                if subdomain.http_url.endswith("/"):
                    temp_http_url = subdomain.http_url + "FUZZ"
                else:
                    temp_http_url = subdomain.http_url + "/FUZZ"
                if (
                    "wordlist" not in yaml_configuration["dir_file_search"]
                    or not yaml_configuration["dir_file_search"]["wordlist"]
                    or "default" in yaml_configuration["dir_file_search"]["wordlist"]
                ):
                    wordlist_location = settings.TOOL_LOCATION + "dirsearch/db/dicc.txt"
                else:
                    wordlist_location = (
                        settings.TOOL_LOCATION
                        + "wordlist/"
                        + yaml_configuration["dir_file_search"]["wordlist"]
                        + ".txt"
                    )

                dirsearch_command = (
                    settings.TOOL_LOCATION
                    + "get_dirs.sh {} {} {} {}".format(
                        temp_http_url,
                        wordlist_location,
                        dirs_results,
                        extensions,
                    )
                )

                # check if recursive strategy is set to on
                if yaml_configuration["dir_file_search"]["recursive"]:
                    dirsearch_command = dirsearch_command + " {}".format(
                        yaml_configuration["dir_file_search"]["recursive_level"]
                    )
                else:
                    dirsearch_command = dirsearch_command + " {}".format("10")
                # print(dirsearch_command)
                os.system(dirsearch_command)
                try:
                    with open(dirs_results, "r") as json_file:
                        if subdomain.http_url.endswith("/"):
                            temp_http_url = (
                                subdomain.http_url
                                + "dayladuongdan@@khongtontai@trenmaychu"
                            )
                        else:
                            temp_http_url = (
                                subdomain.http_url
                                + "/dayladuongdan@@khongtontai@trenmaychu"
                            )
                        try:
                            default_size = len(requests.get(url=temp_http_url).content)
                        except:
                            default_size = -1
                        json_string = json_file.read()
                        print(json_string)
                        json_string = "\n".join(
                            check_dirs_result(json_string, default_size)
                        )
                        scanned_host = ScannedHost.objects.get(
                            scan_history__id=task.id,
                            http_url=subdomain.http_url,
                        )
                        scanned_host.directory_json = json_string
                        scanned_host.save()
                except Exception as exception:
                    print("-" * 30)
                    print("454")
                    print(exception)
                    print("-" * 30)
                    update_last_activity(activity_id, 0)

        """
        Getting endpoint from GAU, is also not set by default, check for conditions.
        One thing to change is that, currently in gau, providers is set to wayback,
        later give them choice
        """
        # TODO: give providers as choice for users between commoncrawl,
        # alienvault or wayback
        if task.scan_type.fetch_url:
            update_last_activity(activity_id, 2)
            activity_id = create_scan_activity(task, "Fetching endpoints", 1)
            """
            It first runs gau to gather all urls from wayback, then we will use hakrawler to identify more urls
            """
            if "all" in yaml_configuration["fetch_url"]["uses_tool"]:
                tools = "gau hakrawler"
            else:
                tools = " ".join(
                    str(tool) for tool in yaml_configuration["fetch_url"]["uses_tool"]
                )

            subdomain_scan_results_file = (
                target_result_dir + "/sorted_subdomain_collection.txt"
            )

            if "aggressive" in yaml_configuration["fetch_url"]["intensity"]:
                with open(subdomain_scan_results_file) as subdomain_list:
                    for subdomain in subdomain_list:
                        if validators.domain(subdomain.rstrip("\n")):
                            print("-" * 20)
                            print("Fetching URL for " + subdomain.rstrip("\n"))
                            os.system(
                                settings.TOOL_LOCATION
                                + "get_urls.sh %s %s %s"
                                % (
                                    subdomain.rstrip("\n"),
                                    target_result_dir,
                                    tools,
                                )
                            )

                            urls_json_result = open(url_results_file, "r")
                            lines = urls_json_result.readlines()
                            for line in lines:
                                print(f"line 495 {line}")
                                json_st = json.loads(line.strip())
                                endpoint = WayBackEndPoint()
                                endpoint.url_of = task
                                endpoint.http_url = (
                                    "" if "url" not in json_st else json_st["url"]
                                )
                                endpoint.content_length = (
                                    json_st["content-length"]
                                    if "content-length" in json_st
                                    else 0
                                )
                                endpoint.http_status = (
                                    ""
                                    if "status_code" not in json_st
                                    else json_st["status_code"]
                                )
                                endpoint.page_title = (
                                    "" if "title" not in json_st else json_st["title"]
                                )
                                endpoint.discovered_date = timezone.now()
                                if "content-type" in json_st:
                                    endpoint.content_type = json_st["content-type"]
                                endpoint.save()
            else:
                os.system(
                    settings.TOOL_LOCATION
                    + "get_urls.sh %s %s %s"
                    % (domain.domain_name, target_result_dir, tools)
                )

                url_results_file = target_result_dir + "/final_httpx_urls.json"

                urls_json_result = open(url_results_file, "r")
                lines = urls_json_result.readlines()
                for line in lines:
                    print(f"line 517 {line}")
                    json_st = json.loads(line.strip())
                    endpoint = WayBackEndPoint()
                    endpoint.url_of = task
                    endpoint.http_url = json_st["url"]
                    endpoint.content_length = (
                        json_st["content-length"] if "content-length" in json_st else 0
                    )
                    endpoint.http_status = json_st["status_code"]
                    endpoint.page_title = json_st["title"]
                    endpoint.discovered_date = timezone.now()
                    if "content-type" in json_st:
                        endpoint.content_type = json_st["content-type"]
                    endpoint.save()

        """
        Run Jaeles Scan
        """
        if task.scan_type.vulnerability_scan:
            print("Start Jaeles")
            target_list = ScannedHost.objects.filter(scan_history__id=scan_history_id)
            print(target_list)
            update_last_activity(activity_id, 2)
            activity_id = create_scan_activity(task, "Vulnerability Scan", 1)
            try:
                for target in target_list:
                    doJaelesScanTarget(target, task, jaeles_result_dir)
            except Exception as exception:
                print("╒" + "-" * 15 + "Start Scan jaeles Exception" + "-" * 15 + "╕")
                print(exception)
                print("╘" + "-" * 15 + "End Scan jaeles Exception" + "-" * 15 + "╛")
                update_last_activity(activity_id, 0)
        """
        Once the scan is completed, save the status to successful
        """
        task.scan_status = 2
        task.save()
    except Exception as exception:
        print("-" * 30)
        print("644")
        print(exception)
        print("-" * 30)
        scan_failed(task)

    send_notification("Big-recon finished scanning " + domain.domain_name)
    update_last_activity(activity_id, 2)
    activity_id = create_scan_activity(task, "Scan Completed", 2)
    return {"status": True}


def send_notification(message):
    send_telegram_notification(message)
    notif_hook = NotificationHooks.objects.filter(send_notif=True)
    # notify on slack
    scan_status_msg = {"text": message}
    headers = {"content-type": "application/json"}
    for notif in notif_hook:
        requests.post(notif.hook_url, data=json.dumps(scan_status_msg), headers=headers)


def scan_failed(task):
    task.scan_status = 0
    task.save()


def create_scan_activity(task, message, status):
    scan_activity = ScanActivity()
    scan_activity.scan_of = task
    scan_activity.title = message
    scan_activity.time = timezone.now()
    scan_activity.status = status
    scan_activity.save()
    return scan_activity.id


def update_last_activity(id, activity_status):
    ScanActivity.objects.filter(id=id).update(
        status=activity_status, time=timezone.now()
    )


@app.task(bind=True)
def test_task(self):
    print("*" * 40)
    print("test task run")
    print("*" * 40)


def convert_output_jaeles_to_nuclei(output_path):
    jaeles_path = output_path + "/jaeles-vuln/jaeles-summary.txt"
    nuclei_path = output_path + "/vulnerability.json"
    if not os.path.exists(jaeles_path):
        print("Jaeles output not found")
        return
    nuclei_output_json = {
        "template": "",
        "type": "http",
        "matched": "",
        "name": "",
        "severity": "",
        "author": "Mr.X",
        "description": "",
    }
    try:
        with open(jaeles_path, "r") as f:
            for raw in f.readlgnes():
                if not raw:
                    continue
                raw_split = raw.strip().split(" - ")
                vuln_url = raw_split[1]
                label = raw_split[0]
                template_name = label.split("][")[0].replace("[", "")
                severity = label.split("][")[1].replace("]", "")
                if vuln_url != None:
                    nuclei_output_json["matched"] = vuln_url
                    nuclei_output_json["name"] = template_name
                    nuclei_output_json["severity"] = severity
                    with open(nuclei_path, "a+") as fn:
                        json.dump(nuclei_output_json, fn)
                        fn.write("\n")
    except Exception as e:
        print("[+] Write json error, " + str(e))
        pass


@app.task(name="subdomain_file_task")
def subdomain_file_task(subdomain_file_path, dir_path):
    # time.sleep(10)
    print("-----------start file task--------------")
    print(dir_path)
    print(subdomain_file_path)
    # time.sleep(20)
    print("da in roi nha " + dir_path)

    run_xray.apply_async(args=([dir_path]), queue="run_xray", routing_key="run_xray")
    time.sleep(5)
    # os.system('timeout 3600 /app/tools/xray/xray_linux_amd64 webscan --listen 127.0.0.1:7777 --html-output '+ dir_path +'/output.html')# | python3 /app/tools/crawlergo.py '+ dir_path+'/'+subdomain_file_path)
    print("xray run roi, cho python")
    os.system("python3 /app/tools/crawlergo.py " + dir_path + "/" + subdomain_file_path)


@app.task(name="run_xray")
def run_xray(dir_path):
    print("da vao ham run xray")
    os.system(
        "timeout 36000 /app/tools/xray/xray_linux_amd64 webscan --listen 127.0.0.1:7777 --html-output "
        + dir_path[0]
        + "/output.html"
    )  # | python3 /app/tools/crawlergo.py '+ dir_path+'/'+subdomain_file_path)


def doJaelesScanTarget(target: ScannedHost, task, result_dir):
    os.system(f"jaeles config init")
    os.system(f"jaeles config add --signDir {settings.TOOL_LOCATION}/jaeles/signatures")
    os.system(f"jaeles config add --signDir ")
    result_dir = result_dir + "_" + target.subdomain
    if target.technology_stack:
        target_tech = target.technology_stack.split(",")
    else:
        target_tech = []
    os.mkdir(result_dir)
    command_to_run = "jaeles scan -u " + target.subdomain + " -o " + result_dir
    signature_part = ""
    common_sign = Signatures.objects.filter(target_for__contains="common")
    signature_paths = set(x.sign_path for x in common_sign)
    for tech in target_tech:
        tech_sign = Signatures.objects.filter(target_for__contains=tech)
        tech_sign_paths = set(x.sign_path for x in tech_sign)
        signature_paths = signature_paths.union(tech_sign_paths)
    for sign_path in signature_paths:
        signature_part += " -s " + sign_path
    if signature_part:
        command_to_run += signature_part
    os.system(command_to_run)
    vuln_summary = result_dir + "/vuln-summary.txt"
    if os.path.isfile(vuln_summary):
        read_and_send_notification(vuln_summary, task)
    else:
        print("Something happened")


def read_and_send_notification(file, task=None):
    print(file)
    with open(file, "r") as f:
        lines = f.readlines()
        for line in lines:
            print(line)
            pattern = re.compile(r"\[([^\]]*)\]\[([^\]]*)\] - (.*)")
            try:
                sign_id, severity, url = re.search(pattern, line).groups()
                print(sign_id, severity, url)
                save_vuln(sign_id, url, task)
                message = base_message.format(url=url, severity=severity, id=sign_id)
                send_telegram_notification(message)
            except Exception as e:
                print(e)


def save_vuln(sign_id, url, task):
    vuln = VulnerabilityScan()
    sign = Signatures.objects.get(sign_id=sign_id)
    vuln.sign_id = sign_id
    vuln.name = sign.sign_name
    vuln.severity = sign.severity
    vuln.discovered_date = timezone.now()
    vuln.url = url
    vuln.vulnerability_of = task
    vuln.save()


def send_telegram_notification(message):
    try:
        print(message)
        telegram_notify = telegram.Bot("1742462899:AAFUt1VdxpSyGOq3bY9MQfVCamKViXucvgo")
        chat_id = "-524606655"
        telegram_notify.send_message(
            chat_id=chat_id, text=message, parse_mode="Markdown"
        )
    except Exception as ex:
        print(ex)

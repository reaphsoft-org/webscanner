#!/usr/bin/env python
import re
import socket
import time
from itertools import groupby
from random import choice

import spacy
import whois
from django.conf import settings
from django.core.paginator import Paginator
from requests.exceptions import ProxyError
from zapv2 import ZAPv2

from . import keywords
from .models import CVE

zap = ZAPv2(apikey=settings.ZAP_API_KEY)

def spider(target_url):
    """"""
    try:
        scan_id = zap.spider.scan(target_url)
        return int(scan_id), ""
    except ProxyError:
        return -1, "Scanner was unable to connect to proxy."


def ajax_spider(target_url):
    """
    When this function is called, do
    >>> timeout = time.time() * 60 * 2 # 2 minutes from now
    Then

    >>> while zap.ajaxSpider.status == 'running':
            if time.time() > timeout:
                break
            print('Ajax Spider status' + zap.ajaxSpider.status)
            time.sleep(2)
    """
    try:
        scan_id = zap.ajaxSpider.scan(target_url)
        return int(scan_id), ""
    except ProxyError:
        return -1, "Scanner was unable to connect to proxy."


def passive_scan_results(target_url):
    alerts = zap.core.alerts(baseurl=target_url)
    cwe = list(filter(lambda i: i["cweid"] != "-1", alerts))
    non_cwe = list(filter(lambda i: i["cweid"] == "-1", alerts))
    cwe.sort(key=lambda x: x["name"])
    groups = groupby(cwe, lambda i: i["name"])

    results = []
    for group, items in groups:
        _list = list(items)
        _sample = _list[0]
        cwe_id = _sample['cweid']
        alert_ref = _sample['alertRef']
        keyword = keywords.data.get(alert_ref, "")
        object_list = get_cves_by_cwe(cwe_id, page_size=10, keyword=keyword).object_list
        if len(object_list) > 0:
            matching_cve = choice(object_list).to_dict()
        else:
            matching_cve = None
        cves = list(object_list.values_list("cve_id", flat=True))
        dic = {"name": _sample["name"], "cweid": _sample["cweid"], "description": _sample["description"],
               "risk": _sample["risk"], "solution": _sample["solution"], "cves": cves, "matching_cve": matching_cve,
               "urls": list(set([(i["confidence"], i["url"]) for i in _list])), "tags": list(_sample["tags"].items())}
        results.append(dic)
    non_cwe.sort(key=lambda x: x["name"])
    groups2 = groupby(non_cwe, lambda i: i["name"])

    for group, items in groups2:
        _list = list(items)
        _sample = _list[0]
        dic = {"name": _sample["name"], "cweid": _sample["cweid"], "description": _sample["description"],
               "risk": _sample["risk"], "solution": _sample["solution"], "cves": [], "matching_cve": None,
               "urls": list(set([(i["confidence"], i["url"]) for i in _list])), "tags": list(_sample["tags"].items())}
        results.append(dic)

    return results


def get_cves_by_cwe(cwe_id, page_number=1, page_size=50, keyword=""):
    original_query = CVE.objects.filter(
        # weaknesses__contains=[{"description": [{"value": f"CWE-{cwe_id}"}]}] # this targets both primary and secondary
        weaknesses__contains=[{"type": "Primary", "description": [{"value": f"CWE-{cwe_id}"}]}],
        # this targets only primary.
        metrics__contains={"cvssMetricV30": []},  # Ensures cvssMetricV30 exists
    ).filter(
        descriptions__icontains="web"
    )
    query = original_query.filter(
        descriptions__icontains=keyword
    )
    if query.count() < 1:
        query = original_query
    query = query.order_by("-cve_id")  # Sort in descending order by CVE ID
    paginator = Paginator(query, page_size)
    return paginator.get_page(page_number)


def extract_ip(url):
    # Regex pattern to match protocol, IP address, and optional port
    pattern = r"^(https?:\/\/)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?(\/.*)?$"

    match = re.match(pattern, url)
    if match:
        ip = match.group(2)  # Extract the IP address
        return True, ip

    return False, None


def get_hosting_info(url, session = None):
    # Ensure the URL is in the correct format
    if not url.startswith("http"):
        url = "http://" + url  # Add http if missing

    domain = url.split("//")[-1].split("/")[0]  # Extract domain name

    # Get the domain's WHOIS info
    try:
        w = whois.whois(domain)
        registrar = w.registrar  # Hosting provider or domain registrar
        registrar_url = w.registrar_url
        if type(registrar_url) == type(str):
            registrar_url = [registrar_url]
        name_servers = w.name_servers
        if len(name_servers) > 0:
            server = name_servers[0]
            index = server.find(".")
            if index >= 0:
                web_host = server[index+1:].lower()
            else:
                web_host = server.lower()
        else:
            web_host = "Unable to fetch web hosting provider"
    except Exception:
        registrar = "Could not retrieve WHOIS data"
        registrar_url = ["Could not retrieve registrar URL"]
        web_host = "Unable to fetch web hosting provider"

    # Get the IP address of the domain
    try:
        ip_address = socket.gethostbyname(domain)
    except Exception:
        flag, ip_address = extract_ip(url)
        if not flag:
            ip_address = "Could not resolve IP"

    result = {
        "domain": domain,
        "ip_address": ip_address,
        "registrar": registrar,
        "registrar_url": registrar_url,
        "web_host": web_host,
    }

    if session:
        session["get_hosting_info"] = result
        session.save()

    return result


def spacy_compare(description, cwe_id):
    nlp = spacy.load("en_core_web_md")
    query = CVE.objects.filter(
        weaknesses__contains=[{"type": "Primary", "description": [{"value": f"CWE-{cwe_id}"}]}] # this targets only primary.
        )
    zap_doc = nlp(description)
    similarities = [(cve, zap_doc.similarity(nlp(cve.descriptions[0]["value"]))) for cve in query]
    similarities.sort(key=lambda x: x[1], reverse=True)
    if len(similarities) > 0:
        return similarities[0][0]
    else:
        return None

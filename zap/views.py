import threading

from django.shortcuts import render, redirect
from django.views.decorators.http import require_POST
from requests.exceptions import ProxyError

from .tasks import spider, zap, passive_scan_results, get_cves_by_cwe, get_hosting_info


# Create your views here.

def home(request):
    """"""
    error = request.session.get("zap_error", "")
    return render(request, "zap/home.html", {"error": error})

@require_POST
def scan(request):
    """"""
    url = request.POST.get('url')
    scan_id = int(request.session.get("zap_scan_id", -1))
    if scan_id != -1:
        request.session['zap_error'] = ("A scan is currently ongoing, or hasn't been cleared. "
                                          "Please check the scan status.")
        request.session.modified = True
        return redirect("zap:home")

    scan_id, message = spider(url)
    if scan_id < 0:
        request.session['zap_error'] = message
        request.session.modified = True
        return redirect("zap:home")

    thread = threading.Thread(target=get_hosting_info, args=(url, request.session))
    thread.start()

    request.session['url'] = url
    request.session['zap_scan_id'] = scan_id
    request.session.modified = True

    return redirect("zap:status")

def status(request):
    """"""
    scan_id = int(request.session.get("zap_scan_id", -1))
    target_url = request.session.get("url", "")
    if scan_id < 0:
        return redirect("zap:home")
    message = ""
    results = []
    items_left = 0
    passive_results = []
    hosting_info = {
        "domain": "Running",
        "ip_address": "Running",
        "registrar": "Running",
        "registrar_url": "Running",
        "web_host": "Running",
    }

    try:
        level = int(zap.spider.status(scan_id))
        results = zap.spider.results(scan_id)
        if level >= 100:
            items_left = int(zap.pscan.records_to_scan)
            if items_left == 0:
                passive_results = passive_scan_results(target_url)
            hosting_info = request.session.get("get_hosting_info", hosting_info)

    except ProxyError:
        level = 0
        message = ("We were unable to establish a connection while checking the status of your scan. "
                   "Please refresh the page or contact the admin.")
    context = {'level': level, 'results': results, "error": message, "items_left": items_left,
               "passive_results": passive_results, "hosting_info": hosting_info
               }
    return render(request, "zap/status.html", context)

def clear(request):
    """"""
    scan_id = int(request.session.get("zap_scan_id", -1))
    if scan_id != -1:
        zap.spider.stop(scan_id)
    request.session.flush()
    return render(request, "zap/clear.html")

def cves(request, cwe):
    """"""
    page = int(request.GET.get('page', 1))
    if page < 1:
        page = 1
    page_size = 100
    paginator = get_cves_by_cwe(cwe, page, page_size)
    context = {
        'cwe_id': cwe,
        'cves': paginator.object_list,
        'page': page,
        'total_pages': paginator.paginator.num_pages,
        'prev_page': page - 1 if page > 1 else None,
        'next_page': page + 1 if page < paginator.paginator.num_pages else None
    }

    return render(request, 'zap/cve_list.html', context)
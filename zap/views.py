from django.shortcuts import render, redirect
from django.views.decorators.http import require_POST
from requests.exceptions import ProxyError

from .tasks import spider, zap


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

    request.session['url'] = url
    request.session['zap_scan_id'] = scan_id
    request.session.modified = True

    return redirect("zap:status")

def status(request):
    """"""
    scan_id = int(request.session.get("zap_scan_id", -1))
    if scan_id < 0:
        return redirect("zap:home")
    message = ""
    results = []
    try:
        level = zap.spider.status(scan_id)
        results = zap.spider.results(scan_id)
    except ProxyError:
        level = 0
        message = ("We were unable to establish a connection while checking the status of your scan. "
                   "Please refresh the page or contact the admin.")
    return render(request, "zap/status.html", {'level': level, 'results': results, "error": message})
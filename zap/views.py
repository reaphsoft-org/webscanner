from django.shortcuts import render, redirect
from django.views.decorators.http import require_POST
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
    scan_id = int(request.session.get("zap_error", ""))
    if scan_id != 0:
        request.session['zap_error'] = ("A scan is currently ongoing, or hasn't been cleared. "
                                          "Please check the scan status.")
        request.session.modified = True
        return redirect("zap:home")

    request.session['zap_scan_id'] = scan_id
    request.session['url'] = url
    scan_id = spider(url)
    request.session['zap_scan_id'] = scan_id
    request.session.modified = True

    return redirect("zap:status")

def status(request):
    """"""
    return render(request, "scanner/homev2.html")
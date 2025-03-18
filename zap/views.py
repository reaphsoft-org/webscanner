import io
import threading

from django.conf import settings
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST
from requests.exceptions import ProxyError
from xhtml2pdf import pisa

from .models import ScanData
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
    user_email = request.session.get("user_email", "")
    if scan_id < 0:
        return redirect("zap:home")
    message = ""
    results = request.session.get("spider_results", [])
    items_left = 0
    passive_results = []
    hosting_info = {
        "domain": "Running",
        "ip_address": "Running",
        "registrar": "Running",
        "registrar_url": ["Running"],
        "web_host": "Running",
        "hostname": "Running",
        "host_organization": "Running"
    }

    try:
        level = int(zap.spider.status(scan_id))
        if level >= 100:
            if not results:
                results = zap.spider.results(scan_id)
                request.session["spider_results"] = results
            items_left = int(zap.pscan.records_to_scan)
            if items_left == 0:
                passive_results = request.session.get("passive_results", [])
                if not passive_results:
                    passive_results = passive_scan_results(target_url)
                    request.session['passive_results'] = passive_results
            hosting_info = request.session.get("get_hosting_info", hosting_info)
    except ProxyError:
        level = 0
        message = ("We were unable to establish a connection while checking the status of your scan. "
                   "Please refresh the page or contact the admin.")
    context = {'level': level, 'results': results, "error": message, "items_left": items_left,
               "passive_results": passive_results, "hosting_info": hosting_info, 'user_email': user_email,
               }
    return render(request, "zap/status.html", context)

def clear(request):
    """"""
    user_email = request.session.get("user_email", "")
    scan_id = int(request.session.get("zap_scan_id", -1))
    if scan_id != -1:
        zap.pscan.clear_queue()
        zap.spider.stop(scan_id)
    request.session.flush()
    if user_email:
        # request.session["user_email"] = user_email
        request.session.save()
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

def save_report(request):
    email = request.GET.get("email")

    if not email:
        email = request.session.get("user_email")  # Try to get it from the session

    if not email:
        return JsonResponse({"success": False, "error": "Email is required"}, status=400)

    # Store email in session for future requests
    request.session["user_email"] = email

    target_url = request.session.get("url", "")
    hosting_info = request.session.get("get_hosting_info", dict())
    passive_results = request.session.get("passive_results", [])
    results = request.session.get("spider_results", [])

    # Save the report
    flag = request.session.get("saved_report", False)
    if not flag:
        ScanData.objects.create(
            email=email,
            url=target_url,
            results=results,
            hosting_info=hosting_info,
            passive_results=passive_results
        )
        request.session["saved_report"] = True


    return JsonResponse({"success": True, "message": "Report saved successfully!"})

def history(request):
    """"""

    if request.method == "POST":
        email = request.POST.get("email")  # Get email from the form
        if email:
            request.session["user_email"] = email  # Store email in session
            return redirect(reverse("zap:history"))  # Redirect to the same page (or another view if needed)

    email = request.session.get("user_email", "")  # Retrieve email from session
    reports = []  # You can replace this with logic to fetch user-specific reports
    page_obj = None

    if email:
        # Filter reports by email
        query_set = ScanData.objects.filter(email=email).order_by("-datetime")

        # Paginate results (50 per page)
        paginator = Paginator(query_set, 50)
        page_number = request.GET.get("page")
        page_obj = paginator.get_page(page_number)

        # Format reports as list of dictionaries
        reports = [{"id": report.id, "name": report.datetime} for report in page_obj]

    context = { "user_email": email, "reports": reports,  "page_obj": page_obj, }
    return render(request, "zap/reports.html", context)

def view_report(request, pk):
    """"""
    email = request.session.get("user_email", "")
    if not email:
        return redirect(reverse("zap:history"))  # Redirect to the same page (or another view if needed)
    # continue use email and pk to get report.
    try:
        report = ScanData.objects.get(email=email, pk=pk)
    except ScanData.DoesNotExist:
        report = None
    return render(request, "zap/report.html", {"report": report})

def generate_pdf(request):
    target_url = request.session.get("url", "")
    hosting_info = request.session.get("get_hosting_info", dict())
    passive_results = request.session.get("passive_results", [])
    results = request.session.get("spider_results", [])
    if not target_url or not hosting_info or not passive_results or not results:
        return redirect("zap:status")
    report = ScanData(
        email="",
        url=target_url,
        results=results,
        hosting_info=hosting_info,
        passive_results=passive_results
    )

    return create_pdf(report)

def download_pdf(request, pk):
    email = request.session.get("user_email", "")
    if not email:
        return redirect(reverse("zap:history"))  # Redirect to the same page (or another view if needed)
    # continue use email and pk to get report.
    try:
        report = ScanData.objects.get(email=email, pk=pk)
    except ScanData.DoesNotExist:
        return redirect(reverse("zap:history"))

    return create_pdf(report)

def create_pdf(report):
    template_name = "zap/report_template.html"
    context = {"report": report}
    html_content = render_to_string(template_name, context)
    # Create a PDF
    pdf_file = io.BytesIO()
    pisa_status = pisa.CreatePDF(io.BytesIO(html_content.encode("UTF-8")), pdf_file)
    if pisa_status.err:
        return HttpResponse("Error generating PDF", content_type="text/plain")
    # Return response
    pdf_file.seek(0)
    return HttpResponse(pdf_file, content_type="application/pdf",
                        headers={"Content-Disposition": 'attachment; filename="report.pdf"'})

def send_via_email(request, pk):
    """"""
    email = request.GET.get("email")

    if not email:
        email = request.session.get("user_email")

    if not email:
        return JsonResponse({"success": False, "error": "Email is required. Try refreshing the page."}, status=400)

    if int(pk) == 0:
        target_url = request.session.get("url", "")
        hosting_info = request.session.get("get_hosting_info", dict())
        passive_results = request.session.get("passive_results", [])
        results = request.session.get("spider_results", [])
        if not target_url or not hosting_info or not passive_results or not results:
            return JsonResponse({"success": False, "error": "No scan data was found for this session. Please refresh the page."}, status=400)
        report = ScanData(
            email="",
            url=target_url,
            results=results,
            hosting_info=hosting_info,
            passive_results=passive_results
        )
        report_time = timezone.now()
    else:
        try:
            report = ScanData.objects.get(email=email, pk=pk)
            report_time = report.datetime
        except ScanData.DoesNotExist:
            return JsonResponse({"success": False, "error": "No scan data was found. Please refresh the page."}, status=400)

    email = request.GET.get("email")
    context = {
        'report': report,
        'report_time': report_time
    }
    html = render_to_string('zap/mail.html', context=context)

    send_mail(
        'WebScan Results',
        f'Attached to this email is the result of your webscan for {report.url}',
        f'WebScanner <{settings.EMAIL_HOST_USER}>',
        recipient_list=[
            'felix@reaphsoft.com',
            # 'cybersecurity@reaphsoft.com',
            email
        ],
        html_message=html,
        fail_silently=False
    )

    request.session["user_email"] = email

    return JsonResponse({"success": True, "message": f"An email has been sent to {email}"})
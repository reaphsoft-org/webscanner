# from django.shortcuts import render

# Create your views here.

import csv
import requests
from .tasks import run_crawler
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from celery.result import AsyncResult
from django.conf import settings
from django.core.mail import send_mail
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.utils import timezone
from django.contrib import messages
from django.views.decorators.http import require_POST


def scanner(request):
    if request.method == 'POST':
        url = request.POST.get('url')

        # Validate the URL
        if not url.startswith('http'):
            url = f'http://{url}'

        try:
            # Send a request to the target website
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
            }
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()  # Raise an error for bad status codes

            # Parse the HTML content
            soup = BeautifulSoup(response.text, 'html.parser')

            # Perform scanning logic
            vulnerabilities = []
            discovered_users = []
            
            # Example 1: Check for common vulnerabilities
            if 'php?id=' in response.text or 'query=' in response.text:
                vulnerabilities.append("Potential SQL Injection")
            
            if '<script>' in response.text:
                vulnerabilities.append("Potential Cross-Site Scripting (XSS)")

            # Example 2: Check for forms without CSRF tokens (indicating CSRF vulnerability)
            forms = soup.find_all('form')
            for form in forms:
                if not form.find('input', {'name': 'csrf_token'}):
                    vulnerabilities.append("Potential CSRF vulnerability")

            # Example 3: Attempt to extract user data from the target
            # (e.g., usernames or roles from forms, comments, or metadata)
            possible_users = soup.find_all(string=lambda text: text and ('username' in text.lower() or 'user' in text.lower()))
            for user in possible_users:
                discovered_users.append({'username': user.strip(), 'role': 'Unknown', 'server': 'Unknown'})

            # Simulate default results for demonstration purposes
            if not discovered_users:
                discovered_users = [
                    {'username': 'guest', 'role': 'Guest', 'server': 'Linux'},
                ]

            request.session['results'] = vulnerabilities
            request.session['url'] = url

            task = run_crawler.delay(url)
            request.session['task_id'] = task.id

            request.session.modified = True


            return render(request, 'scanner/results.html', {
                'url': url,
                'vulnerabilities': vulnerabilities or ["No vulnerabilities detected"],
                'users': discovered_users,
            })
        except requests.exceptions.RequestException as e:
            # Handle connection errors
            return render(request, 'scanner/scanner.html', {'error': f"Error accessing {url}: {str(e)}"})
    
    return render(request, 'scanner/scanner.html')

def consent_page(request):
    if request.method == 'POST':
        if 'yes' in request.POST:
            return redirect('scanner')
        else:
            messages.warning(request, "You must confirm permission to proceed.")
    return render(request, 'scanner/consent.html')

def download_csv(request):
    """

    """

    response = HttpResponse(
        content_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="WebScanResult.csv"'},
    )

    writer = csv.writer(response)
    writer.writerow(["S/N", "Vulnerability", "Severity"])
    vulnerabilities = request.session.get('results', [])
    for i, v in enumerate(vulnerabilities):
        writer.writerow([f"{i+1}", v, "NA"])

    return response

@require_POST
def send_via_email(request):
    """
    """
    now = timezone.now()
    v = request.session.get('results', [])
    url = request.session.get('url', 'NA')
    email = request.POST.get("email")
    context = {
        'website_url': url,
        'vulnerabilities': [{'name': i, 'severity': 'N/A'} for i in v],
        'scan_date': now
    }
    html = render_to_string('scanner/mail.html', context=context)
    
    send_mail(
        'WebScan Results',
        f'Attached to this email is the result of your webscan for {url}',
        f'WebScanner <{settings.EMAIL_HOST_USER}>',
        recipient_list=[
            'felix@reaphsoft.com',
            'cybersecurity@reaphsoft.com',
            email
        ],
        html_message=html,
        fail_silently=False
    )

    return render(request, 'scanner/scanner.html', {'error': f"An email has been sent to {email}"})

def task_status(request, task_id):
    result = AsyncResult(task_id)
    if result.state == "SUCCESS":
        return JsonResponse({"status": result.state, "result": result.result})
    return JsonResponse({"status": result.state})

def current_task(request):
    task_id = request.session.get('task_id', None)
    if not task_id:
        return  JsonResponse({"status": "Not task found"})
    return task_status(request, task_id)

def tasks(request):
    scan_id = request.session.get('task_id', "None")
    return JsonResponse({'task_id': scan_id})
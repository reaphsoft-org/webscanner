# from django.shortcuts import render

# Create your views here.

from django.shortcuts import render
from django.http import JsonResponse

def scanner(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        # Add your scanning logic here
        return render(request, 'scanner_app/results.html', {
            'url': url,
            'vulnerabilities': ["SQL Injection", "Cross-Site Scripting (XSS)"],
            'users': [
                {'username': 'admin', 'role': 'Administrator', 'server': 'AWS'},
                {'username': 'user1', 'role': 'Editor', 'server': 'Azure'},
            ]
        })
    return render(request, 'scanner_app/scanner.html')

# scanner/views.py
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib import messages

def consent_page(request):
    if request.method == 'POST':
        if 'yes' in request.POST:
            return redirect('scanner')
        else:
            messages.warning(request, "You must confirm permission to proceed.")
    return render(request, 'scanner/consent.html')

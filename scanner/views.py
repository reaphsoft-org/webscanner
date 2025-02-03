# from django.shortcuts import render

# Create your views here.

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from django.shortcuts import render
from django.shortcuts import render, redirect
from django.contrib import messages


def scanner(request):
    if request.method == 'POST':
        url = request.POST.get('url')

        # Validate the URL
        if not url.startswith('http'):
            url = f'http://{url}'

        try:
            # Send a request to the target website
            response = requests.get(url, timeout=10)
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

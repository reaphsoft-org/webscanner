import threading

from django.contrib import messages
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from django.shortcuts import render, redirect

from fetch_cve_data import save_cve_data


# ----------------------------------------------------------------------
def login(request):
    """"""
    if request.method == "POST":
        hashed = 'pbkdf2_sha256$600000$lHZa95U29LwMEWE2bqjiRZ$wtdj14hUCs0c8xTaYOjgbQA9Xo6wMALeRhaSkgDpmSs='
        password = request.POST.get("password")

        flag = check_password(password, hashed)
        if flag:
            # store in session
            request.session['password'] = password
            return redirect("dashboard")  # Redirect to dashboard or home
        else:
            messages.error(request, "Invalid password.")

    if request.session.get('password', None) is not None:
        return redirect("dashboard")

    return render(request, "a/login.html")


# ----------------------------------------------------------------------
def dashboard(request):
    """"""
    if request.session.get('password', None) is None:
        return redirect("login")

    return render(request, "a/dashboard.html")


# ----------------------------------------------------------------------
def register(request):
    """"""
    if request.session.get('password', None) is None:
        return redirect("login")
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect('create_admin')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered.")
            return redirect('create_admin')

        # Create superuser (admin)
        user = User.objects.create_superuser(username=username, email=email, password=password,
                                             first_name=first_name, last_name=last_name)
        messages.success(request, f"Admin user '{username}' created successfully!")

        return redirect('/admin/')

    return render(request, "a/create_admin.html")


# ----------------------------------------------------------------------
def download_cve_data(request):
    """"""
    if request.session.get('password', None) is None:
        return redirect("login")
    if request.method == "POST":
        start_index = request.POST.get("start_index", 0)

        # Validate input
        try:
            start_index = int(start_index)
            if start_index < 0:
                messages.error(request, "Start index cannot be negative.")
                return redirect("download_cve")
        except ValueError:
            messages.error(request, "Invalid input. Please enter a valid number.")
            return redirect("download_cve")

        # Here you can implement logic to process CVE data
        running = request.session.get('download_cve_started', False)
        if running:
            return redirect("download_status")

        request.session['download_cve_started'] = True
        request.session['download_cve_messages'] = [f"CVE data download started from index {start_index}."]

        thread = threading.Thread(target=save_cve_data, args=(start_index, request))
        thread.start()

        request.session.save()

        return redirect("download_status")

    return render(request, 'a/download_cve.html')


# ----------------------------------------------------------------------
def download_status(request):
    """"""
    if request.session.get('password', None) is None:
        return redirect("login")

    if request.session.get('download_cve_stopped', False):
        del request.session['download_cve_started']

    download_messages = request.session.get('download_cve_messages', [])

    return render(request, 'a/download_status.html', {'messages': download_messages})
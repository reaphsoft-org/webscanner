from django.contrib import messages
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from django.shortcuts import render, redirect


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

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect('create_admin')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered.")
            return redirect('create_admin')

        # Create superuser (admin)
        user = User.objects.create_superuser(username=username, email=email, password=password)
        messages.success(request, f"Admin user '{username}' created successfully!")

        return redirect('/admin/')

    return render(request, "a/create_admin.html")

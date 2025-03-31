from django.contrib import messages
from django.contrib.auth.hashers import check_password
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
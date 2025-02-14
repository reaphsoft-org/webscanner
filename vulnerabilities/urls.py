from django.urls import path
from .views import FetchVulnerabilitiesAPI

urlpatterns = [
    path('fetch-vulnerabilities/', FetchVulnerabilitiesAPI.as_view(), name='fetch-vulnerabilities'),
]

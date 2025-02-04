from . import views
from django.urls import path

urlpatterns = [
    path('', views.scanner, name="scan"),
    path('consent/', views.consent_page, name='consent'),
    path('download/csv/', views.download_csv, name='download_csv'),
    path('send/email/', views.send_via_email, name='send_via_email'),
]

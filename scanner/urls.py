from . import views
from django.urls import path

urlpatterns = [
    path('', views.scanner, name="scan"),
    path('consent/', views.consent_page, name='consent'),
]

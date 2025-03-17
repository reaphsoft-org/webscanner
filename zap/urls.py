from . import views
from django.urls import path

app_name = "zap"
urlpatterns = [
    path('', views.home, name="home"),
    path('scan/', views.scan, name="scan"),
    path('scan-status/', views.status, name="status"),
    path('clear/', views.clear, name="clear"),
    path('cves/<str:cwe>/', views.cves, name="cves"),
    path('save/report/', views.save_report, name="save_report"),
    path('history/', views.history, name="history")
]
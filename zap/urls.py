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
    path('history/', views.history, name="history"),
    path('report/<int:pk>/', views.view_report, name="report"),
    path('report/<int:pk>/download/', views.download_pdf, name="download_report"),
    path('report/<int:pk>/mail/', views.download_pdf, name="mail_report"),
    path('download/', views.generate_pdf, name="download"),
]
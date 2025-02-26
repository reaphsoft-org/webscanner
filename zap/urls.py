from . import views
from django.urls import path

app_name = "zap"
urlpatterns = [
    path('', views.home, name="home"),
]
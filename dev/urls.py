from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path(
        '',
        views.dev,
        name='dev'),
    path('download/scan_results/<str:filepath>', views.download_file,name='download'),
    path('subdomainfile',views.upload_subdomain_file,name='upload_subdomain_file'),
]

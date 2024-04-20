from django.contrib import admin
from django.urls import path, include
from . import views
urlpatterns = [
    path('add',
        views.add,
        name='gen_sign'),
    path('list',
        views.list_sign,
        name='list_sign'),
    path('scan',
        views.scan,
        name='scan_vuln'),
    path('api/',
        include('signatures.api.urls', 'signature_api')),
    path('edit/<str:sign_id>',
        views.edit,
        name='edit_sign'),
    path('delete/<str:sign_id>',
        views.delete,
        name='delete_sign'),
    path('deleteAll',
        views.delete_all,
        name='delete_all_sign'),
    path('reloadAll',
        views.reload_all,
        name='reload_all_sign')
]

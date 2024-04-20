from django.conf.urls import url, include
from django.urls import path
from rest_framework import routers
from .views import SignaturesViewSet

app_name = 'signatures'
router = routers.DefaultRouter()

router.register(r'signatures', SignaturesViewSet)

urlpatterns = [
    url('^', include(router.urls))
]

urlpatterns += router.urls

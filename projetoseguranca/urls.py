
from django.contrib import admin
from django.urls import path
from assinaturas.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', Login.as_view(), name='login'),
]

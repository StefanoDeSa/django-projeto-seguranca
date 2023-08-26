
from django.contrib import admin
from django.urls import path
from assinaturas.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', login_view, name='login'),
]

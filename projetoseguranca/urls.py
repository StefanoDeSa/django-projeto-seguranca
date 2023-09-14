
from django.contrib import admin
from django.urls import path
from assinaturas.views import *

urlpatterns = [
    path('', login_view),
    path('admin/', admin.site.urls),
    path('accounts/login/', login_view, name='login'),
    path('accounts/register/', register_view, name='register'),
    path('logout/', logout_view, name='logout'),
    path('keys/', generate_keys, name='generate_keys'),
    path('newdocument/', new_document, name='new_document'),
    path('signature_list/', signature_list, name='signature_list'),
    path('documentos/<int:id>/view/', view_document, name='view_document'),
]

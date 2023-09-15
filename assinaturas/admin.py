from django.contrib import admin
from .models import *
# Register your models here.

class KeyAdmin(admin.ModelAdmin):
    list_display = ('user', 'list_chave_privada', 'list_chave_publica')

    def list_chave_privada(self, obj):
        return obj.private_key.decode('utf-8')

    def list_chave_publica(self, obj):
        return obj.public_key.decode('utf-8')

    list_chave_privada.short_description = "Chave Privada"
    list_chave_publica.short_description = "Chave Pública"

class SignatureAdmin(admin.ModelAdmin):
    list_display = ('data', 'assinatura', 'hash')

class DocumentAdmin(admin.ModelAdmin):
    list_display = ('user', 'texto')


admin.site.register(Key, KeyAdmin)
admin.site.register(Signature, SignatureAdmin)
admin.site.register(Document, DocumentAdmin)
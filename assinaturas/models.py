from django.db import models
from django.contrib.auth.models import User

class Key(models.Model):

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='keys',
    )
    private_key = models.BinaryField(verbose_name='Chave Privada')
    public_key = models.BinaryField(verbose_name='Chave Pública')

    def __str__(self):
        return f'Chave para o usuário: {self.user}'

class Signature(models.Model):

    data = models.DateTimeField(verbose_name='Data e Hora', auto_now_add=True)
    assinatura = models.TextField(verbose_name='Assinatura')

    def __str__(self):
        data_formatada = self.data.strftime('%Y-%m-%d %H:%M:%S')
        return f"Assinatura do {self.user} - {data_formatada}"
    

class Document(models.Model):

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='documentUser')
    texto = models.TextField(verbose_name='Texto')
    salvo = models.BooleanField(verbose_name='Salvo?')
    assinado = models.ForeignKey(Signature, on_delete=models.CASCADE, related_name='userSignature', null=True, blank=True)

    def __str__(self):
        return f"Documento do usuário: {self.user}"
    

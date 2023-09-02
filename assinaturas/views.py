import hashlib

from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from django.contrib.auth.decorators import login_required
from .models import *

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('generate_keys')  # Redirecionar para a página de entrada
        else:
            return render(request, 'accounts/login.html', {'error': 'Usuário ou senha inválidos'})

    return render(request, 'accounts/login.html')

def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)

        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = UserCreationForm()

    return render(request, 'accounts/registrar.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def generate_keys(request):

    user = request.user

    if user.keys.exists():
        # O usuário já tem uma chave
        return render(request, 'gerar_chaves.html', {
            'error': 'Você já tem uma chave registrada.'
        })

    if request.method == 'POST':
        # O usuário clicou no botão
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        key = Key(
            user=user,
            private_key=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ),
            public_key=public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
        )
        key.save()

        return render(request, 'gerar_chaves.html', {
            'success': 'As chaves foram geradas com sucesso.'
        })
    else:
        return render(request, 'gerar_chaves.html')

@login_required
def new_document(request):
    user = request.user
    texto = request.POST['texto']

    if request.method == 'POST':
        if request.POST['action'] == 'salvar':

            # Verifique se o documento já existe no banco de dados.
            document = Document.objects.filter(user=request.user, texto=texto).first()

            if document:
                # O documento já existe no banco de dados.
                return render(request, 'criar_documento.html', {
                    'message': 'O documento já existe.',
                })
            else:
                # O documento não existe no banco de dados.
                document = Document(
                    user=request.user,
                    texto=texto,
                    salvo=True,
                )

                document.save()

                return render(request, 'criar_documento.html', {
                    'document': 'Documento salvo',
                })
        else:
            chaves = Key.objects.get(user=user)
            chave_privada = chaves.private_key
            hash_documento = hashlib.sha256(request.POST['texto'].encode()).digest()

            # Gerar o hash do texto
            hash = hashlib.sha256(texto.encode()).hexdigest()

           
    else:
        return render(request, 'criar_documento.html')
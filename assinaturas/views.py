import hashlib

from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes

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
    if request.method == 'POST':
        user = request.user
        action = request.POST.get('action', '')

        if action == 'salvar':
            texto = request.POST.get('texto', '')

            # Puxando o documento pelo usuário e o texto atual.
            document = Document.objects.filter(user=user, texto=texto).first()

            if document:
                # O documento já existe no banco de dados.
                return render(request, 'criar_documento.html', {
                    'message': 'O documento já existe.',
                })
            else:
                # O documento não existe no banco de dados e é criado.
                document = Document(
                    user=user,
                    texto=texto,
                    salvo=True,
                )

                document.save()

                return render(request, 'criar_documento.html', {
                    'document': 'Documento salvo',
                })
        elif action == 'assinar':
            texto = request.POST.get('texto', '')

            # Recuperando a chave privada do usuário
            chaves = Key.objects.get(user=user)
            chave_privada = serialization.load_pem_private_key(
                chaves.private_key,
                password=None,
            )
            
            #recupera chave publica
            chave_publica = chave_privada.public_key()
            
            #criptografa a mensagem
            ciphertext = chave_publica.encrypt(
            texto.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )

            #consegue o hash da mensagem criptografada
            ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()

            # Assinando a mensagem usando a chave privada
            signature = chave_privada.sign(
                ciphertext,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
    
            assinado = Signature(
                assinatura = signature,
                hash = ciphertext_hash
            )

            assinado.save()
            
            document = Document.objects.filter(user=user, texto=texto).first()

            if document:
                #quero apenas atualizar o campo "assinado" com o ass

                document.assinado = assinado
                document.save()
                return render(request, 'criar_documento.html', {
                    'document': 'O documento já existe e foi assinado.',
                })
            else:
                document = Document(
                    user=user,
                    texto=texto,
                    salvo=True,
                    assinado=assinado
                )

                document.save()

                return render(request, 'criar_documento.html', {
                    'document': 'Documento salvo e assinado',
                })

    else:
        return render(request, 'criar_documento.html')
    
@login_required
def signature_list(request):

    user = request.user

    documents = Document.objects.filter(user=user, assinado__isnull=False)

    return render(request, 'lista_assinados.html', {
        'documents': documents,
    })

@login_required
def view_document(request, id):

    document = Document.objects.get(id=id)
    assinatura_hex = document.assinado.assinatura.encode().hex()
    document.assinado.assinatura = assinatura_hex

    return render(request, 'visualizar_documento.html', {
        'documento': document,
    })

def validar_hash(request):

    if request.method == 'POST':

        hash = request.POST['hash']

        # Verifique se o hash já está no sistema
        if Signature.objects.filter(hash=hash).exists():
            return render(request, 'validar_hash.html', {
                'hash_existe': True,
            })
        else:
            return render(request, 'validar_hash.html', {
                'hash_existe': False,
            })

    return render(request, 'validar_hash.html')
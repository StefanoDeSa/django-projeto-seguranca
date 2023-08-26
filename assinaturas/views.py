from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('https://google.com.br')  # Redirecionar para a página de entrada
        else:
            print("Usuário errado")

    return render(request, 'login.html')
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from cadastros.models import Usuario
from django.contrib import messages
from django.http import JsonResponse
from django.core.mail import send_mail, EmailMessage
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.utils.crypto import get_random_string
from django.http import HttpResponse
from django.shortcuts import render, redirect
from cadastros.forms import UsuarioCreationForm
from django.contrib import messages
from django.core.cache import cache


def criar_usuario(request):
    if request.method == 'POST':
        form = UsuarioCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Usuário criado com sucesso!')
            return redirect('autenticacao:login')  # Redireciona para alguma página
    else:
        form = UsuarioCreationForm()

    return render(request, 'criar_usuario.html', {'form': form})


TOKENS = {}

def recuperar_senha(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = Usuario.objects.get(email=email)
            token = get_random_string(32)  # Gera um token aleatório
            cache.set(token, email, timeout=3600)  # Expira em 1 hora
            send_mail(
                'Recuperação de senha',
                f'Use este link para redefinir sua senha: '
                f'http://127.0.0.1:8000/resetar-senha/{token}/',
                'seuemail@exemplo.com',
                [email],
            )
            messages.success(request, 'E-mail enviado com sucesso.')
            return redirect('autenticacao:login')
        except Usuario.DoesNotExist:
            messages.error(request, 'E-mail não encontrado.')
            return redirect('autenticacao:login')

    return render(request, 'recuperar_senha.html')


def resetar_senha(request, token):
    if request.method == 'POST':
        nova_senha = request.POST.get('senha')
        email = cache.get(token)  # Recupera o e-mail associado ao token
        if email:
            try:
                user = Usuario.objects.get(email=email)
                user.password = make_password(nova_senha)
                user.save()
                cache.delete(token)  # Remove o token após o uso
                messages.success(request, 'Senha alterada com sucesso.')
                return redirect('autenticacao:login')
            except Usuario.DoesNotExist:
                messages.error(request, 'Usuário não encontrado.')
                return redirect('autenticacao:login')
        messages.error(request, 'Token inválido ou expirado.')
        return redirect('autenticacao:login')
    return render(request, 'resetar_senha.html', {'token': token})


def login(request):
    if request.method == 'POST':
        email = request.POST.get('txtEmail')
        senha = request.POST.get('txtSenha')
        perfil_id = request.POST.get('slcPerfil')

        usuario = authenticate(request, username=email, password=senha)

        if usuario is not None and perfil_id:
            perfis_usuario = usuario.perfis.filter(id=perfil_id)
            if perfis_usuario.exists():

                request.session.flush()
                auth_login(request, usuario)

                request.session['id_atual'] = usuario.id
                request.session['email_atual'] = usuario.email
                request.session['departamento_id_atual'] = usuario.departamento.id
                request.session['departamento_nome_atual'] = usuario.departamento.nome
                request.session['departamento_sigla_atual'] = usuario.departamento.sigla
                request.session['perfil_atual'] = perfis_usuario.first().nome
                request.session['perfis'] = list(usuario.perfis.values_list('nome',flat=True))
                request.session.set_expiry(14400)

                messages.success(request, 'Login realizado com sucesso!')

                if request.session.get('perfil_atual') in {'Administrador', 'Estoquista', 'Vendedor'}:
                    return redirect('core:main')
            else:
                messages.error(request, 'Perfil inválido!')
        else:
            if usuario is None:
                messages.error(request, 'Senha incorreta!')
            else:
                messages.error(request, 'Usuário ou Senha inválido!')

    return render(request, 'login.html')

def get_perfis(request):
    email = request.GET.get('email', '')
    perfis = []

    if Usuario.objects.filter(email=email).exists():
        usuario = Usuario.objects.get(email=email)
        perfis = usuario.perfis.all().values('id', 'nome')
        data = {'perfis': list(perfis), 'usuario_existe': True}
    else:
        data = {'usuario_existe': False}

    return JsonResponse(data)

def logout(request):
    request.session.flush()
    auth_logout(request)
    messages.success(request, 'Logout realizado com sucesso!')
    return redirect('autenticacao:login')

from django.urls import path
from . import views

app_name = 'autenticacao'

urlpatterns = [
    path('', views.login, name='login'),
    path('get_perfis/', views.get_perfis, name='get_perfis'),
    path('logout/', views.logout, name='logout'),
    path('recuperar-senha/', views.recuperar_senha, name='recuperar-senha'),
    path('resetar-senha/<str:token>/', views.resetar_senha, name='resetar-senha'),
    path('cadastro/', views.criar_usuario, name='cadastro_usuario'),
]
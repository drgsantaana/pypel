from django import forms
from .models import Usuario, Departamento, Perfil

class UsuarioCreationForm(forms.ModelForm):
    # Campos extras para facilitar a criação
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = Usuario
        fields = ['nome', 'email', 'password', 'is_active', 'is_admin', 'departamento', 'perfis']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Personalizar os widgets ou labels se necessário
        self.fields['perfis'].queryset = Perfil.objects.all()  # Exibe todos os perfis disponíveis
        self.fields['departamento'].queryset = Departamento.objects.all()  # Exibe todos os departamentos disponíveis

    def save(self, commit=True):
        usuario = super().save(commit=False)
        usuario.set_password(self.cleaned_data['password'])  # Criptografa a senha antes de salvar
        if commit:
            usuario.save()
        return usuario

from django.contrib.auth.forms import AuthenticationForm
from django_select2.forms import ModelSelect2Widget

from accounts.models import *
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _


class UserForm(forms.ModelForm):
    error_messages = {
        'duplicate_username': _("A user with that username already exists."),
        'password_mismatch': _("The two password fields didn't match."),
        'duplicate_email': _("A user with that email already exists."),
    }
    username = forms.RegexField(label=_("Username"), max_length=30,
        regex=r'^[\w.@+-]+$',
        help_text=_("Required. 30 characters or fewer. Letters, digits and "
                    "@/./+/-/_ only."),
        error_messages={
            'invalid': _("This value may contain only letters, numbers and "
                         "@/./+/-/_ characters.")})
    firstname = forms.CharField(widget=forms.TextInput)
    lastname = forms.CharField(widget=forms.TextInput)

    password1 = forms.CharField(label=_("Password"),
        widget=forms.PasswordInput)
    password2 = forms.CharField(label=_("Password confirmation"),
        widget=forms.PasswordInput,
        help_text=_("Enter the same password as above, for verification."))
    email = forms.CharField(widget=forms.EmailInput)

    def clean(self):
        return self.cleaned_data

    def clean_username(self):
        username = self.cleaned_data["username"]
        try:
            User._default_manager.get(username=username)
            raise forms.ValidationError(
            self.error_messages['duplicate_username'],
            code='duplicate_username',
            )
        except User.DoesNotExist:
            return username

    def clean_email(self):
        # Since User.username is unique, this check is redundant,
        # but it sets a nicer error message than the ORM. See #13147.
        email = self.cleaned_data["email"]
        try:
            User._default_manager.get(email=email)
        except User.DoesNotExist:
            return email
        raise forms.ValidationError(
            self.error_messages['duplicate_email'],
            code='duplicate_email',
        )

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2

    class Meta:
        exclude = ('user',)
        model = UserProfile
        fields = ['username', 'firstname', 'lastname', 'password1', 'password2', 'email', 'address', 'mobile','city','is_active','role',]



class AuthLogin(AuthenticationForm):

    def clean(self):
        super(AuthLogin,self).clean()
        username = self.cleaned_data.get('username')

        if not self.errors:
            try:
                user = User.objects.get(username__iexact=username)
                if not user.is_staff:
                    raise forms.ValidationError(_('You have not permission to login.'))
                if user.username != username:
                    raise forms.ValidationError(_('Username/Password is case sensitive.'))
            except User.DoesNotExist:
                raise ValidationError(
                        self.error_messages['invalid_login'],
                        code='invalid_login',
                        params={'username': self.username_field.verbose_name},
                    )

        return self.cleaned_data


class UserprofileForm(forms.ModelForm):
    error_messages = {
        'duplicate_username': _("A user with that username already exists."),
        'password_mismatch': _("The two password fields didn't match."),
        'duplicate_email': _("A user with that email already exists."),
    }
    username = forms.RegexField(label=_("Username"), max_length=30,
        regex=r'^[\w.@+-]+$',
        help_text=_("Required. 30 characters or fewer. Letters, digits and "
                    "@/./+/-/_ only."),
        error_messages={
            'invalid': _("This value may contain only letters, numbers and "
                         "@/./+/-/_ characters.")})
    password1 = forms.CharField(label=_("Password"),
        widget=forms.PasswordInput)
    password2 = forms.CharField(label=_("Password confirmation"),
        widget=forms.PasswordInput,
        help_text=_("Enter the same password as above, for verification."))
    email = forms.CharField(widget=forms.EmailInput)

    def clean(self):
        return self.cleaned_data

    def clean_username(self):
        username = self.cleaned_data["username"]
        try:
            User._default_manager.get(username=username)
            raise forms.ValidationError(
            self.error_messages['duplicate_username'],
            code='duplicate_username',
            )
        except User.DoesNotExist:
            return username


    def clean_email(self):
        # Since User.username is unique, this check is redundant,
        # but it sets a nicer error message than the ORM. See #13147.
        email = self.cleaned_data["email"]
        try:
            User._default_manager.get(email=email)
        except User.DoesNotExist:
            return email
        raise forms.ValidationError(
            self.error_messages['duplicate_email'],
            code='duplicate_email',
        )

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2



    class Meta:
        exclude = ('user',)
        model = UserProfile
        fields = ['username', 'password1','password2','email',
                  'address','city','mobile']


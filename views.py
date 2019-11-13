from django.contrib import messages
from django.contrib.auth.forms import PasswordChangeForm
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import permission_required, user_passes_test, login_required
from django.views.generic.base import View
from django.views.generic import FormView
from django.contrib.auth import REDIRECT_FIELD_NAME, logout, update_session_auth_hash
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import resolve_url, render
from django.template.response import TemplateResponse
from django.utils.http import is_safe_url
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.contrib.auth import (login as auth_login)
from django.views.generic import (ListView, CreateView, UpdateView,TemplateView)
from django.utils.translation import ugettext as _
from accounts.forms import *
from qworky import settings
from django.forms.models import inlineformset_factory
from qworky.settings import LOGIN_URL
from django.urls import reverse, reverse_lazy
from . forms import *


@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request, template_name='login.html',redirect_field_name=REDIRECT_FIELD_NAME,authentication_form=AuthLogin,extra_context=None):
    """
    Displays the login form and handles the login action.
    """
    redirect_to = request.POST.get(redirect_field_name,
                                   request.GET.get(redirect_field_name, ''))

    if request.method == "POST":
        form = authentication_form(request, data=request.POST)
        if form.is_valid():

            # Ensure the user-originating redirection url is safe.
            if not is_safe_url(url=redirect_to, allowed_hosts=request.get_host()):
                redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)

            # Okay, security check complete. Log the user in.
            auth_login(request, form.get_user())

            return HttpResponseRedirect(redirect_to)
    else:
        form = authentication_form(request)

    current_site = get_current_site(request)

    context = {
        'form': form,
        redirect_field_name: redirect_to,
        'site': current_site,
        'site_name': current_site.name,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context)


def Ulogout(request):
    logout(request)
    messages.success(request, 'You have been logged out!.')
    return HttpResponseRedirect('/qworky/login/')


def password_change(request,
                    template_name='change_password_form.html',
                    post_change_redirect='/qworky/password/change/done/',
                    password_change_form=PasswordChangeForm,
                    current_app=None, extra_context=None):
    if post_change_redirect is None:
        post_change_redirect = reverse('password_change_done')
    else:
        post_change_redirect = resolve_url(post_change_redirect)
    if request.method == "POST":
        form = password_change_form(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()

            update_session_auth_hash(request, form.user)
            return HttpResponseRedirect(post_change_redirect)
    else:
        form = password_change_form(user=request.user)
    context = {
        'form': form,
        'title': _('Password change'),
    }
    if extra_context is not None:
        context.update(extra_context)

    if current_app is not None:
        request.current_app = current_app

    return TemplateResponse(request, template_name, context)

class AddUserProfile(FormView):
    @method_decorator(user_passes_test(lambda u: u.is_superuser, login_url=LOGIN_URL))
    def dispatch(self, *args, **kwargs):
        return super(AddUserProfile, self).dispatch(*args, **kwargs)
    login_required = True
    form_class =  UserForm
    template_name = 'user_form.html'

    def form_valid(self, form):
        if form.is_valid :
            user = User()
            user.username = self.request.POST.get('username')
            user.set_password(self.request.POST['password1'])
            user.email = self.request.POST['email']
            user.first_name = self.request.POST['firstname']
            user.last_name = self.request.POST['lastname']
            user.is_superuser=False
            user.save()
            userprofile = form.save(commit=False)
            userprofile.user = user
            if str(userprofile.role).lower() != 'client':
                print(userprofile.role)
                user.is_staff = True
                user.save()
            else:
                userprofile.user.is_staff = False
                user.save()
            userprofile.save()
            messages.success(self.request,'Successfully Added')
        return HttpResponseRedirect('/qworky/UserList/')

class UserUpdate(UpdateView):
    form_class = UserForm
    model = UserProfile
    template_name = 'user_form.html'
    success_url = '/qworky/UserList'

    def form_valid(self, form):
        user_pro = form.instance()
        user_pro.user.username = form.username
        user_pro.user.first_name = form.first_name
        user_pro.user.last_name = form.last_name
        user_pro.user.email = form.email
        return super(UserUpdateView, self).form_valid(form)

def password_change_done(request):
    logout(request)
    messages.success(request, 'Password change successful.')
    return HttpResponseRedirect('/qworky/login/')

def home(request):
    return render(request, 'homepage.html')


class UserList(ListView):
    model = UserProfile
    template_name = 'user_list.html'

class RoleList(ListView):
    model = Role
    template_name = 'role_list.html'


class AddRole(CreateView):
    model = Role
    fields = '__all__'
    template_name = 'role_form.html'
    success_url = '/qworky/RoleList'


class RoleAction(View):
    def get(self,request,id=None):
        print(id)
        role = Role.objects.get(id=id)
        role.delete()
        data = {
            'delete': True
        }
        return JsonResponse(data)

    def post(self, request,id=None):
        print(id)
        name = request.POST['role']
        role = Role.objects.get(id=id)
        role.name = name.upper()
        role.save()
        return JsonResponse({'status': True})

@login_required
def UserDeleteView(request,pk):
    uprofile = UserProfile.objects.get(id=pk)
    uprofile.delete()
    return HttpResponseRedirect(reverse('/qworky/UserList'))

class CabinListView(ListView):
    template_name = 'cabin_list.html'
    model = Cabin

class CabinCreateView(CreateView):
    fields = ('centre','code','type','price'.'choices')
    model = Cabin
    template_name = 'cabin_form.html'
    success_url = reverse_lazy("accounts:CabinList")


class CabinUpdateView(UpdateView):
    fields = ('centre', 'code', 'type','price','choices')
    model = Cabin
    template_name = 'cabin_form.html'
    success_url = reverse_lazy("accounts:CabinList")


class PremisesCreateView(CreateView):
    fields = ('address', 'incharge', 'city')
    model = Premises
    template_name = 'premises_form.html'
    success_url = reverse_lazy("accounts:Premiseslist")

def CabinDeleteView(request,pk):
    cabin = Cabin.objects.get(id=pk)
    cabin.delete()
    return HttpResponseRedirect(reverse('accounts:CabinList'))


class PremisesListView(ListView):
    model = Premises
    template_name = 'premises_list.html'


class PremisesUpdateView(UpdateView):
    fields = ('address', 'incharge', 'city')
    model = Premises
    template_name = 'premises_form.html'
    success_url = reverse_lazy("accounts:Premiseslist")

def PremisesDeleteView(request,pk):
    uprofile = Premises.objects.get(id=pk)
    uprofile.delete()
    return HttpResponseRedirect(reverse('accounts:Premiseslist'))








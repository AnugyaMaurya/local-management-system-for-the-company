from django.contrib import admin
from .models import *
from django.contrib.auth.models import User
# Register your models here.
#checking pull

admin.site.register(UserProfile)
admin.site.register(Role)
admin.site.register(Premises)

admin.site.register(Cabin)
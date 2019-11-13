import os
from django.contrib.auth.models import User
from django.core.validators import RegexValidator
from django.db import models
from django.utils.timezone import now
from django.template.defaultfilters import slugify
import random
from django.contrib.auth.models import UserManager

def get_upload_path(instance, filename):
    return os.path.join('user/image/', now().date().strftime("%Y/%m/%d"), filename)

# Create your models here.
phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$',message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")


class Role(models.Model):
    name = models.CharField(max_length=200,unique=True)
    def __str__(self):
        return self.name

class Type(models.Model):
    name = models.CharField(max_length=200)


class UserProfile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    mobile = models.CharField(validators=[phone_regex], max_length=17, null=True,blank=True)
    address = models.CharField(max_length=255,null=True,blank=True)
    city = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    slug = models.SlugField(unique=False, blank=True)

    def save(self, *args, **kwargs):
        self.slug = slugify(self.user)
        super(UserProfile, self).save(*args, **kwargs)


class Premises(models.Model):
    address = models.CharField(max_length=255,unique=True,null=True,blank=True)
    city = models.CharField(max_length=100)
    incharge = models.ForeignKey(User, on_delete=models.CASCADE)
    slug = models.SlugField(unique=False, blank=True)

    def save(self, *args, **kwargs):
        self.slug = slugify(self.address)
        super(Premises, self).save(*args, **kwargs)
    def __str__(self):
        return self.address

def unique_rand():
    while True:
        code = Cabin.objects.make_random_password(length=6, allowed_chars="1234567890")
        if not Cabin.objects.filter(code=code).exists():
            return code

Choice = (
    ('workstation', 'WORKSTAION'),
    ('cabin', 'CABIN'),
    ('conference', 'CONFERENCE'),


class Cabin(models.Model):
    centre = models.ForeignKey(Premises, on_delete=models.CASCADE)
    code = models.CharField(max_length=255, unique=True,default=unique_rand)
    type = models.ForeignKey(Role, on_delete=models.CASCADE)
    price = models.CharField(max_length=100)
    choices=models.CharField(max_length=50, choices=Choice)

    slug = models.SlugField(unique=False, blank=True)
    objects = UserManager()

    def save(self, *args, **kwargs):
        self.slug = slugify(self.centre)
        super(Cabin, self).save(*args, **kwargs)

    def __str__(self):
        return self.code



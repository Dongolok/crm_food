from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.conf import settings
from datetime import datetime, timedelta
import jwt


class Roles(models.Model):
    ROLES_CHOICES = [(1, 'Waiter'),
                     (2, 'Admin'),
                     (3, 'Chef')]
    name = models.IntegerField(choices=ROLES_CHOICES)

    def __str__(self):
        return '%s' % self.name


class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None, **kwargs):
        if username is None:
            raise ValueError('User must have a username')
        if email is None:
            raise ValueError('Users must have email')

        user = self.model(username=username,
                          email=self.normalize_email(email),
                          **kwargs
                          )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password, **kwargs):
        if password is None:
            raise ValueError('Users must have password')

        user = self.create_user(username=username,
                                password=password,
                                email=self.normalize_email(email),
                                **kwargs
                                )
        user.is_superuser = True
        user.is_staff = True
        user.is_admin = True
        user.save(using=self._db)
        return user


class Users(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(max_length=120, unique=True, default='some name')
    surname = models.CharField(max_length=120)
    email = models.EmailField(max_length=120, unique=True)
    password = models.CharField(max_length=1000, default=1234, blank=False, null=False)
    role = models.ForeignKey(Roles, on_delete=models.CASCADE, default='3')
    phone = models.CharField(max_length=120)
    date = models.DateTimeField(auto_now_add=True, null=True)
    username = models.CharField(max_length=100, unique=True, blank=False)
    REQUIRED_FIELDS = ['name', 'surname', 'email', 'password', 'phone']
    USERNAME_FIELD = 'username'
    objects = UserManager()
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    def __str__(self):
        return self.surname

    @property
    def token(self):
        return self._generate_jwt_token()

    def _generate_jwt_token(self):
        day = datetime.datetime.now() + timedelta(days=60)

        token = jwt.encode({
            'id': self.pk,
            'exp': int(day.strftime('%s'))
        }, settings.SECRET_KEY, algorithm='HS256')

        return token.decode('utf-8')

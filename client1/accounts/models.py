from django.db import models
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session


# Create your models here.
class AccessInfo(models.Model):
	session = models.ForeignKey(Session, on_delete=models.CASCADE)
	access_token = models.CharField(max_length=500)
from django.db import models

class RSAKeyPair(models.Model):
    private_key = models.TextField()
    public_key = models.TextField()
    password = models.CharField(max_length=50)
    timestamp = models.DateTimeField(auto_now_add = True, auto_now = False, blank = True)
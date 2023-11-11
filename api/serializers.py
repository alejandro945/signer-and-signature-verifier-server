
from rest_framework import serializers
from .models import RSAKeyPair

class RSAKeyPairSerializer(serializers.ModelSerializer):
    class Meta:
        model = RSAKeyPair
        fields = ['id', 'private_key', 'public_key', 'password', 'timestamp']
from rest_framework import serializers
from .models import VulnerabilitySignature

class VulnerabilitySignatureSerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilitySignature
        fields = '__all__'

from rest_framework import serializers
from django.utils import timezone

from signatures.models import Signatures


class SignaturesSerializer(serializers.ModelSerializer):
    last_modified = serializers.SerializerMethodField()

    def get_last_modified(self, Signatures):
        return timezone.localtime(Signatures.last_modified).strftime("%b %d, %Y %H:%M")

    class Meta:
        model = Signatures
        fields = '__all__'
        # lookup_field = 'scan_history'
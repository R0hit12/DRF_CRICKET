from rest_framework import serializers
from .models import *


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'role']
        extra_kwargs = {'password': {'write_only': True},
                        "id": {"read_only": True},
                        "role":{"read_only": True}}


class BlogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blog
        fields = ['id','author', 'title','description']
        read_only_fields = ['id','author']


class TeamSerializer(serializers.ModelSerializer):
    class Meta:
        model = Team
        fields = '__all__'


class PlayerSerializer(serializers.Serializer):
    class Meta:
        model = Player
        fields = '__all__'

class MatchSerializer(serializers.Serializer):
    class Meta:
        model = Match
        fields = "__all__"

class HighlightSerializer(serializers.Serializer):
    class Meta:
        model = MatchHighlight
        fields = []
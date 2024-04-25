from rest_framework import serializers
from .models import *


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'role']
        extra_kwargs = {'password': {'write_only': True},
                        "id": {"read_only": True},
                        "role": {"read_only": True}}


# class BlogSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Blog
#         fields = ['id', 'author', 'title', 'description']
#         read_only_fields = ['id', 'author']


class TeamSerializer(serializers.ModelSerializer):
    class Meta:
        model = Team
        fields = '__all__'


class PlayerSerializer(serializers.Serializer):
    class Meta:
        model = Player
        fields = '__all__'


class MatchSerializer(serializers.ModelSerializer):
    class Meta:
        model = Match
        fields = "__all__"



class MatchHighlightSerializer(serializers.ModelSerializer):
    match = serializers.PrimaryKeyRelatedField(queryset=Match.objects.all())
    highlight = serializers.FileField()
    uploaded_by = serializers.CharField(source='uploaded_by.username', read_only=True)  # Use 'uploaded_by.username' to get the username

    class Meta:
        model = MatchHighlight
        fields = ['match', 'uploaded_by', 'highlight', 'highlight_url', 'upload_date']

    def create(self, validated_data):
        user = self.context['request'].user
        highlight = validated_data['highlight']
        match = validated_data['match']


        # Fetch the existing Match instance based on match_id
        try:
            match_instance = Match.objects.get(id=match)
        except Match.DoesNotExist:
            raise serializers.ValidationError("Invalid match_id")  # Handle if match_id is not found

        # Create and save the MatchHighlight instance
        instance = MatchHighlight.objects.create(
            match=match_instance,
            highlight=highlight,
            uploaded_by=user
        )

        # Automatically set upload_date and highlight_url
        instance.save()
        return instance


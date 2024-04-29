from rest_framework import serializers
from rest_framework.serializers import ValidationError

from .models import *


class UserSerializer(serializers.ModelSerializer):
    role = serializers.CharField(source='role.roles', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'role']
        extra_kwargs = {'password': {'write_only': True},
                        "id": {"read_only": True},
                        "role": {"read_only": True}}


class PlayerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Player
        fields = ['id', 'player_name']


class TeamSerializer(serializers.ModelSerializer):
    team_players = serializers.SerializerMethodField()

    class Meta:
        model = Team
        fields = ['id', 'team_name', 'team_players']

    def get_team_players(self, obj):
        players = obj.team_players.all()
        return [player.player_name for player in players]


class MatchSerializer(serializers.ModelSerializer):
    is_upcoming = serializers.SerializerMethodField()
    team1 = serializers.CharField(source= "team1.team_name")
    team2 = serializers.CharField(source= "team2.team_name")

    class Meta:
        model = Match
        fields = "__all__"

    def get_is_upcoming(self, obj):
        return obj.match_date > timezone.now().date()


class MatchHighlightSerializer(serializers.ModelSerializer):
    match = serializers.PrimaryKeyRelatedField(queryset=Match.objects.all())
    highlight = serializers.FileField()
    testing = serializers.CharField(max_length=100)
    uploaded_by = serializers.CharField(source='uploaded_by.username',
                                        read_only=True)  # Use 'uploaded_by.username' to get the username
    like_count = serializers.SerializerMethodField()
    class Meta:
        model = MatchHighlight
        fields = ['id', 'match', 'uploaded_by', 'highlight', 'highlight_url', 'upload_date', 'active', 'testing','like_count','views']

    def get_like_count(self, obj):
        return obj.likes.count()
    def create(self, validated_data):
        user = self.context['request'].user
        highlight = validated_data['highlight']
        match = validated_data['match']
        testing = validated_data['testing']

        try:
            if user.role.roles not in ['Streamer', 'Superadmin']:  # Check if user has appropriate role
                raise ValidationError("You are not authorized to create highlights")
        except Exception as e:
            raise ValidationError("An error occurred: {}".format(str(e)))

        # Extract the primary key of the Match instance if it's an object
        if isinstance(match, Match):
            match_id = match.id
        else:
            match_id = match
        # Fetch the existing Match instance based on match_id
        try:
            match_instance = Match.objects.get(id=match_id)
        except Match.DoesNotExist:
            raise serializers.ValidationError("Invalid match_id")  # Handle if match_id is not found

        # Create and save the MatchHighlight instance
        instance = MatchHighlight.objects.create(
            match=match_instance,
            highlight=highlight,
            uploaded_by=user,
            testing=testing
        )

        # Automatically set upload_date and highlight_url and active
        instance.save()
        return instance

    def update(self, instance, validated_data):
        user = self.context['request'].user

        # Allow Streamer to update uploaded highlights fields except 'active'
        if user.role.roles == 'Streamer':

            if instance.uploaded_by != user:
                raise serializers.ValidationError("You are not author of this post")
            # Check if the 'active' field is present in validated_data
            if 'active' in validated_data:
                raise serializers.ValidationError("Streamers are not allowed to change the 'active' field")

            # Allow Streamer to update other fields
            instance.highlight = validated_data.get('highlight', instance.highlight)
            instance.testing = validated_data.get('testing', instance.testing)
            instance.save()
            return instance

        # Superadmin can update any field including 'active'
        elif user.role.roles == 'Superadmin':
            instance.highlight = validated_data.get('highlight', instance.highlight)
            instance.active = validated_data.get('active', instance.active)
            instance.testing = validated_data.get('testing', instance.testing)
            instance.save()
            return instance

        # Any other role is not allowed to update
        else:
            raise serializers.ValidationError("You don't have permission to perform this action")

    def to_representation(self, instance):
        request = self.context.get('request')
        if request and request.method == 'GET':
            # Check if the instance matches the requested primary key
            pk = request.parser_context['kwargs'].get('pk')
            if str(instance.pk) == pk:
                # Increment view count if it matches
                instance.views += 1
                instance.save()

        return super().to_representation(instance)
class HighlightLikeSerializer(serializers.ModelSerializer):
    liked_by = serializers.CharField(source='liked_by.username', read_only=True)

    class Meta:
        model = HighlightLike
        fields = '__all__'





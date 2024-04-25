import base64
import os
from rest_framework import exceptions
from django.conf import settings
from django.contrib.auth.models import Group
from django.core.mail import send_mail
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from .models import *
# from .serializers import UserSerializer, BlogSerializer, MatchHighlightSerializer
from user.serializers import *
import pyotp

from .permissions import IsSuperAdminOrReadOnly


class UserRegistrationView(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        print(password, "password")

        user = authenticate(username=username, password=password)
        print(user, "====================================")
        if user is not None:
            # Authentication successful, generate or retrieve token
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key})
        else:
            # Authentication failed
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class UserChangePasswordView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):

        user = request.user
        print(user)
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        print(old_password, "\n", new_password, '--------------')
        if not old_password or not new_password:
            return Response({'error': 'Both old_password and new_password are required'},
                            status=status.HTTP_400_BAD_REQUEST)
        if not user.check_password(old_password):
            return Response({'error': 'Invalid old password'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password changed successfully'})


class UserResetPasswordInitiate(APIView):

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')

        if not username or not email:
            return Response({
                'error': 'username and email are required'},
                status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(username=username, email=email)
        except User.DoesNotExist:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_400_BAD_REQUEST)

        otp = self.generate_otp()
        user.otp = otp
        user.save()

        self.send_otp_email(user)

        return Response({'message': "OTP SENT SUCCESSFULLY"})

    def generate_otp(self):
        # Generate a secret key of 160 bits (20 bytes)
        secret = base64.b32encode(os.urandom(20)).decode('utf-8')
        otp = pyotp.TOTP(secret, digits=6).now()
        return otp

    def send_otp_email(self, user):
        # Send OTP to user's email using Django's configured email settings
        subject = 'Password Reset OTP'
        message = f'Your OTP for password reset is: {user.otp}'
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [user.email]

        try:
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
        except Exception as e:
            # Handle email sending failure
            return Response({'error': 'Failed to send OTP email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserResetPasswordView(APIView):

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        email = request.data.get('email')
        enter_otp = request.data.get('otp')
        new_password = request.data.get('new_password')

        if not username or not email or not enter_otp or not new_password:
            return Response({'error': 'username, email,otp and new_password are required'},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(username=username, email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found with provided username and email'},
                            status=status.HTTP_404_NOT_FOUND)

        if user.otp != enter_otp:
            return Response({'error': 'Invalid otp'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.otp = None
        user.save()

        return Response({'message': 'Password reset successfully'})


class RolesAssignment(APIView):
    serializer_class = UserSerializer
    permission_classes = [IsSuperAdminOrReadOnly]

    def post(self, request, *args, **kwargs):
        # Check if requesting user is authenticated
        if not request.user.is_authenticated:
            return Response({"message": "User not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)

        # Check if requesting user has a valid role assigned
        if not hasattr(request.user, 'role'):
            return Response({"message": "User has no role assigned"}, status=status.HTTP_403_FORBIDDEN)

        # Assuming request.user.role is a ForeignKey to the Roles model
        if request.user.role.roles != 'Superadmin':
            return Response({"message": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        # Proceed with assigning roles to other users
        username = request.data.get('username')
        email = request.data.get('email')
        roles = request.data.get('roles')

        try:
            user_to_assign_role = User.objects.get(username=username, email=email)
        except User.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            role = Roles.objects.get(roles=roles)
        except Roles.DoesNotExist:
            return Response({"message": "Role not found"}, status=status.HTTP_404_NOT_FOUND)

        # Update or create the user's profile with the assigned role
        user_to_assign_role.role = role  # Assign the new role
        user_to_assign_role.save()

        # Optionally, serialize and return the updated user's data
        serialized_user = self.serializer_class(user_to_assign_role).data
        return Response(serialized_user, status=status.HTTP_200_OK)



class HighlightsviewSet(ModelViewSet):
    queryset = MatchHighlight.objects.all()
    serializer_class = MatchHighlightSerializer


class MatchViewSet(ModelViewSet):
    queryset = Match.objects.all()
    serializer_class = MatchSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        """
        Override method to apply different permissions based on the request method.
        """
        if self.request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            # Restrict CRUD operations based on user role using custom permission class
            return [IsSuperAdminOrReadOnly()]
        return super().get_permissions()

    def handle_exception(self, exc):
        """
        Custom exception handler to return proper error responses.
        """
        if isinstance(exc, exceptions.PermissionDenied):
            # Return 403 Forbidden with detailed error message
            return Response({"detail": str(exc)}, status=403)
        return super().handle_exception(exc)

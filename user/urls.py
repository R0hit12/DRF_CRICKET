from django.urls import path, include
from rest_framework import routers
from.views import *

router = routers.DefaultRouter()
router.register(r'users', UserRegistrationView, basename='users')
# router.register(r'login', UserLoginView, basename='login')
# router.register(r'change-password', UserChangePasswordView, basename='change-password')
router.register(r'highlights', HighlightsviewSet, basename='highlights')
# router.register(r'blog', BlogView, basename='blog')
router.register(r'match', MatchViewSet, basename= 'match')

urlpatterns = [
    path('', include(router.urls)),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('change-password/' ,UserChangePasswordView.as_view(), name = 'pass-change'),
    path('reset-password/', UserResetPasswordView.as_view(), name = 'reset'),
    path("role_assign/", RolesAssignment.as_view(), name = 'role-assignment'),
    path('passresetini/', UserResetPasswordInitiate.as_view(), name='passresetini')
]
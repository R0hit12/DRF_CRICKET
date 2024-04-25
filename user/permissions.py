from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied




class IsSuperAdminOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True  # Allow read-only permissions for GET requests
        user_role = request.user.role
        return request.user.is_authenticated and user_role.roles == 'Superadmin'

    def has_object_permission(self, request, view, obj):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True  # Allow read-only permissions for GET requests
        user_role = request.user.role
        return request.user.is_authenticated and user_role.roles == 'Superadmin'

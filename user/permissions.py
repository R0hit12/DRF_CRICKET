from rest_framework import permissions

class IsSuperAdminOrReadOnly(permissions.BasePermission):
    """
    Custom permission to allow superadmins to perform any actions,
    but restrict others to read-only (GET, HEAD, OPTIONS) operations.
    """
    def has_permission(self, request, view):
        # Allow superadmins full access, restrict others to read-only
        return request.user.role.roles == 'superadmin' if request.user.role else False

class IsStreamerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to allow streamers to create, update, and view their own blogs,
    but restrict others to read-only (GET, HEAD, OPTIONS) operations.
    """
    def has_permission(self, request, view):
        # Allow streamers to perform actions on their own blogs, restrict others to read-only
        return request.user.role.roles == 'streamer' if request.user.role else False

    def has_object_permission(self, request, view, obj):
        # Allow streamers to perform actions on their own blogs
        return obj.author == request.user  # Assuming `author` is the user who created the blog

class IsViewer(permissions.BasePermission):
    """
    Custom permission to allow viewers read-only access to all blogs.
    """
    def has_permission(self, request, view):
        # Allow viewers read-only access
        return request.user.role.roles == 'viewer' if request.user.role else False

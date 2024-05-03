from django.urls import path
from .views import *

urlpatterns = [
    path('stream/', stream_completions, name='stream_view'),
]
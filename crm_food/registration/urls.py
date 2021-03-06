from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from .views import authenticate_user, RegistrationAPIView

app_name = 'registration'
urlpatterns = [
    # path('login/', authenticate_user),
    path('register/', RegistrationAPIView.as_view()),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

]

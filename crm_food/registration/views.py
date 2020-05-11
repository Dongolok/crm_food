from django.contrib.auth import user_logged_in
from rest_framework.decorators import *
from rest_framework.permissions import AllowAny
from .models import Users
from rest_framework import settings
import jwt
from rest_framework import status
from rest_framework.status import *
from rest_framework.response import Response
from rest_framework.settings import api_settings
from .serializers import *
from rest_framework.renderers import JSONRenderer
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import Token


class RegistrationAPIView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = UsersRegistrationSerializer
    # renderer_classes = (JSONRenderer,)

    def post(self, request):
        user = request.data.get('user', {})

        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def authenticate_user(request):
    username = request.data.get("username")
    password = request.data.get("password")

    if username is None or password is None:
        return Response({'error': 'Please provide both username and password'},
                        status=HTTP_400_BAD_REQUEST)
    user = authenticate(username=username, password=password)
    if not user:
        return Response({'error': 'Invalid Credentials'},
                        status=HTTP_404_NOT_FOUND)
    token, created = Token.objects.get_or_create(user=user)
    return Response({'token': token.key},
                    status=HTTP_200_OK)

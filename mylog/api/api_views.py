from http import HTTPStatus
from django.contrib.auth import login
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from knox.models import AuthToken
from knox.views import LoginView as KnoxLoginView
from rest_framework.authentication import SessionAuthentication
from rest_framework.generics import ListAPIView, CreateAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from mylog.api.serializers import (
    LoginSerializer, RegisterSerializer,
    UpdateSerializer, UserSerializer, AddTaskSerializer,
    CreateLogSerializer, ProjectSerializer
)
from mylog.models import CustomUser

# API based views


class RegisterApiView(APIView):
    """
    ## Create user Endpoint: /register/  ##
    ## Payload ##
        {
            "username": "test_1",
            "first_name": "test_1",
            "last_name": "test_surname",
            "email": "test_1@gmail.com",
            "password": 12345
        }
    ## Response ##
        {
            "Registered user": {
                "id": 60,
                "username": "test_1",
                "first_name": "test_1",
                "last_name": "test_surname",
                "email": "test_1@gmail.com",
                "password": "pbkdf2_sha256$390000$k23aixSZ9hNQbbBFeHslVv$llgi8h8J6iv20sdI0HpZTCH/nDrXgDr0mlP/uqz6mPY="
            },
            "token": "1875bebec2d0146786d9f4c72539cbe8ba098e7d22eb61bffc478fbabae1e296"
        }
    """
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = AuthToken.objects.create(user)[1]
            return Response({'Registered user': serializer.data, 'token': token}, status=HTTPStatus.CREATED)
        return Response({'error': serializer.errors})


class UpdateApiView(APIView):
    """
    ## Change User Endpoint:  update/<int:pk>/  ##
    *Request
    Method: PUT
    ## payload ##
    {
        "username": "user80",
        "first_name": "user80",
        "last_name": "jose"
    }
    ## Response ##
    {
        "username": "user80",
        "first_name": "user80",
        "last_name": "jose"
    }
    """
    def put(self, request, pk=None):
        """
        for updating user data with fields passed into serializer class
        if want to update data partially simply define patch method 
        and add partial=True into serializer.
        but if you use UpdateApiView it will have both put, patch method, so you do not need to write this explicit.
        """
        data = request.data
        user = CustomUser.objects.get(id=pk)
        serializer = UpdateSerializer(user, data=data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=HTTPStatus.OK)
        return Response({"Error": serializer.errors})


class LoginApiView(KnoxLoginView):
    """
    ## Login user Endpoint: user/login/ ##
    ## Payload ##
        {
            "email": "test_12@gmail.com",
            "password": 12345
        }
    ## Response ##
        {
            "Successfully Login": {
                "email": "test_12@gmail.com",
                "password": "12345"
            }
        }

    """
    permission_classes = (AllowAny, )

    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            login(request, user)
            return Response({'Successfully Login': serializer.data}, status=HTTPStatus.OK)
        return Response(serializer.errors, status=HTTPStatus.FORBIDDEN)


class ListApiView(ListAPIView):
    permission_classes = [IsAdminUser]
    authentication_classes = [SessionAuthentication]
    """
    ## User List Endpoint ##
    ## headers : Token 1875bebec2d0146786d9f4c72539cbe8ba098e7d22eb61bffc478fbabae1e296 ##
    ## Response ##
    {
    "count": 3,
    "next": null,
    "previous": null,
        "results": [
            {
                "id": 3,
                "username": "admin",
                "first_name": "",
                "last_name": "",
                "email": "admin@gmail.com"
            },
            {
                "id": 31,
                "username": "test_1",
                "first_name": "test_1",
                "last_name": "test_surname",
                "email": "test_1@gmail.com"
            },
            {
                "id": 32,
                "username": "test_123",
                "first_name": "test_123",
                "last_name": "test_surname",
                "email": "test_12@gmail.com"
            }
        ]
    }
    """
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer


class AddTaskApiView(CreateAPIView):
    """
    ## create bulk task view endpoint : /task/ ##
    ## payload ##
        [
            {
                "project": "44",
                "title": "Implement List Serializer"
            },
            {
                "project": "1",
                "title": "Django signals"
            }
        ]
    ## Response ##
        [
            {
                "id": 26,
                "project": 44,
                "title": "Implement List Serializer"
            },
            {
                "id": 27,
                "project": 1,
                "title": "Django signals"
            }
        ]

    """
    # permission_classes = [IsAdminUser]
    # authentication_classes = []
    serializer_class = AddTaskSerializer

    def get_serializer(self, *args, **kwargs):
        if "data" in kwargs:
            data = kwargs["data"]
            if isinstance(data, list):
                kwargs["many"] = True
        return super(AddTaskApiView, self).get_serializer(*args, **kwargs)


class ProjectApiView(CreateAPIView):
    """
    ## Create bulk of project endpoint: /project/ ##
    ## Payload ##
        {
        "name": "e-commerece"
        }
    ## Response ##
        {
            "Project created": {
                "id": 48,
                "name": "e-commerece"
            }
        }
    """
    serializer_class = ProjectSerializer

    def post(self, request, *args, **kwargs):
        serializer = ProjectSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'Project created': serializer.data}, status=HTTPStatus.CREATED)
        return Response({'Errors': serializer.errors}, status=HTTPStatus.BAD_REQUEST)


class CreateDailyLogApiView(CreateAPIView):
    """
    ## Create Daily Log Api endpoint : /create/log/  ##
    ## Payload ##
    params : [
                {
                    "user": "60",
                    "date": "2023-02-22",
                    "project_name": "43",
                    "task": "23",
                    "description": "create it for project and user daily logs",
                    "start_time": "05:34:40",
                    "end_time": "07:34:40"
                },
                {
                    "user": "70",
                    "date": "2023-02-22",
                    "project_name": "43",
                    "task": "23",
                    "description": "Performed it.",
                    "start_time": "12:34:40",
                    "end_time": "5:34:40"
                }
            ]

    headers : Token 1875bebec2d0146786d9f4c72539cbe8ba098e7d22eb61bffc478fbabae1e296
    ## Response ##
        [
            {
                "id": 7,
                "user": 60,
                "date": "2023-02-22",
                "project_name": 43,
                "task": 23,
                "description": "create it for project and user daily logs",
                "start_time": "05:34:40",
                "end_time": "07:34:40"
            },
            {
                "id": 8,
                "user": 70,
                "date": "2023-02-22",
                "project_name": 43,
                "task": 23,
                "description": "Performed it.",
                "start_time": "12:34:40",
                "end_time": "05:34:40"
            }
        ]
    """
    permission_classes = [IsAuthenticated]
    serializer_class = CreateLogSerializer

    def get_serializer(self, *args, **kwargs):
        """ for many=True as have to create multiple objects."""
        if "data" in kwargs:
            data = kwargs['data']
            if isinstance(data, list):
                kwargs['many'] = True
        return super(CreateDailyLogApiView, self).get_serializer(*args, **kwargs)


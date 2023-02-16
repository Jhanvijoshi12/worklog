import csv
import datetime
from http import HTTPStatus
from django.contrib import messages
from django.contrib.auth import login, logout
from django.core.paginator import Paginator
from django.core.validators import EMPTY_VALUES
from django.http import HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from knox.models import AuthToken
from knox.views import LoginView
from rest_framework import permissions, status
from rest_framework.decorators import api_view
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from mylog.api.serializers import (
    LoginSerializer, UserLogSerializer, RegisterSerializer,
    ListUserSerializer, TaskSerializer, ProjectSerializer,
    UserDailyLogListSerializer, UpdateSerializer, UserSerializer,
)
from mylog.constants import (
    USER_CREATED, USER_LOGIN,
    INVALID_LOGIN_CREDENTIAL, USER_LOG_CREATED,
    INVALID_DETAILS, DAILY_LOG_CSV_COLUMNS, LOGIN_REQUIRED, UNAUTHORIZED_USER
)
from mylog.jobs import send_email_to_user
from mylog.models import UserDailyLogs, Project, Task, CustomUser


class GetOptionView(APIView):
    """ class when admin login, can see options to create project, task
    and user's list view ."""
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'admin_option.html'

    def get(self, request):
        serializer = TaskSerializer()
        if request.user.is_authenticated:
            if request.user.groups.filter(name='Admin').exists():
                return Response({'serializer': serializer, 'style': serializer.style})
            return Response({'status': 'failed', 'errors': UNAUTHORIZED_USER,
                             'style': serializer.style}, template_name='error.html')
        return Response({'status': 'failed', 'errors': LOGIN_REQUIRED,
                         'style': serializer.style}, template_name='401_error_page.html')


class RegistrationView(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'register.html'

    def get(self, request):
        serializer = RegisterSerializer()
        if request.user.is_authenticated:
            return redirect(reverse('mylog:daily_log'))
        return Response({'serializer': serializer, 'style': serializer.style})

    def post(self, request, format=None):
        serializer = RegisterSerializer(data=request.data)  # serializer obj and send parsed data
        data = {
            'username': request.data['username'],
            'email': request.data['email']
        }
        if serializer.is_valid():
            serializer.save()
            # for sending email to register user.
            send_email_to_user.delay(
                data['email'], data, request.scheme, request.get_host()
            )
            messages.success(self.request, USER_CREATED)
            return redirect(reverse('mylog:login'))
        else:
            errors = serializer.errors
            return Response({'serializer': serializer, 'errors': errors, 'style': serializer.style},
                            template_name='register.html')


class UserLoginView(LoginView):
    """
    user login view
    """
    permission_classes = (permissions.AllowAny, )
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'login.html'

    def get(self, request):
        serializer = LoginSerializer()
        return Response({'serializer': serializer, 'style': serializer.style})

    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data, context={'request': request})
        try:
            serializer.is_valid()
            if 'user' in serializer.validated_data:
                user = serializer.validated_data['user']
                login(request, user)
                _, token = AuthToken.objects.create(user)
                messages.success(self.request, USER_LOGIN)
                if request.user.groups.filter(name="Admin").exists():
                    Response({'user': user, 'token': token})
                    return redirect('mylog:get_admin_option')
                elif request.user.groups.filter(name="Software Engineer").exists():
                    return redirect('mylog:daily_log')
                return redirect(reverse('mylog:daily_log'))
            messages.error(self.request, INVALID_LOGIN_CREDENTIAL)
            return redirect(reverse('mylog:login'))
        except Exception as e:
            errors = serializer.errors
            return Response({'status': 'failed', 'errors': errors, 'style': serializer.style},
                            template_name='login.html')


class LogoutView(APIView):
    """ this class is for logout view """
    def post(self, request, format=None):
        logout(request)
        return redirect(reverse('mylog:login'))


class DashBoardView(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'dashboard.html'

    def get(self, request):
        user = request.user
        queryset = UserDailyLogs.objects.filter(user=user).last()
        serializer = ListUserSerializer(queryset)
        return Response({'serializer': serializer.data, 'style': serializer.style},
                        template_name='dashboard.html')


class UserDailyLogsView(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'daily_log_update.html'

    def get(self, request):
        serializer = UserLogSerializer()
        if request.user.is_authenticated:
            return Response({'serializer': serializer, 'style': serializer.style})
        return Response({'status': 'failed', 'errors': LOGIN_REQUIRED,
                         'style': serializer.style}, template_name='401_error_page.html')

    def post(self, request, *args, **kwargs):
        data = request.data.copy()
        data['user'] = request.user.id
        serializer = UserLogSerializer(data=data)
        if not request.user.is_authenticated:
            return redirect(reverse('mylog:login'))
        if serializer.is_valid():
            serializer.save()
            messages.success(self.request, USER_LOG_CREATED)
            return redirect('mylog:daily_log')
        else:
            errors = serializer.errors
            errors = {key.upper(): value for key, value in errors.items()}
            return Response({'serializer': serializer, 'errors': errors, 'style': serializer.style},
                            template_name='daily_log_update.html')


@api_view(['GET'])
def get_related_tasks(request):
    """ function for getting task from selected project name
    in daily log update
    returns: serialize data """
    project_id = request.GET.get('project_id')
    tasks = Task.objects.filter(project_id=project_id)
    serializer = TaskSerializer(tasks, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def get_task_details(request):
    """ function for get task from selected task field
    in daily log update
    returns: serialize data """
    task_id = request.GET.get('task_id')
    task = Task.objects.get(id=task_id)
    serializer = TaskSerializer(task)
    return Response(serializer.data)


class CreateProjectView(APIView):
    """ class for project creation """
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = ProjectSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'serializer': serializer.data}, status=HTTPStatus.CREATED)
        return Response({'error': serializer.errors}, status=HTTPStatus.BAD_REQUEST)


class CreateTaskView(APIView):
    """ class for task creation """
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'serializer': serializer.data}, status=HTTPStatus.CREATED)
        return Response({'error': serializer.errors}, status=HTTPStatus.BAD_REQUEST)


class ListUserView(ListAPIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'users_list.html'
    paginate_by = 10

    def get(self, request, *args, **kwargs):
        serializer = ListUserSerializer()
        if request.user.is_authenticated:
            page = self.request.GET.get('page')
            queryset = UserDailyLogs.objects.all()
            data = {
                'user': self.request.GET.get('user'),
                'project': self.request.GET.get('project'),
                'date': self.request.GET.get('date'),
                'create_csv': self.request.GET.get('create_csv')
            }

            if data['user'] or data['project'] or data['date'] or data['create_csv']:
                if data['date'] in EMPTY_VALUES:
                    date_obj = None
                else:
                    date_obj = datetime.datetime.strptime(data['date'], '%m/%d/%Y').date()
                # if filter applied to any of the below option.
                if data['user']:
                    queryset = queryset.filter(user__username__icontains=data['user'])
                if data['project']:
                    queryset = queryset.filter(project_name__name__icontains=data['user'])
                if date_obj:
                    queryset = queryset.filter(date=date_obj)
                # when click ond download csv this function is
                # called and if not and main queryset is returned
                if data['create_csv'] != 'False':
                    return self.create_csv_response(queryset, self.paginate_by)
                serializer = ListUserSerializer(queryset, many=True)
                paginator = Paginator(serializer.data, self.paginate_by)
                users = paginator.get_page(page)
                return Response({'users': users}, template_name='users_list.html')
            else:
                serializer = ListUserSerializer(queryset, many=True)
                paginator = Paginator(serializer.data, self.paginate_by)
                users = paginator.get_page(page)
                return Response({'users': users}, template_name='users_list.html')
        else:
            return Response({'status': 'failed', 'errors': LOGIN_REQUIRED,
                             'style': serializer.style}, template_name='401_error_page.html')

    def create_csv_response(self, queryset, paginate_by):
        """ function for creating csv file form queryset and
        filtered queryset. """
        serializer = ListUserSerializer(queryset, many=True)
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="daily_log.csv"'
        writer = csv.writer(response)
        writer.writerow(DAILY_LOG_CSV_COLUMNS)
        paginator = Paginator(serializer.data, paginate_by)
        page = self.request.GET.get('page')
        filtered_data = paginator.get_page(page)
        for row in filtered_data:
            writer.writerow(row.values())
        messages.success(self.request, "CSV file is created successfully!!")
        return response


class AddDailyLogView(APIView):
    permission_classes = [IsAuthenticated]
    """ class for add task manually"""

    def post(self, request, *args, **kwargs):
        project = request.data.get('project_name')
        task = request.data.get('task')
        description = request.data.get('description')
        start_time = request.data.get('start_time')
        end_time = request.data.get('end_time')
        date = request.data.get('date')
        project_obj = Project.objects.create(name=project)
        task_obj = Task.objects.create(project=project_obj, title=task)
        try:
            UserDailyLogs.objects.create(
                user=request.user, date=date, project_name=project_obj,
                task=task_obj, description=description,
                start_time=start_time, end_time=end_time
            )
            return Response({'message': USER_LOG_CREATED, 'status': status.HTTP_201_CREATED})
        except Exception as e:
            return Response({'message': INVALID_DETAILS, 'status': status.HTTP_400_BAD_REQUEST})


class UserDailyLogList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'user_daily_log_list.html'
    paginate_by = 5

    def get(self, request):
        serializer = UserDailyLogListSerializer()
        project = self.request.GET.get('project')
        if request.user.is_authenticated:
            user = request.user
            filter_queryset = UserDailyLogs.objects.filter(user=user)
            if project is not None:
                project_obj = Project.objects.filter(name__icontains=project).first()
                filter_queryset = filter_queryset.filter(project_name__id=project_obj.id)
            page = self.request.GET.get('page')
            serializer = UserDailyLogListSerializer(filter_queryset, many=True)
            paginator = Paginator(serializer.data, self.paginate_by)
            users = paginator.get_page(page)
            return Response({'users': users}, template_name='user_daily_log_list.html')
        return Response({'status': 'failed', 'errors': LOGIN_REQUIRED,
                         'style': serializer.style}, template_name='401_error_page.html')


# API based views
class RegisterApiView(APIView):
    # serializer_class = RegisterSerializer
    """
    ## Create user Endpoint: register/  ##
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
            "username": "test_1",
            "first_name": "test_1",
            "last_name": "test_surname",
            "email": "test_1@gmail.com",
            "password": "pbkdf2_sha256$390000$oK4yneA0BDn2MOFzgQirrq$vCOgwdp062yDWXwkLAi4mXu1o3AZzfoNOSLwEQwVkKY="
        }
    """
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=HTTPStatus.CREATED)
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


class LoginApiView(LoginView):
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
    """
    ## User List Endpoint ##
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

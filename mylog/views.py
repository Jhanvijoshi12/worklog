import csv
import datetime
from http import HTTPStatus

import requests
from django.contrib import messages
from django.contrib.auth import login, logout
from django.core.paginator import Paginator
from django.core.validators import EMPTY_VALUES
from django.http import HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from knox.models import AuthToken
from knox.views import LoginView
from rest_framework import permissions
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import api_view
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from mylog.api.serializers import (
    TaskSerializer, RegisterSerializer,
    LoginSerializer, ForgotPasswordSerializer,
    ResetPasswordSerializer, ListUserSerializer,
    UserLogSerializer, ProjectSerializer, UserDailyLogListSerializer
)
from mylog.constants import (
    UNAUTHORIZED_USER, LOGIN_REQUIRED, USER_CREATED,
    USER_LOGIN, INVALID_LOGIN_CREDENTIAL,
    USER_LOG_CREATED, DAILY_LOG_CSV_COLUMNS,
    INVALID_DETAILS, CHECK_EMAIL_MSG, ENTER_EMAIL_ERROR_MSG,
    PASSWORD_RESET_SUCCESSFUL, PASSWORD_ENTER_VALUE_ERROR
)
from mylog.jobs import send_email_to_user, send_reset_password_email
from mylog.models import CustomUser, UserDailyLogs, Task, Project


# Create your views here.

class GetOptionView(APIView):
    """ class when admin login, can see options to create project, task
    and user's list view ."""
    authentication_classes = [SessionAuthentication]
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
            user = serializer.save()
            # for sending email to register user.
            send_email_to_user.delay(
                data['email'], data, request.scheme, request.get_host()
            )
            messages.success(self.request, USER_CREATED)
            token = AuthToken.objects.create(user)[1]
            # for sending generated token into header because
            # when user tries to access another page it gives access.
            url = 'http://' + str(request.get_host()) + str((reverse('mylog:login')))
            headers = {'Authorization': 'Token ' + str(token)}
            response = requests.get(url, headers=headers)
            return redirect(response.url)
        else:
            return Response({'serializer': serializer, 'errors': serializer.errors,
                             'style': serializer.style}, template_name='register.html')


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
        serializer = LoginSerializer(data=request.data)
        try:
            serializer.is_valid()
            if 'user' in serializer.validated_data:
                user = serializer.validated_data['user']
                login(request, user)
                messages.success(self.request, USER_LOGIN)
                if request.user.groups.filter(name="Admin").exists():
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


class ForgotPasswordView(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'forgot_password.html'

    def get(self, request):
        serializer = ForgotPasswordSerializer()
        return Response({'serializer': serializer, 'style': serializer.style})

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        email = request.data['email']
        serializer.is_valid()
        if CustomUser.objects.filter(email=email).exists():
            user = CustomUser.objects.filter(email=email).last()
            if user:
                # send reset password mail to user when he/she
                # get the link for resting the password
                send_reset_password_email.delay(
                    email, user, request.scheme, request.get_host()
                )
                messages.success(self.request, CHECK_EMAIL_MSG)
                return redirect(reverse('mylog:forgot_password'))
            messages.error(self.request, ENTER_EMAIL_ERROR_MSG)
            return Response(serializer.errors, status=HTTPStatus.BAD_REQUEST)
        messages.error(self.request, ENTER_EMAIL_ERROR_MSG)
        return Response(serializer.errors, status=HTTPStatus.BAD_REQUEST)


class ResetPasswordView(APIView):
    authentication_classes = [SessionAuthentication]
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'reset_password.html'

    def get(self, request):
        serializer = ResetPasswordSerializer()
        return Response({"serializer": serializer, 'style': serializer.style})

    def post(self, request):
        """ method for reset password for user"""
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid()
        password = request.data['password']
        user = CustomUser.objects.filter(email=request.data['email']).last()
        if user and password:
            user.set_password(password)
            user.save()
            messages.success(self.request, PASSWORD_RESET_SUCCESSFUL)
            return redirect(reverse('mylog:login'))
        messages.error(self.request, PASSWORD_ENTER_VALUE_ERROR)
        return Response({'errors': serializer.errors, 'style': serializer.style},
                        template_name='reset_password.html')


class DashBoardView(APIView):
    authentication_classes = [SessionAuthentication]
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'dashboard.html'

    def get(self, request):
        user = request.user
        queryset = UserDailyLogs.objects.filter(user=user).last()
        serializer = ListUserSerializer(queryset)
        return Response({'serializer': serializer.data, 'style': serializer.style},
                        template_name='dashboard.html')


class UserDailyLogsView(APIView):
    authentication_classes = [SessionAuthentication]
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
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = ProjectSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'serializer': serializer.data}, status=HTTPStatus.CREATED)
        return Response({'error': serializer.errors}, status=HTTPStatus.BAD_REQUEST)


class CreateTaskView(APIView):
    """ class for task creation """
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'serializer': serializer.data}, status=HTTPStatus.CREATED)
        return Response({'error': serializer.errors}, status=HTTPStatus.BAD_REQUEST)


class ListUserView(ListAPIView):
    authentication_classes = [SessionAuthentication]
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
            return Response({'message': USER_LOG_CREATED, 'status': HTTPStatus.CREATED})
        except Exception as e:
            return Response({'message': INVALID_DETAILS, 'status': HTTPStatus.BAD_REQUEST})


class UserDailyLogList(APIView):
    authentication_classes = [SessionAuthentication]
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
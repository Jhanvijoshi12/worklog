from django.urls import path
from mylog.api.api_views import (
    UserLoginView, UserDailyLogsView,
    RegistrationView, ListUserView,
    AddDailyLogView, GetOptionView, CreateTaskView,
    CreateProjectView, LogoutView, UserDailyLogList, get_related_tasks,
    get_task_details, DashBoardView
)

app_name = 'mylog'

urlpatterns = [
    path('', RegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('dashboard/', DashBoardView.as_view(), name='dashboard'),
    path('log/', UserDailyLogsView.as_view(), name='daily_log'),
    path('users/list/', ListUserView.as_view(), name='list'),
    path('add/log/', AddDailyLogView.as_view(), name='add_log'),
    path('option/', GetOptionView.as_view(), name='get_admin_option'),
    path('daily/log/list/', UserDailyLogList.as_view(), name='daily_log_list'),
    path('create/project/', CreateProjectView.as_view(), name='create_project'),
    path('create/task/', CreateTaskView.as_view(), name='create_task'),
    path('get_related_tasks/', get_related_tasks, name='get_related_tasks'),
    path('get_task_details/', get_task_details, name='task_details'),
]

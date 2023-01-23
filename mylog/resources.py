from import_export import resources
from .models import UserDailyLogs


class MyModelListResource(resources.ModelResource):
    class Meta:
        model = UserDailyLogs
        fields = ['user', 'date', 'project_name', 'task', 'description', 'start_time', 'end_time']


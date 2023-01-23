from django.contrib import admin

from mylog.models import Project, Task, UserDailyLogs, CustomUser


# Register your models here.


class ProjectAdmin(admin.ModelAdmin):
    list_display = ['__all__']


class UserDailyLogsAdmin(admin.ModelAdmin):
    list_display = ['user', 'date', 'task', 'description']


admin.site.register(CustomUser)
admin.site.register(Project)
admin.site.register(Task)
admin.site.register(UserDailyLogs)

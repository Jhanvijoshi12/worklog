from django.contrib.auth.models import AbstractUser, Group
from django.db import models
from django.utils.translation import gettext_lazy as _

# Create your models here.


class CustomUser(AbstractUser):
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="user_group", null=True)

    def __str__(self):
        return "{} - {}".format(self.username, self.email)

    def is_admin(self):
        return self.groups.filter(name="Admin").exists()


class Project(models.Model):
    name = models.CharField(_("project"), max_length=50)
    last_modified = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return "{} - {}".format(self.name, self.last_modified)


class Task(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="tasks")
    title = models.CharField(max_length=50)

    def __str__(self):
        return "{} - {}".format(self.project.name, self.title)


class UserDailyLogs(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="daily_log")
    date = models.DateField()
    project_name = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='project_log')
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='user_tasks')
    description = models.TextField()
    start_time = models.TimeField()
    end_time = models.TimeField()

    def __str__(self):
        return "{} - {} - {} - {}".format(self.user.username, self.date,
                                          self.project_name.name, self.task.title)
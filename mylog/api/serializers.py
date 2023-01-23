from datetime import datetime, date

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import User, Group
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from mylog.constants import INVALID_DETAILS, USER_NOT_FOUND, USER_REGISTER_ERROR
from mylog.models import UserDailyLogs, Project, CustomUser, Task

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True, validators=[UniqueValidator(queryset=User.objects.all())])

    class Meta:
        model = CustomUser
        fields = ['username', 'first_name', 'last_name', 'group', 'email', 'password']

    def create(self, validated_data):
        user = CustomUser.objects.create(**validated_data)
        if not user:
            return serializers.ValidationError({'error': USER_REGISTER_ERROR})
        return user


class LoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'password']
        extra_kwargs = {
            'email': {'required': True},
            'password': {'required': True},
        }

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        if email and password:
            user = CustomUser.objects.filter(email=email).last()
            if user is not None:
                user.set_password(password)
                user.save()
            # authenticate user by username and password after
            # conversion of password into hash format
                auth_user = authenticate(username=user.username, password=password)
                if auth_user is None:
                    raise serializers.ValidationError(USER_NOT_FOUND)
                attrs['user'] = auth_user
        return attrs


class UserLogSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=CustomUser.objects.all(), write_only=True)
    project_name = serializers.PrimaryKeyRelatedField(queryset=Project.objects.all())
    task = serializers.PrimaryKeyRelatedField(queryset=Task.objects.all())

    class Meta:
        model = UserDailyLogs
        fields = ['user', 'date', 'project_name', 'task', 'description', 'start_time', 'end_time']

    def create(self, validated_data):
        return UserDailyLogs.objects.create(**validated_data)


class UserSearchSerializer(serializers.ModelSerializer):
    search_name = serializers.SerializerMethodField(method_name='get_search', read_only=True)

    class Meta:
        model = UserDailyLogs
        fields = ['user', 'date', 'search_name']

    def get_search(self, obj):
        return obj


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ['name']

    def create(self, validated_data):
        return Project.objects.create(**validated_data)


class TaskSerializer(serializers.ModelSerializer):
    project = serializers.PrimaryKeyRelatedField(queryset=Project.objects.all())

    class Meta:
        model = Task
        fields = ['id', 'project', 'title']

    def create(self, validated_data):
        return Task.objects.create(**validated_data)


class ListUserSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField(source='get_user')
    email = serializers.SerializerMethodField(source='get_email')
    project_name = serializers.SerializerMethodField(source='get_project_name')
    task = serializers.SerializerMethodField(source='get_task')
    total_hours = serializers.SerializerMethodField(source='get_total_hours')

    class Meta:
        model = UserDailyLogs
        fields = ['id', 'user', 'email', 'date', 'project_name', 'task', 'description', 'start_time', 'end_time', 'total_hours']

    def get_project_name(self, obj):
        return obj.project_name.name

    def get_task(self, obj):
        return obj.task.title

    def get_user(self, obj):
        return obj.user.username

    def get_total_hours(self, obj):
        """ method for counting total_hours from start and end time of task"""
        total_hours = str(datetime.combine(
            date.today(), obj.end_time) - datetime.combine(
            date.today(), obj.start_time))
        return total_hours

    def get_email(self, obj):
        return obj.user.email


class UserDailyLogListSerializer(serializers.ModelSerializer):
    project_name = serializers.SerializerMethodField(source='get_project_name')
    task = serializers.SerializerMethodField(source='get_task')
    total_hours = serializers.SerializerMethodField(source='get_total_hours')

    class Meta:
        model = UserDailyLogs
        fields = ['id', 'user', 'date', 'project_name', 'task', 'description', 'start_time', 'end_time',
                  'total_hours']

    def get_project_name(self, obj):
        return obj.project_name.name

    def get_task(self, obj):
        return obj.task.title

    def get_total_hours(self, obj):
        """ method for counting total_hours from start and end time of task"""
        total_hours = str(datetime.combine(
            date.today(), obj.end_time) - datetime.combine(
            date.today(), obj.start_time))
        return total_hours
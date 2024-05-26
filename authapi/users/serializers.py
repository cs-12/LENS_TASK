# users/serializers.py
from django.contrib.auth.models import User
from rest_framework import serializers
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password')

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise ValidationError("Email already exists")
        return value

    def create(self, validated_data):
        try:
            user = User.objects.create_user(
                username=validated_data['username'],
                email=validated_data['email'],
                password=validated_data['password']
            )
            return user
        except Exception as e:
            raise ValidationError(f"Error creating user: {str(e)}")

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email')

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            user = authenticate(username=username, password=password)
            if user is None:
                raise ValidationError("Invalid login credentials")
        else:
            raise ValidationError("Must include 'username' and 'password'")
        data['user'] = user
        return data

class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate_refresh_token(self, value):
        try:
            token = RefreshToken(value)
            token.check_blacklist()
        except TokenError:
            raise ValidationError("Invalid or expired token")
        return value

    def save(self, **kwargs):
        try:
            refresh_token = self.validated_data['refresh_token']
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError as e:
            raise ValidationError(f"Error blacklisting token: {str(e)}")

from rest_framework import serializers
from ..model.membersModel import Member
from django.contrib.auth.hashers import make_password,check_password


class MemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Member
        fields = '__all__'
        extra_kwargs = {"password": {"write_only": True,"required":False,"allow_null":True}}
    
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            hashed_password = make_password(password)
            instance.password = hashed_password
        instance.save()
        return instance
    

class MemberRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Member
        fields = ['full_name', 'email', 'password']
        # fields = '__all__'
        extra_kwargs = {
            'password': {'write_only': True},
            }  # Ensure password is not exposed in responses

    def validate_password(self, value):
        """
        Custom password validation logic.
        """
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not any(char.isdigit() for char in value):
            raise serializers.ValidationError("Password must include at least one numeric digit.")
        if not any(char.isalpha() for char in value):
            raise serializers.ValidationError("Password must include at least one letter.")
        return value

    def create(self, validated_data):
        """
        Custom create logic to hash the password before saving.
        """
        password = validated_data.pop('password')  # Extract password from validated data
        validated_data['password'] = make_password(password)  # Hash the password
        return super().create(validated_data)  # Use default create to save the instance

        
class MemberLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        try:
            user = Member.objects.get(email=email)
        except Member.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        if not check_password(password, user.password):
            raise serializers.ValidationError("Invalid password.")

        return attrs
       

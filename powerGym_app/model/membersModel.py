from django.db import models

class Member(models.Model):
    class MembershipType(models.TextChoices):
        REGULAR = 'Regular', 'Regular'
        MONTHLY = 'Monthly', 'Monthly'
        YEARLY = 'Yearly', 'Yearly'

    class BodyType(models.TextChoices):
        SLIM = 'Slim', 'Slim'
        MEDIUM = 'Medium', 'Medium'
        LARGE = 'Large', 'Large'
        
    class Role(models.TextChoices):
        MEMBER = 'Member', 'Member'
        ADMIN = 'Admin', 'Admin'
        TRAINER = 'Trainer', 'Trainer'
        EMPLOYEE = 'Employee', 'Employee'

    class WorkoutPlanType(models.TextChoices):
        CARDIO = 'Cardio', 'Cardio'
        DAY_1 = 'Day_1', 'Day 1'
        DAY_2 = 'Day_2', 'Day 2'
        DAY_3 = 'Day_3', 'Day 3'
        DAY_1_PLUS_CARDIO = 'Day_1_plus_Cardio', 'Day 1 + Cardio'
        DAY_2_PLUS_CARDIO = 'Day_2_plus_Cardio', 'Day 2 + Cardio'
        DAY_3_PLUS_CARDIO = 'Day_3_plus_Cardio', 'Day 3 + Cardio'
        # DAY_2 = 'Day_2','Day 2 + Cardio',
        # DAY_3 = 'Day_3','Day 3 + Cardio',

    member_id = models.AutoField(primary_key=True)
    full_name = models.CharField(max_length=255)
    age = models.PositiveIntegerField(blank=True,null=True)
    profession = models.CharField(max_length=255)
    present_address = models.TextField()
    permanent_address = models.TextField()
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    mobile_number = models.CharField(max_length=15)
    role = models.CharField(max_length=15,choices=Role.choices,default=Role.MEMBER)
    image = models.ImageField(upload_to='photos/users', null=True, blank=True)
    membership_type = models.CharField(
        max_length=10, 
        choices=MembershipType.choices, 
        default=MembershipType.REGULAR
    )
    body_type = models.CharField(
        max_length=10, 
        choices=BodyType.choices, 
        default=BodyType.MEDIUM
    )
    weight = models.CharField(max_length=10)
    height = models.CharField(max_length=10)
    workout_plan_type = models.CharField(
        max_length=20, 
        choices=WorkoutPlanType.choices, 
        default=WorkoutPlanType.CARDIO
    )
    joined_date = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # def __str__(self):
    #     return self.full_name
    
    def __str__(self):
        return f"{self.full_name} (ID: {self.member_id}, Email: {self.email})"


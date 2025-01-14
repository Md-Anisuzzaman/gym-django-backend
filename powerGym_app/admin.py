from django.contrib import admin
from django.contrib.auth.hashers import make_password
from .model.membersModel import Member
from .model.membersActivityModel import MembersActivity
from .model.trainerActivityModel import TrainerActivityModel 
from .model.memberPaymentsModel import MemberPaymentsModel 

@admin.register(Member)
class MemberModelAdmin(admin.ModelAdmin):
    # list_display = ('id', 'p_id', 'title', 'per_share_cost',
    #                 'address', 'created_at', 'updated_at')
    # list_display = [field.name for field in Member._meta.fields]
    # list_display_links = ('member_id',)
    
     # Dynamically include all fields except password
    list_display = [field.name for field in Member._meta.fields if field.name != "password"] + ["truncated_password"]

    # Custom method to truncate the password
    def truncated_password(self, obj):
        if obj.password:
            return f"{obj.password[:5]}..."  # Show only the first 10 characters
        return "No Password"

    truncated_password.short_description = "Password"  # Set column header
    
    list_display_links = ('member_id',)
    
    def save_model(self, request, obj, form, change):
        if obj.password and not obj.password.startswith('pbkdf2_'):  # Avoid re-hashing
            obj.password = make_password(obj.password)
        super().save_model(request, obj, form, change)
    
@admin.register(MembersActivity)
class MemberActivityModelAdmin(admin.ModelAdmin):
    list_display = [field.name for field in MembersActivity._meta.fields]
    list_display_links = ('member',)
    
    
@admin.register(TrainerActivityModel)
class TrainerActivityModelAdmin(admin.ModelAdmin):
    list_display = [field.name for field in TrainerActivityModel._meta.fields]
    list_display_links = ('trainer',)
    
@admin.register(MemberPaymentsModel)
class MemberPaymentsModelAdmin(admin.ModelAdmin):
    list_display = [field.name for field in MemberPaymentsModel._meta.fields]
    list_display_links = ('payment_member',)

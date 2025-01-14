from django.db import models
from .membersModel import Member

class MembersActivity(models.Model):
    class ActivityStatus(models.TextChoices):
        ACTIVE = 'active', 'Active'
        EXPIRED = 'expired', 'Expired'
        CANCELED = 'canceled', 'Canceled'

    class PaymentStatus(models.TextChoices):
        PAID = 'paid', 'Paid'
        DUE = 'due', 'Due'

    memActivites_id = models.AutoField(primary_key=True)
    member = models.ForeignKey(
        'Member',
        on_delete=models.CASCADE,
        related_name='gym_members_activities'
    )
    locker_no = models.CharField(max_length=20, blank=True, null=True)
    start_date = models.DateTimeField(auto_now_add=True)
    gym_entry = models.DateTimeField(blank=True, null=True)
    gym_exit = models.DateTimeField(blank=True, null=True)
    activity_status = models.CharField(
        max_length=15,
        choices=ActivityStatus.choices,
        default=ActivityStatus.ACTIVE
    )
    
    due_amount = models.IntegerField(blank=True, null=True)
    payment_status = models.CharField(
        max_length=10,
        choices=PaymentStatus.choices,
        default=PaymentStatus.DUE
    )

    def __str__(self):
        return f"Activity {self.memActivites_id} - Member {self.member.member_id}"


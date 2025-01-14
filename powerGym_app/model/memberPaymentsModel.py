from django.db import models
from datetime import datetime

def generate_month_year_choices():
    current_year = datetime.now().year
    # short_year = str(current_year)[-2:]  # E.g., '25' for 2025
    months = [
        'January', 'February', 'March', 'April', 'May',
        'June', 'July', 'August', 'September', 'October',
        'November', 'December'
    ]
    return [(f"{month}-{current_year}", f"{month}-{current_year}") for month in months]

def default_month_year():
    return datetime.now().strftime('%B - %Y')  # Example: "November-2024"

class MemberPaymentsModel(models.Model):
    payment_id = models.AutoField(primary_key=True)
    payment_member = models.ForeignKey(
        'Member',
        on_delete=models.CASCADE,
        related_name="gym_members_payments",
        limit_choices_to={'role': 'Member'}
    )
    paid_amount = models.IntegerField()

    paid_month = models.CharField(
        max_length=20,
        choices=generate_month_year_choices,  # Callable to dynamically generate choices
        default=default_month_year,  # Default to current month and year
    )
    payment_desc = models.CharField(blank=True, max_length=255)
    payment_method = models.CharField(
        max_length=15,
        choices=[("Cash", "Cash"), ("Bkash", "Bkash"), ("Nagad", "Nagad"), ("Others", "Others")],
        default="Cash"
    )
    payment_status = models.CharField(
        max_length=15,
        choices=[("Paid", "Paid"), ("Due", "Due")]
    )
    due_amount = models.IntegerField(blank=True,null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Payment {self.payment_id} - {self.paid_month}"

from django.db import models
# from  .membersModel import Member

class TrainerActivityModel(models.Model):
    traner_act_id = models.AutoField(primary_key=True)
    trainer = models.ForeignKey( 'Member',on_delete=models.CASCADE,
        related_name='gym_trainers_activities',limit_choices_to={'role': 'Trainer'})
    trainer_entry = models.DateTimeField(blank=True,null=True)
    trainer_exit = models.DateTimeField(blank=True,null=True)
    duty_shift=models.CharField(max_length=20,choices=[("Morning","Morning"),("Evening","Evening")],blank=True)
    morning_shift_status=models.BooleanField(default=False)
    evening_shift_status=models.BooleanField(default=False)
    worked_duty = models.CharField(max_length=15,blank=True)
    holiday = models.CharField(max_length=100,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    
    def calculate_duty_status(self):
        """
        Calculate whether the trainer worked a Full-Day, Half-Day, or was Absent based on shift statuses.
        This function runs whenever the trainer exits during the day.
        """
        # Ensure shifts are updated only if trainer_entry and trainer_exit are recorded
        if self.trainer_entry and self.trainer_exit:
            # Update shift statuses based on entry and exit times
            if self.duty_shift == "Morning":
                self.morning_shift_status = True
            elif self.duty_shift == "Evening":
                self.evening_shift_status = True

        # Determine overall worked duty status
        if self.morning_shift_status and self.evening_shift_status:
            self.worked_duty = "Full-Day"
        elif self.morning_shift_status or self.evening_shift_status:
            self.worked_duty = "Half-Day"
        else:
            self.worked_duty = "Absent"  # No shifts worked

        self.save()
        
        
    def __str__(self):
        return f"Trainer Activity {self.traner_act_id} - {self.trainer}"

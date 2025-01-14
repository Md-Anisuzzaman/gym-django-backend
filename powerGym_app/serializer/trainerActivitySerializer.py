from rest_framework import serializers
from ..model.trainerActivityModel import TrainerActivityModel
from ..model.membersModel import Member

class TranierActivitySerializer(serializers.ModelSerializer):
    
  class Meta:
    model = TrainerActivityModel
    fields = '__all__'
    extra_kwargs = {}
    
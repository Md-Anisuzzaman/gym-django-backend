from rest_framework import serializers
from ..model.membersActivityModel import MembersActivity
from ..serializer.membersSerializer import MemberSerializer


class MembersActivitySerializer(serializers.ModelSerializer):
    member = MemberSerializer()
    class Meta:
       model = MembersActivity
       fields = '__all__'
        
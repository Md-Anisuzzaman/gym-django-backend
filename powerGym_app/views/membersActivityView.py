from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from ..model.membersActivityModel import MembersActivity
from ..serializer.membersActivitySerializer import MembersActivitySerializer
import json
from ..utils import global_response


class MembersActivityView(APIView):
    
    def get(self,request):
        
            try:
                membersAct = MembersActivity.objects.all()
                if not membersAct.exists():
                    return global_response(
                        msg ="No members activity found", status=status.HTTP_404_NOT_FOUND)
                serializer = MembersActivitySerializer(membersAct, many=True)
                return global_response(
                    data = serializer.data, msg="All members activity fetched successfully", status=status.HTTP_200_OK)
            except Exception as e:
                return global_response(
                    errors = "An error occurred while fetching members activity.", msg = str(e),status=status.HTTP_500_INTERNAL_SERVER_ERROR)        
        
    def post(self, request):
        serializer = MembersActivitySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return global_response(data = serializer.data, msg="Data created successfully",
                            status=status.HTTP_201_CREATED)
        return global_response(errors = serializer.errors, status=status.HTTP_417_EXPECTATION_FAILED)   
    


class MemberActivityDeatilsView(APIView):
    def get(self,request,pk):
          
            try:
                memActivities = MembersActivity.objects.get(pk=pk)
                serializer = MembersActivitySerializer(memActivities)
                return global_response(data =serializer.data, msg = "Single member activities data provided",
                    status=status.HTTP_200_OK,
                )
            except MembersActivity.DoesNotExist:
                return global_response(msg ="Requested member activities not found", status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return global_response(
                    errors = "An unexpected error occurred.", msg =str(e),status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            # Fetch the Member object by primary key (id)
            memActivities = MembersActivity.objects.get(pk=pk)
        except memActivities.DoesNotExist:
            return Response(
                {"error": "Requested member activities not found to update"},
                status=status.HTTP_404_NOT_FOUND,
            )
        # Deserialize and validate the data
        serializer = MembersActivitySerializer(memActivities, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()  # Save the updated object
            return Response(
                {"message": "Memmber activities updated successfully.", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"error": "Invalid data.", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )
    
    def delete(self, request, pk):
        try:
            memActivities = MembersActivity.objects.get(pk=pk)
            memActivities.delete()
            return global_response(msg="Memmber activities deleted successfully", status=status.HTTP_200_OK)
        except memActivities.DoesNotExist:
            return Response({"error": "Requested memmber activities not found to delete"}, status=status.HTTP_404_NOT_FOUND)

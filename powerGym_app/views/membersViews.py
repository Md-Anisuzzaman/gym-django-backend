from django.http import JsonResponse,HttpResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.hashers import check_password
from rest_framework import status
from ..model.membersModel import Member
from ..serializer.membersSerializer import MemberSerializer,MemberRegistrationSerializer,MemberLoginSerializer
from ..utils import global_response,get_tokens,verify_token
from django.utils.decorators import method_decorator

# @method_decorator(api_key_required, name='dispatch')
class MemberListView(APIView):
    def get(self,request):
            try:
                members = Member.objects.all()
                if not members.exists():
                    return global_response(
                        msg ="No members found", status=status.HTTP_404_NOT_FOUND)
                serializer = MemberSerializer(members, many=True)
                return global_response(
                    data = serializer.data, msg="All members fetched successfully", status=status.HTTP_200_OK)
            except Exception as e:
                return global_response(
                    errors = "An error occurred while fetching members.", msg = str(e),status=status.HTTP_500_INTERNAL_SERVER_ERROR)        
    
    def post(self, request):
        serializer = MemberSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return global_response(data = serializer.data, msg="Data created successfully",
                            status=status.HTTP_201_CREATED)
        return global_response(errors = serializer.errors, status=status.HTTP_417_EXPECTATION_FAILED)   
    
class MemberDeatilsView(APIView):
    def get(self,request,pk):
            try:
                member = Member.objects.get(pk=pk)
                serializer = MemberSerializer(member)
                return global_response(data =serializer.data, msg = "Single member data provided",
                    status=status.HTTP_200_OK,
                )
            except Member.DoesNotExist:
                return global_response(msg ="Requested member not found", status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return global_response(
                    errors = "An unexpected error occurred.", msg =str(e),status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            # Fetch the Member object by primary key (id)
            member = Member.objects.get(pk=pk)
        except Member.DoesNotExist:
            return Response(
                {"error": "Requested member not found to update"},
                status=status.HTTP_404_NOT_FOUND,
            )
        # Deserialize and validate the data
        serializer = MemberSerializer(member, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()  # Save the updated object
            return Response(
                {"message": "Member updated successfully.", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"error": "Invalid data.", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )
    
    def delete(self, request, pk):
        try:
            member = Member.objects.get(pk=pk)
            member.delete()
            return global_response(msg="Member deleted successfully", status=status.HTTP_200_OK)
        except Member.DoesNotExist:
            return Response({"error": "Requested member not found to delete"}, status=status.HTTP_404_NOT_FOUND)


class MemberRegistrationView(APIView):
    def post(self, request):
        serializer = MemberRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()  # Save the validated data (calls `create` method)
            tokens = get_tokens(request.data)
            response = Response()
            response.set_cookie(
                'access_token', str(tokens['access_token']), httponly=True)
            response.set_cookie(
                'refresh_token', str(tokens['refresh_token']), httponly=True)
            response.data = {
                "data": serializer.data,
                "token": tokens,
                "msg":"User registered successfully",
            }
            return response
        
        return global_response(errors=serializer.errors,msg="User not create", status=status.HTTP_400_BAD_REQUEST)
    

class MemberLoginView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = MemberLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = Member.objects.get(email=email)  # Ensure this includes the member_id field

            # Retrieve tokens from cookies (if present)
            access_token = request.COOKIES.get('access_token')
            refresh_token = request.COOKIES.get('refresh_token')

            # Validate tokens
            access_valid = verify_token(access_token) if access_token else False
            refresh_valid = verify_token(refresh_token) if refresh_token else False

            response = Response()
            if not access_valid:
                if refresh_valid:
                    # Refresh token valid, regenerate access token
                    tokens = get_tokens({"email": user.email, "member_id": user.member_id})
                    response.set_cookie('access_token', tokens['access_token'], httponly=True)
                else:
                    # Both tokens invalid, generate new tokens
                    tokens = get_tokens({"email": user.email, "member_id": user.member_id})
                    response.set_cookie('access_token', tokens['access_token'], httponly=True)
                    response.set_cookie('refresh_token', tokens['refresh_token'], httponly=True)

                response.data = {
                    "message": "Successfully login with generated token"
                }
            else:
                # Access token valid
                response.data = {
                    "message": "Login successfully"
                }

            return response
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    def post(self, request):
        response=Response({"message":"User logout successfully"})
        response.delete_cookie("access_token")  # Adjust if needed
        response.delete_cookie("refresh_token")  # Adjust if needed
        return response



from django.conf import settings
from functools import wraps
from rest_framework.response import Response
from datetime import datetime, timedelta, timezone
from functools import wraps
from django.http import JsonResponse
import jwt

def global_response(data=None, msg=None, status=None, errors=None):
    response_data = {}
    if msg:
        response_data["msg"] = msg
    if data:
        response_data["data"] = data
    if errors:
        response_data["errors"] = errors

    return Response(response_data, status=status)


def get_tokens(user):  # Make sure to include 'self' as the first parameter
    # Define your payload
    payload = {
        'email': user['email'],
        'member_id': user['member_id']
    }
    
    # Set expiration time in minutes
    access_token_exp = datetime.now(timezone.utc) + timedelta(minutes=1)
    refresh_token_exp = datetime.now(timezone.utc) + timedelta(minutes=3)
    # access_token_exp = datetime.utcnow() + timedelta(minutes=1)
    # refresh_token_exp = datetime.utcnow() + timedelta(minutes=3)
    # Encode the JWT token with the expiration time
    access_token = jwt.encode({'exp': access_token_exp, **payload},
                              'secret_key', algorithm='HS256')
    refresh_token = jwt.encode({'exp': refresh_token_exp, **payload},
                               'secret_key', algorithm='HS256')
    token = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    return token


def verify_token(token):
    try:
        jwt.decode(token, 'secret_key', algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        print("Token is ExpiredSignatureError")
        return False
    except jwt.exceptions.DecodeError:
        print("Token DecodeError")
        return False
    return True

def token_authentication_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        access_token = request.COOKIES.get('access_token')
        refresh_token = request.COOKIES.get('refresh_token')

        # Check if access token is present and valid
        if access_token:
            is_valid_access = verify_token(access_token)
            if is_valid_access:
                # Access token is valid, proceed with the view function
                return view_func(request, *args, **kwargs)
            else:
                print("Access token is expired")

        # Check if refresh token is present and valid
        if refresh_token:
            is_valid_refresh = verify_token(refresh_token)
            if is_valid_refresh:
                # Refresh token is valid, generate new tokens
                try:
                    payload = jwt.decode(refresh_token, 'secret_key', algorithms=['HS256'])
                    new_tokens = get_tokens(payload)
                    response = view_func(request, *args, **kwargs)
                    # Set new tokens as cookies
                    response.set_cookie('access_token', new_tokens['access_token'], httponly=True)
                    response.set_cookie('refresh_token', new_tokens['refresh_token'], httponly=True)
                    print("New tokens generated and set")
                    return response
                except jwt.ExpiredSignatureError:
                    return JsonResponse({'error': 'Refresh token has expired'}, status=401)
                except jwt.DecodeError:
                    return JsonResponse({'error': 'Invalid refresh token'}, status=401)
                except Exception as e:
                    return JsonResponse({'error': f'Error decoding refresh token: {str(e)}'}, status=500)
            else:
                print("Refresh token is invalid or expired")
                return JsonResponse({'error': 'Refresh authentication is invalid or expired'}, status=401)

        # If neither access nor refresh tokens are valid
        print("Tokens are missing or invalid")
        return JsonResponse({'error': 'Unauthorized: Authentication are missing'}, status=401)

    return wrapper



# Replace this with your actual API key or retrieve it from environment variables
# VALID_API_KEY = os.getenv("API_KEY", "my_secret_api_key")
# VALID_API_KEY = "my_secret_api_key"
# def api_key_required(view_func):
#     @wraps(view_func)
#     def wrapped_view(request, *args, **kwargs):
#         # Try to get the Authorization header
#         api_key = request.headers.get("Authorization") or request.META.get("HTTP_AUTHORIZATION")
#         print("api key:", api_key)  # Debugging
#         # print("Headers:", request.headers)  # Debugging
#         # print("Meta Headers:", request.META)  # Debugging
#         if api_key == f"Bearer {VALID_API_KEY}":
#             return view_func(request, *args, **kwargs)
#         return JsonResponse({"error": "Unauthorized"}, status=401)
#     return wrapped_view


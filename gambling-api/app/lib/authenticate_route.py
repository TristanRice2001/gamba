from app.services.authentication_service import IAuthenticationService
import functools
from flask import request
from app.lib.make_error_response import make_error_response


def authenticate_route(authentication_service: IAuthenticationService, requires_admin = False):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            jwt_header = request.headers.get("Authorization")

            if not jwt_header:
                return make_error_response("Invalid JWT token")
            

            authentication_func = None
            if requires_admin:
                authentication_func = authentication_service.requires_admin_authentication
            else:
                authentication_func = authentication_service.requires_authentication

            user = authentication_func(jwt_header)
            
            if not user:
                return make_error_response("Invalid JWT token")
            
            return fn(*args, user=user, **kwargs)
        return wrapped
    return decorator
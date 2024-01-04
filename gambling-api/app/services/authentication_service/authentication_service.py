from app.models import UserModel
from app.services.jwt_service import IJWTService
from app.services.user import IUserService
from .authentication_service_interface import IAuthenticationService
from app.services.jwt_service.execptions import InvalidSignatureException, InvalidTokenException, ExpiredTokenError


class JWTBasicAuthenticationService(IAuthenticationService):
    def __init__(self, 
                 user_service: IUserService, 
                 jwt_service: IJWTService):
        self.user_service = user_service
        self.jwt_service = jwt_service


    def requires_authentication(self, jwt_token: str) -> UserModel:

        try:
            user = self.jwt_service.decode_payload(jwt_token)
        except (InvalidSignatureException, InvalidTokenException, ExpiredTokenError) as e:
            return None
        
        user_id = user.get("id")

        if not user_id:
            return None
        
        user_model = self.user_service.get_user_by_id(user_id)

        return user_model
    
    def requires_admin_authentication(self, jwt_token: str) -> UserModel:
        user = self.requires_authentication(jwt_token)

        if not user or not user.is_admin:
            return None
        
        return user
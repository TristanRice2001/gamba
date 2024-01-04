from abc import ABC, abstractmethod
from app.services.user import IUserService
from app.services.jwt_service import IJWTService
from app.models import UserModel

class IAuthenticationService(ABC):
    @abstractmethod
    def __init__(self, 
                 user_service: IUserService, 
                 jwt_service: IJWTService):
        pass

    @abstractmethod
    def requires_authentication(self, jwt_token: str) -> UserModel:
        pass

    @abstractmethod
    def requires_admin_authentication(self, jwt_token: str) -> UserModel:
        pass
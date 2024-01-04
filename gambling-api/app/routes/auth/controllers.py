from app.services.recaptcha import IRecaptchaService
from app.services.user import IUserService
from app.services.jwt_service import IJWTService
from .dto import RegisterRequest, LoginRequest
from app.lib import make_error_response
from app.services.hashing_service import IHashingService


class AuthController:

    def __init__(self,
                 user_service: IUserService,
                 recaptcha_service: IRecaptchaService,
                 jwt_service: IJWTService,
                 hashing_service: IHashingService
                 ) -> None:
        self.user_service = user_service
        self.recaptcha_service = recaptcha_service
        self.jwt_service = jwt_service
        self.hashing_service = hashing_service

    def register_post(self, request_data: RegisterRequest) -> dict:
        is_recaptcha_valid = self.recaptcha_service.validate_token(
            request_data.recaptchaToken)

        if not is_recaptcha_valid:
            return make_error_response("Recaptcha is invalid", "recaptcha")

        if self.user_service.get_user_by_email(request_data.email):
            return make_error_response("That email is already taken", "email")

        if self.user_service.get_user_by_username(request_data.username):
            return make_error_response("That username is already taken!", "username")

        hashed_password = self.hashing_service.hash(
            request_data.password)

        new_user = self.user_service.create_user(
            username=request_data.username,
            email=request_data.email,
            password=hashed_password
        )
        jwt_token = self.jwt_service.encode_payload(new_user.to_dict())

        return {
            "jwtToken": jwt_token
        }

    def login_post(self, request_data: LoginRequest):
        invalid_login_msg = "Invalid login information"

        is_recaptcha_valid = self.recaptcha_service.validate_token(
            request_data.recaptchaToken)

        if not is_recaptcha_valid:
            return make_error_response("Recaptcha is invalid", "recaptcha")

        user_by_username = self.user_service.get_user_by_username(
            request_data.emailOrUsername)

        user_by_email = self.user_service.get_user_by_email(
            request_data.emailOrUsername)

        user_to_login = user_by_email or user_by_username or None

        if not user_to_login:
            return make_error_response(invalid_login_msg)

        is_hash_valid = self.hashing_service.verify(
            user_to_login.password, request_data.password)
        if not is_hash_valid:
            return make_error_response(invalid_login_msg)

        jwt_token = self.jwt_service.encode_payload(user_to_login.to_dict())

        return {
            "jwtToken": jwt_token
        }

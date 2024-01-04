from flask import Blueprint, jsonify
from .controllers import AuthController
from .dto import RegisterRequest, RegisterRequestValidator, LoginRequest, LoginRequestValidator
from app import recaptcha_service, user_service, jwt_service, hash_service, authentication_service
from app.lib import marshal_request, authenticate_route
from flask import request
from app.models import UserModel


def make_controller() -> AuthController:
    controller = AuthController(
        user_service=user_service,
        recaptcha_service=recaptcha_service,
        jwt_service=jwt_service,
        hashing_service=hash_service
    )
    return controller


bp = Blueprint("auth", __name__)


@bp.route("/register", methods=["POST"])
@marshal_request(RegisterRequestValidator, RegisterRequest)
def register(request_dto: RegisterRequest):
    controller = make_controller()
    return jsonify(controller.register_post(request_dto))


@bp.route("/login", methods=["POST"])
@marshal_request(LoginRequestValidator, LoginRequest)
def login(request_dto: LoginRequest):
    controller = make_controller()
    return jsonify(controller.login_post(request_dto))

@bp.route("/me", methods=["GET"])
@authenticate_route(authentication_service)
def me(user: UserModel):
    return jsonify(user.to_dict())
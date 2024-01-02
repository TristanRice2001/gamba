from flask import Blueprint, request, jsonify
from .controllers import AuthController
from .dto import RegisterRequest, RegisterRequestValidator, LoginRequest, LoginRequestValidator
from app import recaptcha_service, user_service, jwt_service, hash_service
from app.helpers import marshal_request


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

from flask import Flask
from flask_cors import CORS

from app.config import Config
from peewee import SqliteDatabase

from app.services.recaptcha import RecaptchaService
from app.services.user import UserService
from app.services.jwt_service import JWTService
from app.services.hashing_service import BcryptHashingService

recaptcha_service = RecaptchaService()
user_service = UserService()
jwt_service = JWTService()
hash_service = BcryptHashingService()

db = SqliteDatabase("site.db")


def create_app(is_test=False):
    from app.models import User

    app = Flask(__name__)

    config = Config()

    app.config.from_object(config)

    ##################################
    # Services

    recaptcha_service.init_app(app)
    user_service.init_models(User)
    jwt_service.init_app(app)
    ###############################

    if config.DEBUG and not is_test:
        tables = [User]
        db.drop_tables(tables)
        db.create_tables(tables)

    CORS(app, origins=config.ALLOWED_ORIGINS)

    from app.routes.auth import auth_blueprint

    app.register_blueprint(auth_blueprint, url_prefix="/api/v1/auth/")

    return app

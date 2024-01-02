from datetime import datetime, timedelta
from flask import Flask
import jwt
from .jwt_service_interface import IJWTService


class JWTService(IJWTService):
    def init_app(self, app: Flask) -> None:
        jwt_key = app.config.get("JWT_SECRET")
        assert bool(
            jwt_key), "JWT key is missing from config, try checking the .env file, or config.py"
        self.jwt_key = jwt_key

        self.jwt_lifetime = app.config.get("JWT_LIFETIME")

    def encode_payload(self, payload: dict, add_expiration: bool = True) -> str:
        if type(payload) != dict:
            raise ValueError("Payload must be a dictoinary")

        if add_expiration:
            payload["exp"] = datetime.utcnow() + timedelta(seconds=3600)

        return jwt.encode(payload, self.jwt_key)

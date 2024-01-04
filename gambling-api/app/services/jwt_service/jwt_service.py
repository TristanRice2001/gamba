from datetime import datetime, timedelta
from flask import Flask
import jwt
from .jwt_service_interface import IJWTService
from .execptions import InvalidSignatureException, InvalidTokenException, ExpiredTokenError

class JWTService(IJWTService):
    def init_app(self, app: Flask) -> None:
        jwt_key = app.config.get("JWT_SECRET")
        assert bool(
            jwt_key), "JWT key is missing from config, try checking the .env file, or config.py"
        self.jwt_key = jwt_key

        self.jwt_lifetime = app.config.get("JWT_LIFETIME")

        self.algorithm = "HS256"

    def encode_payload(self, payload: dict, add_expiration: bool = True) -> str:
        if type(payload) != dict:
            raise ValueError("Payload must be a dictoinary")

        if add_expiration:
            payload["exp"] = datetime.utcnow() + timedelta(seconds=self.jwt_lifetime)

        return jwt.encode(payload, self.jwt_key, algorithm=self.algorithm)
    
    def decode_payload(self, jwt_token: str) -> dict:
        """ decodes a JWT token with the current JWT secret in place, and returns its data """

        try:
            decoded_payload = jwt.decode(jwt_token, self.jwt_key, algorithms=[self.algorithm])
        
        except jwt.exceptions.InvalidSignatureError:
            raise InvalidSignatureException("Invalid JWT token")
        
        except jwt.exceptions.DecodeError:
            raise InvalidTokenException("Invalid JWT token")
        
        
        except jwt.exceptions.ExpiredSignatureError:
            raise ExpiredTokenError("Invalid JWT token")
        
        return decoded_payload
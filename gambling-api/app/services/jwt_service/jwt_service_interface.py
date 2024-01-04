from abc import ABC, abstractmethod
from flask import Flask


class IJWTService(ABC):
    @abstractmethod
    def init_app(self, app: Flask) -> None:
        pass

    @abstractmethod
    def encode_payload(self, payload: dict, add_expiration: bool = True) -> str:
        pass

    @abstractmethod
    def decode_payload(self, jwt_token: str) -> dict:
        pass
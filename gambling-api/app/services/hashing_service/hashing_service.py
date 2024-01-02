from .hashing_service_interface import IHashingService
import bcrypt


class BcryptHashingService(IHashingService):
    def hash(self, password: str) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def verify(self, hashed_value: str, verify_value: str) -> bool:
        return bcrypt.checkpw(verify_value.encode(), hashed_value.encode())

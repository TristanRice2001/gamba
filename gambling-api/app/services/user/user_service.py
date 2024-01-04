from .user_service_interface import IUserService
from app.models import UserModel

class UserService(IUserService):
    def init_models(self, user_model: UserModel):
        self.user_model = user_model

    def get_user_by_id(self, id):
        return self.user_model.get_by_id(id)

    def get_user_by_username(self, username: str):
        return self.user_model.filter(self.user_model.username == username).first()

    def get_user_by_email(self, email: str):
        return self.user_model.filter(email=email).first()

    def create_user(self, username, email, password) -> UserModel:
        new_id: UserModel = self.user_model.create(
            username=username,
            email=email,
            password=password
        )
        return self.user_model.get_by_id(new_id)

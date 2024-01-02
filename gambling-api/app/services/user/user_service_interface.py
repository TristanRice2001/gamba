from abc import ABC, abstractmethod


class IUserService(ABC):
    @abstractmethod
    def init_models(self, user_model):
        pass

    @abstractmethod
    def get_user_by_id(self, id):
        pass

    @abstractmethod
    def create_user(self, username, email, password) -> None:
        pass

    @abstractmethod
    def get_user_by_username(self, username: str):
        pass

    @abstractmethod
    def get_user_by_email(self, email: str):
        pass

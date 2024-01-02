from abc import ABC, abstractmethod, abstractproperty


class IRecaptchaService(ABC):

    @abstractmethod
    def validate_token(self, token: str) -> bool:
        pass

    def init_app(self, api_key: str) -> None:
        pass

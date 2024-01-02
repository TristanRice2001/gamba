from abc import ABC, abstractmethod


class IHashingService(ABC):
    @abstractmethod
    def hash(self, password: str) -> str:
        pass

    @abstractmethod
    def verify(self, hashed_string: str, check_string: str) -> bool:
        pass

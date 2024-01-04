import requests
from flask import Flask

from .recaptcha_service_interface import IRecaptchaService


class RecaptchaService(IRecaptchaService):
    def init_app(self, app: Flask) -> None:
        recaptcha_key = app.config.get("RECAPTCHA_KEY")
        self.should_ignore_recaptcha = app.config.get("IGNORE_RECAPTCHA")
        assert recaptcha_key, "Invalid recaptcha key! Value is likely missing in either config.py or .env file"
        self.api_key = recaptcha_key

    def validate_token(self, token: str) -> bool:
        if self.should_ignore_recaptcha:
            # Can turn off recaptcha verification for API testing in IGNORE_RECAPTCHA .env argument
            return True
        
        r = requests.post("https://www.google.com/recaptcha/api/siteverify", data={
            "secret": self.api_key,
            "response": token
        })

        return r.json().get("success", False)

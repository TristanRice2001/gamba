import os
import dotenv

env_file_path = os.path.join(os.path.dirname(__file__), ".env")
is_dotenv_loaded = dotenv.load_dotenv(
    os.path.join(env_file_path)
)

assert is_dotenv_loaded, "Failed to load .env file"

REQUIRED_ENV_ARGS = [
    "ENV",
    "GOOGLE_RECAPTCHA_KEY",
    "ALLOWED_ORIGINS",
    "JWT_SECRET"
]

for arg in REQUIRED_ENV_ARGS:
    assert os.environ.get(arg), \
        f"Argument {arg} is missing from the .env file"


class Config:
    DEBUG = os.environ.get("ENV") == "DEV"
    RECAPTCHA_KEY = os.environ.get("GOOGLE_RECAPTCHA_KEY")
    ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS")
    JWT_SECRET = os.environ.get("JWT_SECRET")

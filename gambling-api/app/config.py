import os
import dotenv

env_file_path: str = os.path.join(os.path.dirname(__file__), ".env")
is_dotenv_loaded: bool = dotenv.load_dotenv(
    os.path.join(env_file_path)
)

assert is_dotenv_loaded, "Failed to load .env file"

REQUIRED_ENV_ARGS: list[str] = [
    "ENV",
    "GOOGLE_RECAPTCHA_KEY",
    "ALLOWED_ORIGINS",
    "JWT_SECRET"
]

for arg in REQUIRED_ENV_ARGS:
    assert os.environ.get(arg), \
        f"Argument {arg} is missing from the .env file"


class Config:
    DEBUG: bool = os.environ.get("ENV") == "DEV"
    RECAPTCHA_KEY: str = os.environ.get("GOOGLE_RECAPTCHA_KEY") or ""
    ALLOWED_ORIGINS: str = os.environ.get("ALLOWED_ORIGINS") or ""
    JWT_SECRET: str = os.environ.get("JWT_SECRET") or ""
    JWT_LIFETIME: int = int(os.environ.get("JWT_LIFETIME") or 3600)
    IGNORE_RECAPTCHA = bool(os.environ.get("IGNORE_RECAPTCHA"))
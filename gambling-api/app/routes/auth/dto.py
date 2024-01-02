from dataclasses import dataclass
from marshmallow import Schema, fields, validate


class RegisterRequestValidator(Schema):
    email = fields.Email(required=True)
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=50),
            validate.Regexp(
                r"^[a-zA-Z\d_]*$", error="Username can only contain letters, numbers, and underscores")
        ]
    )
    password = fields.Str(
        required=True,
        validate=validate.Regexp(
            r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$",
            error="Password must contain at least 1 capital letter, one number, 1 special character, and be greater than 8 characters long"
        )
    )
    recaptchaToken = fields.Str(required=True)


class LoginRequestValidator(Schema):
    emailOrUsername = fields.Str(required=True)
    password = fields.Str(required=True)
    recaptchaToken = fields.Str(required=True)


@dataclass
class LoginRequest:
    emailOrUsername: str = ""
    password: str = ""
    recaptchaToken: str = ""


@dataclass
class RegisterRequest:
    email: str = ""
    username: str = ""
    password: str = ""
    recaptchaToken: str = ""


@dataclass
class RegisterResponse:
    jwt_token: str

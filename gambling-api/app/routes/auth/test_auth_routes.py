import copy
import unittest
from unittest.mock import MagicMock, patch
from app.services.recaptcha import IRecaptchaService, RecaptchaService
from app.models import User
from peewee import SqliteDatabase
from app.services.user import UserService
from app.services.jwt_service import JWTService
from app.services.hashing_service import BcryptHashingService
from .controllers import AuthController
from .dto import LoginRequest, RegisterRequest


def get_error_message(response: dict, key=""):
    err_value = (response.get("error", {}).get(key)) or None

    if type(err_value) != list:
        return err_value

    return err_value[0] if len(err_value) > 0 else None


class MockRecaptchaServiceValid(IRecaptchaService):
    def validate_token(self, token: str) -> bool:
        return True


class MockRecaptchaServiceInvalid(IRecaptchaService):
    def validate_token(self, token: str) -> bool:
        return False


valid_register_request = RegisterRequest(
    email="test@test.com",
    username="username1234",
    password="testPass1234$$$",
    recaptchaToken="recaptcha$$!_thiswontbetested"
)

valid_login_request = LoginRequest(
    emailOrUsername="test@test.com",
    password="P4$$w0rd",
    recaptchaToken="recaptcha$$!_Thiswontbetested"
)

test_data = [
    {
        "username": f"username{i}",
        "email": f"email{i}@test.com",
        "password": f"$2b$12$J4QqJaNcexBP9V6/g9K2Ku9nl0eN.Oq.KJQ1oclZkEjd4XziX9vci"
    }
    for i in range(20)
]


class TestAuthController(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        self.test_db = SqliteDatabase(":memory:")
        super().__init__(methodName)

    def run(self, result=None):
        with self.test_db.bind_ctx([User]):
            self.test_db.create_tables([User])
            for user in test_data:
                User.create(**user)
            super(TestAuthController, self).run(result)
            self.test_db.drop_tables([User])

    def setUp(self):
        from app import create_app
        mock_app = create_app(is_test=True)
        self.test_db = SqliteDatabase(":memory:")

        self.jwt_service = JWTService()
        self.jwt_service.init_app(mock_app)

        self.hash_service = BcryptHashingService()

        self.user_service = UserService()
        self.user_service.init_models(User)

        self.controller = AuthController(
            user_service=self.user_service,
            recaptcha_service=MockRecaptchaServiceValid(),
            jwt_service=self.jwt_service,
            hashing_service=self.hash_service
        )

    def test_when_valid_register_request_return_success(self):
        result = self.controller.register_post(valid_register_request)

        self.assertIsNotNone(result.get("jwtToken"),
                             msg="When a valid register request is sent, ")
        self.assertTrue(result.get("jwtToken"))

        self.assertIsNotNone(User.filter(
            email=valid_register_request.email).first())

    def test_when_valid_login_with_username_return_success(self):
        result = self.controller.login_post(LoginRequest(
            emailOrUsername="username1", password="password"))

        self.assertIsNotNone(result.get("jwtToken"))
        self.assertTrue(result.get("jwtToken"))

    def test_when_valid_login_with_email_return_success(self):
        result = self.controller.login_post(LoginRequest(
            emailOrUsername="email1@test.com", password="password"
        ))

        self.assertIsNotNone(result.get("jwtToken"))
        self.assertTrue(result.get("jwtToken"))

    def test_when_auth_flow_copmleted_return_success(self):
        test_email = "tristan.rice1135@gmail.com"
        test_username = "tristan_rice"
        test_password = "P4$$w0rd"

        register_result = self.controller.register_post(RegisterRequest(
            email=test_email, username=test_username, password=test_password
        ))

        self.assertIsNotNone(register_result.get(
            "jwtToken"), msg="Function should return success")
        self.assertTrue(register_result.get("jwtToken"),
                        msg="Function should return success")

        login_by_email_result = self.controller.login_post(LoginRequest(
            emailOrUsername=test_email, password=test_password
        ))

        self.assertIsNotNone(login_by_email_result.get(
            "jwtToken"), msg="Function should return success")
        self.assertTrue(login_by_email_result.get("jwtToken"),
                        msg="Function should return success")

        login_by_username_result = self.controller.login_post(LoginRequest(
            emailOrUsername=test_username, password=test_password
        ))

        self.assertIsNotNone(login_by_username_result.get(
            "jwtToken"), msg="Function should return success")
        self.assertTrue(login_by_username_result.get(
            "jwtToken"), msg="Function should return success")

    def test_when_invalid_captcha_return_error(self):
        self.controller = AuthController(
            user_service=self.user_service,
            recaptcha_service=MockRecaptchaServiceInvalid(),
            jwt_service=self.jwt_service,
            hashing_service=self.hash_service
        )

        register_result = self.controller.register_post(valid_register_request)

        self.assertIsNotNone(register_result.get("error", {}).get(
            "recaptcha"), msg="Invalid captcha should return an error")

        login_result = self.controller.login_post(valid_login_request)

        self.assertIsNotNone(login_result.get("error", {}).get(
            "recaptcha"), msg="Invalid captcha should return an error")

    def test_when_duplicate_user_return_error(self):
        register_result_1 = self.controller.register_post(
            valid_register_request)

        self.assertIsNotNone(register_result_1.get(
            "jwtToken"), msg="First register function should be successful")
        self.assertTrue(register_result_1.get(
            "jwtToken"), msg="First register function should be successful")

        duplicate_email_request = copy.copy(valid_register_request)
        duplicate_email_request.username = "asdkjhasdkjhadskjadhsUsernamewillnotbetaken"
        register_result_dupe_email = self.controller.register_post(
            valid_register_request)

        self.assertIsNone(register_result_dupe_email.get(
            "jwtToken"), msg="When a duplicate user is registered, function should return an error")
        self.assertEqual(register_result_dupe_email.get("error", {}).get(
            "email"), "That email is already taken", msg="`Invalid error message for when email is taken")

        duplicate_username_request = copy.copy(valid_register_request)
        duplicate_username_request.email = "asdadsadsadsadsadsasddasemailwillnotbetaken"
        register_result_dupe_username = self.controller.register_post(
            duplicate_username_request)
        self.assertIsNone(register_result_dupe_username.get(
            "jwtToken"), msg="When a duplicate user is registered, function should return an error")
        self.assertEqual(register_result_dupe_username.get(
            "error", {}).get("username"), "That username is already taken!", msg="Invalid error message for when username is taken")

    def test_when_valid_information_then_password_is_hashed(self):
        mock_hashing_service = BcryptHashingService()
        mock_hashing_service.hash = MagicMock(return_value="test")

        controller = AuthController(
            user_service=self.user_service,
            recaptcha_service=MockRecaptchaServiceValid(),
            jwt_service=self.jwt_service,
            hashing_service=mock_hashing_service
        )

        controller.register_post(valid_register_request)

        mock_hashing_service.hash.assert_called_once_with(
            valid_register_request.password)


class TestAuthRoutes(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        self.test_db = SqliteDatabase(":memory:")
        super().__init__(methodName)

    def run(self, result=None):
        with self.test_db.bind_ctx([User]):
            self.test_db.create_tables([User])
            for user in test_data:
                User.create(**user)
            super(TestAuthRoutes, self).run(result)
            self.test_db.drop_tables([User])

    def setUp(self):
        from app import create_app
        self.app = create_app()
        self.app.config.update({
            "RECAPTCHA_KEY": "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWes"
        })
        self.test_client = self.app.test_client()

    @patch.object(RecaptchaService, "validate_token")
    def test_valid_register(self, mock_validate_token: MagicMock):
        mock_validate_token.return_value = True
        response = self.test_client.post("/api/v1/auth/register", json={
            "username": "test1",
            "email": "tristan.rice1135@gmail.com",
            "password": "P4$$w0rd",
            "recaptchaToken": "aaaa"
        }, content_type="application/json")

        # Recaptcha service should be called at least once with the recaptcha supplied
        mock_validate_token.assert_called_once_with(
            "aaaa")

        self.assertIsNotNone(response.json.get("jwtToken"))

    @patch.object(RecaptchaService, "validate_token")
    def test_register_missing_data(self, mock_validate_token: MagicMock):
        mock_validate_token.return_value = True
        response_missing_username = self.test_client.post("/api/v1/auth/register", json={
            "email": "tristan.rice1135@gmail.com",
            "password": "P4$$w0rd",
            "recaptchaToken": "aaa"
        }, content_type="application/json")

        self.assertEqual(response_missing_username.json.get("error", {}).get(
            "username", [])[0], "Missing data for required field.")

        response_missing_email = self.test_client.post("/api/v1/auth/register", json={
            "username": "tristan_rice",
            "password": "P4$$w0rd",
            "recaptchaToken": "aaa"
        }, content_type="application/json")

        self.assertEqual(response_missing_email.json.get("error", {}).get(
            "email", [])[0], "Missing data for required field.")

        response_missing_password = self.test_client.post("/api/v1/auth/register", json={
            "email": "tristan.rice1135@gmail.com",
            "username": "tristan_rice",
            "recaptchaToken": "aaa"
        }, content_type="application/json")

        self.assertEqual(response_missing_password.json.get("error", {}).get(
            "password", [])[0], "Missing data for required field.")

        response_missing_password = self.test_client.post("/api/v1/auth/register", json={
            "email": "tristan.rice1135@gmail.com",
            "username": "tristan_rice",
            "password": "P4$$w0rd1234_"
        }, content_type="application/json")

        self.assertEqual(response_missing_password.json.get("error", {}).get(
            "recaptchaToken", [])[0], "Missing data for required field.")

    @patch.object(RecaptchaService, "validate_token")
    def test_register_when_invalid_email_then_fail(self, mock_validate_token: MagicMock):
        response_invalid_username = self.test_client.post("/api/v1/auth/register", json={
            "username": "!!!invaliduser!!!!",
            "email": "tristan.rice1135@gmail.com",
            "password": "P4$$w0rd",
            "recaptchaToken": "aaaa"
        })

        expected_error_messasge = response_invalid_username.json.get(
            "error", {}).get("username", [])[0]
        self.assertEqual(expected_error_messasge,
                         "Username can only contain letters, numbers, and underscores")

    @patch.object(RecaptchaService, "validate_token")
    def test_register_when_invalid_username_length_then_fail(self, mock_valiate_token: MagicMock):
        test_data = {
            "email": "tristan.rice1135@gmail.com",
            "password": "P4$$w0rd",
            "recaptchaToken": "aaaa"
        }

        error_message = "Length must be between 3 and 50."

        test_data_too_short = {**test_data, "username": "aa"}
        test_data_too_long = {**test_data, "username": "a" * 51}
        response_username_too_short = self.test_client.post(
            "/api/v1/auth/register", json=test_data_too_short, content_type="application/json")

        self.assertEqual(response_username_too_short.json.get(
            "error", {}).get("username", [])[0], error_message)

        resposne_username_too_long = self.test_client.post(
            "/api/v1/auth/register", json=test_data_too_long, content_type="application/json")

        self.assertEqual(resposne_username_too_long.json.get(
            "error", {}).get("username", [])[0], error_message)

    @patch.object(RecaptchaService, "validate_token")
    def test_register_when_invalid_email_then_fail(self, mock_validate_token: MagicMock):
        invalid_emails = [
            "plainaddress",
            "#@%^%#$@#$@#.com",
            "@example.com",
            "Joe Smith <email@example.com>",
            "email.example.com",
            "email@example@example.com",
            ".email@example.com",
            "email.@example.com",
            "email..email@example.com",
            "email@example.com (Joe Smith)",
            "email@example",
            "email@-example.com",
            "email@example..com",
            "Abc..123@example.com",
        ]

        for invalid_email in invalid_emails:
            response_invalid_email = self.test_client.post("/api/v1/auth/register", json={
                "username": "validusername",
                "password": "P4$$w0rd",
                "email": invalid_email,
                "recaptchaToken": "aaa"
            }, content_type="application/json")

            response_error = get_error_message(
                response_invalid_email.json, key="email")
            self.assertIsNotNone(
                response_error, msg=f"Invalid email address: {invalid_email} should fail")
            self.assertEqual(response_error, "Not a valid email address.",
                             msg=f"Invalid email address {invalid_email} should fail")

    @patch.object(RecaptchaService, "validate_token")
    def test_register_when_weak_password_then_fail(self, mock_validate_token: MagicMock):
        weak_passwords = [
            "password",
            "p4$$word_without_capitals",
            "$A1a"
            "",
            "P4$$WORD_WITHOUT_LOWERCASE",
            "PASSWORD_WITHOUT_numbers!",
            "n0specialChars",
            "123456",
            "12345",
            "123456789",
            "password",
            "iloveyou",
            "princess",
            "1234567",
            "rockyou",
            "12345678",
            "abc123",
            "nicole",
            "daniel",
            "babygirl",
            "monkey",
            "lovely",
            "jessica",
            "654321",
            "michael",
            "ashley",
            "qwerty",
            "111111",
            "iloveu",
            "000000",
            "michelle",
            "tigger",
            "sunshine",
            "chocolate",
            "password1",
            "soccer",
        ]

        for weak_password in weak_passwords:
            response_weak_password = self.test_client.post("/api/v1/auth/register", json={
                "username": "validusername",
                "password": weak_password,
                "email": "tristan.rice1135@gmail.com",
                "recaptchaToken": "aaa"
            }, content_type="application/json")

            response_error = get_error_message(
                response_weak_password.json, key="password")

            self.assertIsNotNone(
                response_error, msg=f"Weak password: \"{weak_password}\" should return a fail response")

            self.assertEqual(
                response_error, "Password must contain at least 1 capital letter, one number, 1 special character, and be greater than 8 characters long",
                msg=f"Weak password: \"{weak_password}\" should return a fail respons with the correct error message"
            )

    @patch.object(RecaptchaService, "validate_token")
    def test_full_auth_flow(self, mock_validate_token):
        valid_register_response = self.test_client.post("/api/v1/auth/register", json={
            "username": valid_register_request.username,
            "email": valid_register_request.email,
            "password": valid_register_request.password,
            "recaptchaToken": "aaa"
        })

        self.assertTrue("jwtToken" in valid_register_response.json,
                        msg="Valid register request should return success")
        self.assertIsNotNone(valid_register_response.json.get(
            "jwtToken"), msg="Valid register request should return success")

        valid_login_response_username = self.test_client.post("/api/v1/auth/login", json={
            "emailOrUsername": valid_register_request.username,
            "password": valid_register_request.password,
            "recaptchaToken": "aaa"
        })
        self.assertTrue("jwtToken" in valid_login_response_username.json,
                        msg="Valid register request should return success")
        self.assertIsNotNone(valid_login_response_username.json.get(
            "jwtToken"), msg="Valid register request should return success")

        valid_login_response_email = self.test_client.post("/api/v1/auth/login", json={
            "emailOrUsername": valid_register_request.email,
            "password": valid_register_request.password,
            "recaptchaToken": "aaa"
        })
        self.assertTrue("jwtToken" in valid_login_response_email.json,
                        msg="Valid register request should return success")
        self.assertIsNotNone(valid_login_response_email.json.get(
            "jwtToken"), msg="Valid register request should return success")

    @patch.object(RecaptchaService, "validate_token")
    def test_when_invalid_login_creds_return_fail(self, mock_validate_token):
        invalid_login_with_email = self.test_client.post("/api/v1/auth/login", json={
            "emailOrUsername": valid_register_request.email,
            "password": valid_register_request.password,
            "recaptchaToken": "aaa"
        })

        error_message = get_error_message(
            invalid_login_with_email.json, "__all__")

        self.assertIsNotNone(
            error_message, msg="Login requesst with invalid credentials should return fail")
        self.assertEqual(error_message, "Invalid login information",
                         msg="Login requesst with invalid credentials should return fail")


if __name__ == "__main__":
    unittest.main()

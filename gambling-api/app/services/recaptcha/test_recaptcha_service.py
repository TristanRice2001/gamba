import unittest
from unittest.mock import patch
from app.services.recaptcha import IRecaptchaService, RecaptchaService
from base64 import b64decode


class MockResponse:
    def json(self):
        return {"success": True}


class TestJwtService(unittest.TestCase):
    def setUp(self):
        from app import create_app
        self.test_token = "test_token"
        self.app = create_app()
        self.recaptcha_valid_service = RecaptchaService()
        self.recaptcha_valid_service.init_app(self.app)

    def test_when_invalid_token_then_return_false(self):
        """when a random invalid token is given to the service, it should return false"""
        result = self.recaptcha_valid_service.validate_token("aaaa")
        self.assertFalse(result, msg="Invalid token should be false!")

    @patch("requests.post")
    def test_when_valid_response_return_true(self, mock_post):
        """ When response is { "success": true }, then return true"""
        mock_post.return_value = MockResponse()

        service = RecaptchaService()

        service.init_app(self.app)

        result = service.validate_token("aaa")

        self.assertTrue(
            result, msg="Service should return true if successful response")

    def test_when_custom_key_return_true(self):
        from app import create_app

        app = create_app()

        recaptcha_service = RecaptchaService()
        app.config.update({
            "RECAPTCHA_KEY": "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"
        })

        recaptcha_service.init_app(app)
        result = recaptcha_service.validate_token("aaa")

        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()

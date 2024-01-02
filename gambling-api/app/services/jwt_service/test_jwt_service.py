import unittest
from app.services.jwt_service import JWTService, IJWTService
from base64 import b64decode


class TestJwtService(unittest.TestCase):
    def setUp(self):
        from app import create_app
        self.test_token = "test_token"
        self.app = create_app()
        self.app.config.update({
            "JWT_SECRET": self.test_token
        })

        self.jwt_service: IJWTService = JWTService()
        self.jwt_service.init_app(app=self.app)

    def test_jwt_format(self):
        # Basic payload should have the correct JWT format
        data = {"test": "test"}
        actual = self.jwt_service.encode_payload(data)

        sections = actual.split(".")

        self.assertEqual(len(sections), 3,
                         "Encoded JWT payload should have 3 sections")

        head, dat, sig = sections
        self.assertIsNotNone(head, "JWT headers are missing")
        self.assertIsNotNone(dat, "JWT data is missing")
        self.assertIsNotNone(sig, "Signature is missing")

        try:
            b64decode(dat + "==")
            b64decode(head + "==")
        except:
            self.fail("Cannot decode data or headers")

    def test_encode(self):
        # Basic payload should equal expected value
        data = {"test": "test"}
        expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCJ9.I-u_xwC37SKennvU032F6jlKLUtv8DRVVKEDhdvAHo0"
        actual = self.jwt_service.encode_payload(data, add_expiration=False)

        self.assertEqual(actual, expected, "Encoded JWT payload is not valid")

    def test_invalid_input(self):
        # Encode payload should only accept a dictionary as an argument
        data = "aa"
        expected = ValueError
        self.assertRaises(expected,
                          lambda: self.jwt_service.encode_payload(data))


if __name__ == "__main__":
    unittest.main()

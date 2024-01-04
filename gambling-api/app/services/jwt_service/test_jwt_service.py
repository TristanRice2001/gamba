import unittest
from app.services.jwt_service import JWTService, IJWTService
from .execptions import InvalidTokenException, InvalidSignatureException, ExpiredTokenError
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

    def test_when_invalid_token_then_raise_error(self):
        data = "aaa"
        expected = InvalidTokenException

        self.assertRaises(expected,
                          lambda: self.jwt_service.decode_payload(data))
        
    
    def test_when_invalid_signature_then_raise_error(self):
        # Test data with the jWT secret 'invalid_secret'
        data = """eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTcwNDM4MzU2M30.T3T28FeOCuElOvbkxSslftm_QZ37rpnPZpFrm4q_tp4"""
        expected = InvalidSignatureException

        self.assertRaises(expected,
                          lambda: self.jwt_service.decode_payload(data))

    def test_when_expired_token_then_raise_error(self):
        # Token with the exp attribute set to 100
        data = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoidGVzdCIsImV4cCI6MTAwfQ.hNLYytHDdn-9N5ytTuZYErlp6z9Yblhkl_ibvPje3YU"
        expected = ExpiredTokenError

        self.assertRaises(expected,
                          lambda: self.jwt_service.decode_payload(data))

    def test_when_valid_token_return_valid_response(self):
        data = {"test": "test"}
        jwt_token = self.jwt_service.encode_payload(data, add_expiration=False)

        decoded = self.jwt_service.decode_payload(jwt_token)

        self.assertEqual(data, decoded)
    

if __name__ == "__main__":
    unittest.main()

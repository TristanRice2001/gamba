import unittest
from app.services.hashing_service import BcryptHashingService, IHashingService
from base64 import b64decode


class TestJwtService(unittest.TestCase):
    def setUp(self):
        self.hashing_service: IHashingService = BcryptHashingService()

    def test_when_valid_hashvalue_return_valid_string(self):
        result = self.hashing_service.hash("password123")

        self.assertIsNotNone(result, msg="Hashing result should not be none")
        self.assertIsInstance(
            result, str, msg="Hashing result should be a string")
        self.assertGreater(
            len(result), 50, msg="Hash result length should be greater than 50")

    def test_when_fixed_hash_value_verify_returns_true(self):
        # Hashed value for "aaaa"
        hashed_plaintext = "aaaa"
        hashed_value = "$2b$12$XbRRufQ5vw0JcrqUu6dgYOjjNe8/ru5qaGR57hp8yVhaY8ZiTWFG6"

        result = self.hashing_service.verify(hashed_value, hashed_plaintext)

        self.assertTrue(
            result, msg="Correct hash combination should return true")

    def test_when_incorrect_verify_return_false(self):
        """ When comparing the hashed value of 'aaaa' to a random different strong, verify function should return false"""
        wrong_hashed_plaintext = "aosdjhasdokjhdsa"
        hashed_value = "$2b$12$XbRRufQ5vw0JcrqUu6dgYOjjNe8/ru5qaGR57hp8yVhaY8ZiTWFG6"

        result = self.hashing_service.verify(
            hashed_value, wrong_hashed_plaintext)

        self.assertFalse(
            result, msg="Incorrect hash / plaintext combination should return false")

    def test_hashservice_integration(self):
        """ 
        Test that hashed value with hash / verify service function should return true
        """
        password = "password"
        hashed_value = self.hashing_service.hash(password)

        result = self.hashing_service.verify(hashed_value, password)

        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()

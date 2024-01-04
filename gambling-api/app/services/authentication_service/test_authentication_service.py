import unittest
from app.services.authentication_service import JWTBasicAuthenticationService, IAuthenticationService
from app.services.jwt_service import JWTService
from app.services.user import UserService
from app.services.jwt_service.execptions import InvalidSignatureException
from base64 import b64decode
from app.models.user import UserModel
import unittest.mock


class TestJwtService(unittest.TestCase):
    def test_when_invalid_jwt_token_then_return_none(self):
        mock_jwt_service = unittest.mock.Mock(spec=JWTService)
        mock_jwt_service.decode_payload.side_effect = InvalidSignatureException("")

        mock_user_service = unittest.mock.Mock(spec=UserService)

        mock_user_service.get_user_by_id.return_value = UserModel()

        authentication_service = JWTBasicAuthenticationService(
            user_service=mock_user_service,
            jwt_service=mock_jwt_service
        )

        self.assertIsNone(authentication_service.requires_authentication("a"), msg="When invalid token, then error should be raised")

    def test_when_invalid_user_then_return_none(self):
        mock_jwt_service = unittest.mock.Mock(spec=JWTService)
        mock_jwt_service.decode_payload.side_effect = InvalidSignatureException("")

        mock_user_service = unittest.mock.Mock(spec=UserService)

        mock_user_service.get_user_by_id.return_value = None

        authentication_service = JWTBasicAuthenticationService(
            user_service=mock_user_service,
            jwt_service=mock_jwt_service
        )

        self.assertIsNone(authentication_service.requires_authentication("a"), msg="When user services returns none, then authentication service should fail")

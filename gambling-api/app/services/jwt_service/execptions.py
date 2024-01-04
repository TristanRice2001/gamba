class InvalidTokenException(Exception):
    pass


class InvalidSignatureException(Exception):
    pass


class ExpiredTokenError(Exception):
    pass
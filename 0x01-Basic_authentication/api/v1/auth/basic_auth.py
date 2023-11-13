#!/usr/bin/env python3
"""Contains a child class"""
from api.v1.auth.auth import Auth
import base64


class BasicAuth(Auth):
    """Child authentication class"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """returns the Base64 part of the
        Authorization header for a Basic Authentication
        """
        auth_h = authorization_header
        if not auth_h:
            return None
        elif not isinstance(auth_h, str):
            return None

        if auth_h[:6] == "Basic ":
            return auth_h[6:]
        else:
            return None

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """returns the decoded value of a
        Base64 string base64_authorization_header
        """
        auth_h = base64_authorization_header
        if not auth_h:
            return None
        elif not isinstance(auth_h, str):
            return None

        try:
            decoded = base64.b64decode(auth_h)
            decoded_utf8 = decoded.decode('utf-8')
            return decoded_utf8
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

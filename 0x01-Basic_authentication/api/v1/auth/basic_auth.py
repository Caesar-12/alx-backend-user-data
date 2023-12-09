#!/usr/bin/env python3
"""Contains a child class"""
from api.v1.auth.auth import Auth
import base64
from typing import TypeVar


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

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """
        returns the user email and password from the Base64 decoded value
        """
        auth_h = decoded_base64_authorization_header
        if not auth_h:
            return (None, None)
        elif not isinstance(auth_h, str):
            return (None, None)
        elif ":" not in auth_h:
            return (None, None)

        details = auth_h.split(':')
        return (details[0], details[1])

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """
        returns the User instance based on his email and password
        """
        if not isinstance(user_email, str) or not user_email:
            return None
        elif not isinstance(user_pwd, str) or not user_pwd:
            return None
        

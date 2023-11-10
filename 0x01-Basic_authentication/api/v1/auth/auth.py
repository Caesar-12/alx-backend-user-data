#!/usr/bin/env python3
"""Contains auth class"""
from flask import request
from typing import List, TypeVar


class Auth:
    """Manages API authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Determins if authentication is needed"""
        return False

    def authorization_header(self, request=None) -> str:
        """Creates authorization header"""
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Creates a user"""
        return None

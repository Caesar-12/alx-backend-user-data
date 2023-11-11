#!/usr/bin/env python3
"""Contains auth class"""
from flask import request
from typing import List, TypeVar


class Auth:
    """Manages API authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Determins if authentication is needed"""
        if not path or not excluded_paths:
            return True
        n_path = path.rstrip('/')
        n_excluded_paths = [p.rstrip('/') for p in excluded_paths]
        if n_path in n_excluded_paths:
            return False
        else:
            return True

    def authorization_header(self, request=None) -> str:
        """Creates authorization header"""
        if not request:
            return None
        elif 'Authorization' not in request.headers:
            return None
        elif 'Authorization' in request.headers:
            return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """Creates a user"""
        return request

#!/usr/bin/env python3
"""Contains function that hashes password"""
import bcrypt


def _hash_password(passwd: str) -> bytes:
    """converts passwords to bytes"""
    passwd_bytes = passwd.encode('utf-8')
    salt = bcrypt.gensalt()

    passwd_hash = bcrypt.hashpw(passwd_bytes, salt)

    return passwd_hash

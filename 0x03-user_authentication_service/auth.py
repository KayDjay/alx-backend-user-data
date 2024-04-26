#!/usr/bin/env pthon3
"""
Auth Model
"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """Hashes the input password with bcrypt.

    Args:
        password (str): The password string to be hashed.

    Returns:
        bytes: A salted hash of the input password.
    """
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed

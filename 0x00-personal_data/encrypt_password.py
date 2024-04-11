#!/usr/bin/env python3
""" This is an encrypt module"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes the given password using bcrypt.

    Args:
        password (str): The password to be hashed.

    Returns:
        bytes: The hashed password as a byte string.
    """
    salt = bcrypt.gensalt()

    # Hash the password using the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    # Return the hashed password as a byte string
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check if a password matches a hashed password.

    Args:
      hashed_password (bytes): The hashed password to compare against.
      password (str): The password to check.

    Returns:
      bool: True if the password matches the hashed password, False otherwise.
    """
    hashed_password_str = hashed_password.decode('utf-8')
    return bcrypt.checkpw(
        password.encode('utf-8'),
        hashed_password_str.encode('utf-8')
    )

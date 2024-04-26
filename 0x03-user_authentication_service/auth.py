#!/usr/bin/env python3
"""
Auth Model
"""
import bcrypt
from db import DB
from user import User
from uuid import uuid4
from typing import Union


def _generate_uuid() -> str:
    """
    Generates a string representation of a new UUID.
    """
    return str(uuid4())


def _hash_password(password: str) -> bytes:
    """Hashes the input password with bcrypt.

    Args:
        password (str): The password string to be hashed.

    Returns:
        bytes: A salted hash of the input password.
    """
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed


class Auth:
    """
    Auth class to interact with the authentication database.
    """

    def __init__(self):
        """
        Initializes an instance of the Auth class.
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a user in the database.

        Args:
          email (str): The email address of the user.
          password (str): The password of the user.

        Returns:
          None
        """

        if self._db._session.query(User).filter_by(email=email).first():
            raise ValueError(f"User {email} already exists")

        return self._db.add_user(email, _hash_password(password))
 
    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates a user's login credentials.

        Args:
        email (str): The email address of the user.
        password (str): The password of the user.

        Returns:
        bool: True if the login credentials are valid, False otherwise.
        """
        try:
            user = self._db._session.query(User).filter_by(email=email).first()
            if user:
                return bcrypt.checkpw(
                    password.encode('utf-8'),
                    user.hashed_password
                )
            return False
        except Exception:
            return False

    def create_session(self, email: str) -> Union[str, None]:
        """
        Creates a session for the user with the given email.
        """
        try:
            user = self._db._session.query(User).filter_by(email=email).first()
            if user:
                sess_id = _generate_uuid()
                user.session_id = sess_id
                self._db._session.commit()
                return sess_id
            return None
        except Exception:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """
        Retrieve a user from the database based on the
        provided session ID.

        Args:
            session_id (str): The session ID of the user.

        Returns:
            Union[dict, None]: The user object if found,
                                None otherwise.
        """
        try:
            user = self._db._session.query(User).filter_by(
                session_id=session_id).first()
            if user.session_id:
                return user
            return None
        except Exception:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Destroys a session based on the user ID.

        Args:
            user_id (int): The user ID of the user.

        Returns:
            None
        """
        try:
            user = self._db._session.query(User).filter_by(id=user_id).first()
            user.session_id = None
            self._db._session.commit()
        except Exception:
            pass

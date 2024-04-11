#!/usr/bin/env python3
""" This module helps user logging and filtering data """

import re
import logging
from typing import List
import os
import mysql.connector
from mysql.connector.connection import MySQLConnection


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """
    Replace sensitive information in a message with a redacted value.

    Args:
        fields (list): A list representing the sensitive fields to be redacted.
        redaction (str): The value to replace the sensitive information with.
        message (str): The message containing the sensitive information.
        separator (str): To separate the fields and their values.

    Returns:
        str: The message with the sensitive information redacted.
    """
    for field in fields:
        message = re.sub(f"{field}=[^{separator}]*",
                         f"{field}={redaction}", message)
    return message

# Define PII fields that you intend to obfuscate
PII_FIELDS = ('name', 'email', 'phone', 'password', 'ssn')


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str] = None):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields if fields else []

    def format(self, record: logging.LogRecord) -> str:
            """
            Formats the log record and applies data filtering.

            Args:
                record (logging.LogRecord): The log record to be formatted.

            Returns:
                str: The formatted log record with filtered data.
            """
            return filter_datum(self.fields, self.REDACTION,
                                super().format(record), self.SEPARATOR)


def get_logger() -> logging.Logger:
    """
    Setups and returns a logger with a redacting formatter
    that obfuscates PII fields.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    
    formatter = RedactingFormatter(fields=PII_FIELDS)
    
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)
    logger.propagete = False

    return logger


def get_db() -> MySQLConnection:
    """
    Retrieve database credentials from
    environment variables
    """
    username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "my_db")

    try:  # try Connecting to the database
        connection = mysql.connector.connect(
            user=username,
            password=password,
            host=host,
            database=db_name
        )
        return connection if connection.is_connected() else None
    except mysql.connector.Error as err:
        print("Error:", err)


def main() -> None:
    """
    This is the starting point to the program.

    Retrieves user data from the database and logs it using the logger.
    """
    logger = get_logger()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    param = "name={}; email={}; phone={}; ssn={}; " + \
        "password={}; ip={}; last_login={}; user_agent={};"
    for row in cursor.fetchall():
        logger.info(
            param.format(*row))
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()

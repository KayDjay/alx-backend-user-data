#!/usr/bin/env python3
""" This is Regex-ing module """

import re
import logging

def filter_datum(fields, redaction, message, separator):
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
    regex = re.compile(f"({'|'.join(fields)})=(.*?){separator}")
    return regex.sub(f"\\1={redaction}{separator}", message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    SEPARATOR = ";"

    def __init__(self, fields):
        super(RedactingFormatter, self).__init__("[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s")
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        return filter_datum(self.fields, self.REDACTION, message, self.SEPARATOR)


# Define PII fields that you intend to obfuscate
PII_FIELDS = ["username", "password", "email"]


def get_logger() -> logging.Logger:
    """
    Setups and returns a logger with a redacting formatter
    that obfuscates PII fields.
    """
    logger = logging.getLogger("PII_logger")
    logger.setLevel(logging.INFO)
    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
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

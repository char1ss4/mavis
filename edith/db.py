"""MySQL connection helper (mysql-connector-python)."""

import mysql.connector
from mysql.connector.connection import MySQLConnection

from edith import config


def get_connection() -> MySQLConnection:
    """Open a new connection to the JARVIS/EDITH database using values from config."""
    return mysql.connector.connect(
        host=config.MYSQL_HOST,
        port=config.MYSQL_PORT,
        database=config.MYSQL_DATABASE,
        user=config.MYSQL_USER,
        password=config.MYSQL_PASSWORD,
        charset="utf8mb4",
    )

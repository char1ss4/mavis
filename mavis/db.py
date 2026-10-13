"""MySQL connection helper (mysql-connector-python)."""

import mysql.connector
from mysql.connector.abstracts import MySQLConnectionAbstract
from mysql.connector.pooling import PooledMySQLConnection

from mavis import config


def get_connection() -> PooledMySQLConnection | MySQLConnectionAbstract:
    """Open a new connection to the MAVIS database using values from config."""
    return mysql.connector.connect(
        host=config.MYSQL_HOST,
        port=config.MYSQL_PORT,
        database=config.MYSQL_DATABASE,
        user=config.MYSQL_USER,
        password=config.MYSQL_PASSWORD,
        charset="utf8mb4",
    )

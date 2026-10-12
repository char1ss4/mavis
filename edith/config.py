"""Configuration loaded from the environment / a local .env file.

Secrets live in .env (never committed). See .env.example for the full list.
"""

import os

from dotenv import load_dotenv

load_dotenv()

NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

MYSQL_HOST: str = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT: int = int(os.getenv("MYSQL_PORT") or 3306)
MYSQL_DATABASE: str = os.getenv("MYSQL_DATABASE", "")
MYSQL_USER: str = os.getenv("MYSQL_USER", "")
MYSQL_PASSWORD: str = os.getenv("MYSQL_PASSWORD", "")

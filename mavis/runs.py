"""Record each feed fetch during `poll`, so the HUD can show feed health. Local only."""

from datetime import datetime
from typing import Any

from mavis.db import get_connection

FEEDS = ('NVD', 'KEV', 'EPSS')

# Also in db/schema.sql for fresh databases. Created here too so existing databases
# get the table without `docker compose down -v`, which would delete all stored data.
_CREATE_TABLE = """
    CREATE TABLE IF NOT EXISTS feed_runs (
        id           INT           NOT NULL AUTO_INCREMENT,
        feed         VARCHAR(10)   NOT NULL,
        finished_at  DATETIME      NOT NULL,
        ok           BOOLEAN       NOT NULL,
        items        INT           NULL,
        error        VARCHAR(500)  NULL,
        PRIMARY KEY (id),
        INDEX idx_feed_runs_feed (feed, finished_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """

# Newest run and newest successful run per feed
_HEALTH_QUERY = """
    SELECT
        feed
        , MAX(finished_at)                       AS last_attempt_at
        , MAX(CASE WHEN ok THEN finished_at END) AS last_success_at
    FROM feed_runs
    GROUP BY feed
    """
_LATEST_ERROR_QUERY = """
    SELECT error FROM feed_runs WHERE feed = %s ORDER BY finished_at DESC, id DESC LIMIT 1
    """


def ensure_table() -> None:
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(_CREATE_TABLE)
    finally:
        cursor.close()
        conn.close()


def record_run(feed: str, ok: bool, items: int | None = None, error: str | None = None) -> None:
    """Store the outcome of one fetch. ``error`` is cut to fit the column."""
    ensure_table()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO feed_runs (feed, finished_at, ok, items, error) VALUES (%s, %s, %s, %s, %s)",
            (feed, datetime.now(), ok, items, error[:500] if error else None),
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def feed_health() -> list[dict[str, Any]]:
    """One entry per feed: last attempt, last success, and the error if the last attempt failed."""
    ensure_table()
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(_HEALTH_QUERY)
        rows = {row['feed']: row for row in cursor.fetchall()}
        health = []
        for feed in FEEDS:
            row = rows.get(feed, {})
            error = None
            if row and row['last_attempt_at'] != row['last_success_at']:
                cursor.execute(_LATEST_ERROR_QUERY, (feed,))
                error = cursor.fetchone()['error']
            health.append({
                'feed': feed,
                'last_attempt_at': row.get('last_attempt_at'),
                'last_success_at': row.get('last_success_at'),
                'last_error': error,
            })
        return health
    finally:
        cursor.close()
        conn.close()

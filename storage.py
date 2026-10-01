import math
import os
from threading import Lock

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://sentinelstream:sentinelstream@localhost:5432/sentinelstream",
)

_pool = None
_pool_lock = Lock()


def _get_pool():
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                from psycopg2.pool import ThreadedConnectionPool

                _pool = ThreadedConnectionPool(
                    minconn=1,
                    maxconn=8,
                    dsn=DATABASE_URL,
                    connect_timeout=3,
                )
    return _pool


def json_safe_value(value):
    if isinstance(value, dict):
        return {key: json_safe_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe_value(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def initialize_storage():
    pool = _get_pool()
    connection = pool.getconn()
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        id BIGSERIAL PRIMARY KEY,
                        uid TEXT,
                        event_ts DOUBLE PRECISION,
                        payload JSONB NOT NULL,
                        ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                )
                cursor.execute("ALTER TABLE events DROP CONSTRAINT IF EXISTS events_uid_key")
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS events_event_ts_idx ON events (event_ts DESC)"
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id BIGSERIAL PRIMARY KEY,
                        event_id BIGINT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                        rule_id TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        payload JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        UNIQUE (event_id, rule_id)
                    )
                    """
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS alerts_created_at_idx ON alerts (created_at DESC)"
                )
    finally:
        pool.putconn(connection)


def check_storage():
    pool = _get_pool()
    connection = pool.getconn()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return True
    finally:
        pool.putconn(connection)


def persist_event(event, alerts):
    """Insert one raw event and its related alerts in a single transaction."""
    from psycopg2.extras import Json

    pool = _get_pool()
    connection = pool.getconn()
    clean_event = json_safe_value(event)
    uid = clean_event.get("uid")
    if isinstance(uid, float) and not math.isfinite(uid):
        uid = None
    uid = str(uid) if uid is not None else None
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO events (uid, event_ts, payload)
                    VALUES (%s, %s, %s)
                    RETURNING id
                    """,
                    (uid, _event_timestamp(clean_event), Json(clean_event)),
                )
                event_id = cursor.fetchone()[0]

                for alert in alerts:
                    clean_alert = json_safe_value(alert)
                    cursor.execute(
                        """
                        INSERT INTO alerts (event_id, rule_id, severity, payload)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (event_id, rule_id) DO NOTHING
                        """,
                        (
                            event_id,
                            str(clean_alert.get("rule_id", "UNKNOWN")),
                            str(clean_alert.get("severity", "LOW")),
                            Json(clean_alert),
                        ),
                    )
        return event_id
    finally:
        pool.putconn(connection)


def _event_timestamp(event):
    try:
        value = float(event.get("ts"))
        return value if math.isfinite(value) else None
    except (TypeError, ValueError):
        return None


def get_events(limit=100, offset=0):
    from psycopg2.extras import RealDictCursor

    pool = _get_pool()
    connection = pool.getconn()
    try:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, event_ts, payload, ingested_at
                FROM events
                ORDER BY event_ts DESC NULLS LAST, id DESC
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )
            return [dict(row) for row in cursor.fetchall()]
    finally:
        pool.putconn(connection)


def get_stored_alerts(limit=100, offset=0):
    from psycopg2.extras import RealDictCursor

    pool = _get_pool()
    connection = pool.getconn()
    try:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT id, event_id, rule_id, severity, payload, created_at
                FROM alerts
                ORDER BY created_at DESC, id DESC
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )
            return [dict(row) for row in cursor.fetchall()]
    finally:
        pool.putconn(connection)


def close_storage():
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.closeall()
            _pool = None
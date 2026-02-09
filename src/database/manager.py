import os
import psycopg2
from psycopg2.extras import RealDictCursor

DB_USER = os.getenv("DB_USER", "vtsaiber")
DB_PASSWORD = os.getenv("DB_PASSWORD", "vtsaiber")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "vtsaiber")


def get_connection():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
    )


def test_connection():
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT 1 AS ok;")
            return cur.fetchone()
    finally:
        conn.close()


def create_target(name, target_type, target_url, status, description=None):
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO targets (name, target_type, target_url, status, description)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING *;
                """,
                (name, target_type, target_url, status, description),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        conn.close()


def get_targets():
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM targets ORDER BY id;")
            return cur.fetchall()
    finally:
        conn.close()

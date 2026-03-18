from contextlib import contextmanager
from typing import Any, Iterable

import pymysql
from dbutils.pooled_db import PooledDB

from core.config import settings


_pool = PooledDB(
    creator=pymysql,
    maxconnections=10,
    mincached=1,
    maxcached=5,
    blocking=True,
    host=settings.DB_HOST,
    port=settings.DB_PORT,
    user=settings.DB_USER,
    password=settings.DB_PASSWORD,
    database=settings.DB_NAME,
    charset="utf8mb4",
    cursorclass=pymysql.cursors.DictCursor,
    autocommit=False,
)


@contextmanager
def get_connection():
    conn = _pool.connection()
    try:
        yield conn
    finally:
        conn.close()


def _normalize_params(params: Iterable[Any] | None) -> Iterable[Any]:
    return () if params is None else params


def execute(sql: str, params: Iterable[Any] | None = None) -> tuple[int, int]:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            rows = cursor.execute(sql, _normalize_params(params))
            lastrowid = cursor.lastrowid
        conn.commit()
    return rows, lastrowid


def fetch_one(sql: str, params: Iterable[Any] | None = None) -> dict | None:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, _normalize_params(params))
            return cursor.fetchone()


def fetch_all(sql: str, params: Iterable[Any] | None = None) -> list[dict]:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, _normalize_params(params))
            return list(cursor.fetchall())

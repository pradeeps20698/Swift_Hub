"""Postgres helpers for Swift Hub user management."""
from __future__ import annotations

import psycopg2
import psycopg2.extras
import streamlit as st


@st.cache_resource(show_spinner=False)
def get_conn():
    cfg = st.secrets["database"]
    conn = psycopg2.connect(
        host=cfg["host"],
        port=int(cfg.get("port", 5432)),
        user=cfg["user"],
        password=cfg["password"],
        dbname=cfg["dbname"],
    )
    conn.autocommit = True
    return conn


def init_users_table() -> None:
    with get_conn().cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS swift_hub_users (
                email       TEXT PRIMARY KEY,
                name        TEXT,
                role        TEXT NOT NULL DEFAULT 'user',
                is_blocked  BOOLEAN NOT NULL DEFAULT FALSE,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            """
        )


def list_users() -> list[dict]:
    with get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT email, name, role, is_blocked, created_at FROM swift_hub_users ORDER BY email"
        )
        return [dict(r) for r in cur.fetchall()]


def get_user(email: str) -> dict | None:
    email = email.lower().strip()
    with get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT email, name, role, is_blocked FROM swift_hub_users WHERE email = %s",
            (email,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def upsert_user(email: str, name: str = "", role: str = "user", is_blocked: bool = False) -> None:
    email = email.lower().strip()
    with get_conn().cursor() as cur:
        cur.execute(
            """
            INSERT INTO swift_hub_users (email, name, role, is_blocked)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (email) DO UPDATE
              SET name = EXCLUDED.name,
                  role = EXCLUDED.role,
                  is_blocked = EXCLUDED.is_blocked,
                  updated_at = NOW();
            """,
            (email, name, role, is_blocked),
        )


def delete_user(email: str) -> None:
    email = email.lower().strip()
    with get_conn().cursor() as cur:
        cur.execute("DELETE FROM swift_hub_users WHERE email = %s", (email,))


def set_blocked(email: str, blocked: bool) -> None:
    email = email.lower().strip()
    with get_conn().cursor() as cur:
        cur.execute(
            "UPDATE swift_hub_users SET is_blocked = %s, updated_at = NOW() WHERE email = %s",
            (blocked, email),
        )


def count_users() -> int:
    with get_conn().cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM swift_hub_users")
        return cur.fetchone()[0]

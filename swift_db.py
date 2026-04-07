"""Postgres helpers for Swift Hub: users, permissions, access logs."""
from __future__ import annotations

import psycopg2
import psycopg2.extras
import streamlit as st


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
def init_schema() -> None:
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

            CREATE TABLE IF NOT EXISTS swift_hub_dashboard_permissions (
                role           TEXT NOT NULL,
                dashboard_key  TEXT NOT NULL,
                PRIMARY KEY (role, dashboard_key)
            );

            CREATE TABLE IF NOT EXISTS swift_hub_access_logs (
                id             BIGSERIAL PRIMARY KEY,
                email          TEXT NOT NULL,
                dashboard_key  TEXT,
                action         TEXT NOT NULL,
                ts             TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_swift_hub_access_logs_ts
              ON swift_hub_access_logs (ts DESC);
            CREATE INDEX IF NOT EXISTS idx_swift_hub_access_logs_email
              ON swift_hub_access_logs (email);
            """
        )


# Backwards-compat alias
def init_users_table() -> None:
    init_schema()


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Dashboard permissions
# ---------------------------------------------------------------------------
def list_permissions() -> list[dict]:
    with get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT role, dashboard_key FROM swift_hub_dashboard_permissions ORDER BY role, dashboard_key"
        )
        return [dict(r) for r in cur.fetchall()]


def get_permitted_dashboards(role: str) -> set[str]:
    with get_conn().cursor() as cur:
        cur.execute(
            "SELECT dashboard_key FROM swift_hub_dashboard_permissions WHERE role = %s",
            (role,),
        )
        return {r[0] for r in cur.fetchall()}


def grant_permission(role: str, dashboard_key: str) -> None:
    with get_conn().cursor() as cur:
        cur.execute(
            """
            INSERT INTO swift_hub_dashboard_permissions (role, dashboard_key)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING;
            """,
            (role, dashboard_key),
        )


def revoke_permission(role: str, dashboard_key: str) -> None:
    with get_conn().cursor() as cur:
        cur.execute(
            "DELETE FROM swift_hub_dashboard_permissions WHERE role = %s AND dashboard_key = %s",
            (role, dashboard_key),
        )


def set_role_permissions(role: str, dashboard_keys: list[str]) -> None:
    with get_conn().cursor() as cur:
        cur.execute(
            "DELETE FROM swift_hub_dashboard_permissions WHERE role = %s", (role,)
        )
        for k in dashboard_keys:
            cur.execute(
                "INSERT INTO swift_hub_dashboard_permissions (role, dashboard_key) VALUES (%s, %s)",
                (role, k),
            )


def user_can_access(email: str, dashboard_key: str) -> bool:
    u = get_user(email)
    if not u or u["is_blocked"]:
        return False
    if u["role"] == "admin":
        return True
    return dashboard_key in get_permitted_dashboards(u["role"])


# ---------------------------------------------------------------------------
# Access logs
# ---------------------------------------------------------------------------
def log_access(email: str, action: str, dashboard_key: str | None = None) -> None:
    try:
        with get_conn().cursor() as cur:
            cur.execute(
                "INSERT INTO swift_hub_access_logs (email, dashboard_key, action) VALUES (%s, %s, %s)",
                (email.lower().strip(), dashboard_key, action),
            )
    except Exception:
        # Logging must never break the app.
        pass


def recent_logs(limit: int = 200) -> list[dict]:
    with get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT email, dashboard_key, action, ts FROM swift_hub_access_logs ORDER BY ts DESC LIMIT %s",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]

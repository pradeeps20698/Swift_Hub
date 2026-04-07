"""Drop-in auth + access control for child dashboards (Trip Log, Billing, etc.).

Usage in a child dashboard's main script:

    from swift_auth_child import require_dashboard_access

    user = require_dashboard_access("trip_log")  # use the matching DASHBOARD key

This will:
  - force Google login (st.login)
  - look the user up in swift_hub_users (shared Postgres)
  - check that their role has permission for this dashboard_key
  - log the open into swift_hub_access_logs
  - render a Sign-out button in the sidebar

The child dashboard MUST share the same `[auth]` and `[database]` secrets
as Swift Hub (copy them into its .streamlit/secrets.toml on Streamlit Cloud).
"""
from __future__ import annotations

import streamlit as st

from swift_db import (
    get_user,
    init_schema,
    log_access,
    user_can_access,
)


def _login_gate() -> str:
    if not getattr(st.user, "is_logged_in", False):
        st.title("Sign in required")
        st.write("Please sign in with your company Google account.")
        if st.button("Sign in with Google", type="primary"):
            st.login()
        st.stop()
    return (getattr(st.user, "email", "") or "").lower()


def require_dashboard_access(dashboard_key: str) -> dict:
    """Block the page until the user is logged in AND permitted for this dashboard.

    Returns a dict with email/name/role.
    """
    email = _login_gate()

    try:
        init_schema()
    except Exception as e:
        st.error(f"Database unavailable: {e}")
        st.stop()

    row = get_user(email)
    if row is None:
        st.error(f"{email} is not provisioned in Swift Hub. Ask an administrator to add you.")
        if st.button("Sign out"):
            st.logout()
        st.stop()

    if row["is_blocked"]:
        st.error(f"Access for {email} has been revoked.")
        if st.button("Sign out"):
            st.logout()
        st.stop()

    if not user_can_access(email, dashboard_key):
        log_access(email, action="denied", dashboard_key=dashboard_key)
        st.error(
            f"Your role (`{row['role']}`) does not have access to this dashboard. "
            "Contact an administrator."
        )
        if st.button("Sign out"):
            st.logout()
        st.stop()

    if not st.session_state.get(f"_logged_open_{dashboard_key}"):
        log_access(email, action="open", dashboard_key=dashboard_key)
        st.session_state[f"_logged_open_{dashboard_key}"] = True

    _sidebar_box(row)
    return {
        "email": email,
        "name": getattr(st.user, "name", "") or row.get("name") or "",
        "role": row["role"],
    }


def _sidebar_box(row: dict) -> None:
    with st.sidebar:
        pic = getattr(st.user, "picture", "")
        name = getattr(st.user, "name", "") or row.get("name") or ""
        email = getattr(st.user, "email", "")
        if pic:
            st.image(pic, width=64)
        st.markdown(f"**{name}**")
        st.caption(email)
        st.caption(f"Role: `{row['role']}`")
        if st.button("Sign out", use_container_width=True):
            st.logout()

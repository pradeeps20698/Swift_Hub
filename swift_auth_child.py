"""Drop-in OTP auth + access control for child dashboards.

Usage in a child dashboard's main script:

    from swift_auth_child import require_dashboard_access
    user = require_dashboard_access("trip_log")

Each child app runs its own OTP login (Streamlit Cloud apps don't share
session state across subdomains), but they all share the same Postgres
user table, so a user added in Swift Hub can immediately log in to any
child dashboard their role permits.
"""
from __future__ import annotations

import time

import streamlit as st

# Reuse the same OTP gate from swift_auth so behavior stays in sync.
from swift_auth import require_login as _hub_require_login
from swift_db import (
    init_schema,
    log_access,
    user_can_access,
)


def require_dashboard_access(dashboard_key: str) -> dict:
    """Block the page until the user is logged in AND permitted for this dashboard."""
    try:
        init_schema()
    except Exception as e:
        st.error(f"Database unavailable: {e}")
        st.stop()

    user = _hub_require_login()  # forces OTP gate, returns dict with email/role

    if not user_can_access(user["email"], dashboard_key):
        log_access(user["email"], action="denied", dashboard_key=dashboard_key)
        st.error(
            f"Your role (`{user['role']}`) does not have access to this dashboard. "
            "Contact an administrator."
        )
        st.stop()

    if not st.session_state.get(f"_logged_open_{dashboard_key}"):
        log_access(user["email"], action="open", dashboard_key=dashboard_key)
        st.session_state[f"_logged_open_{dashboard_key}"] = True

    # Heartbeat: log activity every 10 minutes while the user is interacting.
    # Streamlit reruns this code on every widget interaction, so as long as
    # the user keeps clicking, heartbeats keep flowing.
    HEARTBEAT_INTERVAL = 10 * 60  # seconds
    beat_key = f"_last_heartbeat_{dashboard_key}"
    last_beat = st.session_state.get(beat_key, 0)
    now = time.time()
    if now - last_beat >= HEARTBEAT_INTERVAL:
        log_access(user["email"], action="heartbeat", dashboard_key=dashboard_key)
        st.session_state[beat_key] = now

    return user

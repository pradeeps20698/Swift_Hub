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

from swift_auth import SESSION_KEY, RAW_TOKEN_KEY
from swift_db import (
    get_user,
    init_schema,
    log_access,
    lookup_session,
    user_can_access,
)

SWIFT_HUB_URL = "https://swiftapp-838rpjkwfx8t2uprdmffsd.streamlit.app/"


def _block_with_hub_redirect() -> None:
    """Render an in-iframe page that auto-redirects the top window to Swift Hub."""
    import streamlit.components.v1 as components

    components.html(
        f"""
        <html>
          <body style="background:#0e1117;color:#fff;font-family:-apple-system,
                       BlinkMacSystemFont,sans-serif;text-align:center;
                       padding-top:80px;margin:0">
            <h1 style="font-size:38px">🔒 Access via Swift Hub</h1>
            <p style="color:#888;font-size:18px">
              This dashboard can only be opened from Swift Hub.
            </p>
            <p style="margin-top:32px">
              <a href="{SWIFT_HUB_URL}" target="_top" rel="noopener"
                 style="background:#ff4b4b;color:#fff;text-decoration:none;
                        padding:14px 36px;border-radius:8px;font-size:16px;
                        font-weight:600;display:inline-block">
                Go to Swift Hub →
              </a>
            </p>
            <p style="margin-top:16px;font-size:13px;color:#666">
              If the button doesn't work,
              <a href="{SWIFT_HUB_URL}" target="_blank" rel="noopener"
                 style="color:#888">open Swift Hub in a new tab</a>.
            </p>
          </body>
        </html>
        """,
        height=420,
    )
    st.stop()


def require_dashboard_access(dashboard_key: str) -> dict:
    """Allow the page only if the user arrived via a valid Swift Hub ?s= token.
    Otherwise show a 'Go to Swift Hub' page — never an OTP login screen."""
    try:
        init_schema()
    except Exception:
        _block_with_hub_redirect()

    # Already authenticated in this Streamlit session? (refresh / interaction)
    email = st.session_state.get(SESSION_KEY)

    if not email:
        # Look for a session token passed from Swift Hub via ?s=<token>
        try:
            raw = st.query_params.get("s")
        except Exception:
            raw = None
        if not raw:
            _block_with_hub_redirect()

        session_email = lookup_session(raw)
        if not session_email:
            _block_with_hub_redirect()

        row = get_user(session_email)
        if not row or row["is_blocked"]:
            _block_with_hub_redirect()

        st.session_state[SESSION_KEY] = session_email
        st.session_state[RAW_TOKEN_KEY] = raw
        email = session_email

    # Build the user dict locally (no OTP gate involved)
    row = get_user(email)
    if not row or row["is_blocked"]:
        _block_with_hub_redirect()

    user = {
        "email": email,
        "name": row.get("name") or "",
        "role": row["role"],
    }

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

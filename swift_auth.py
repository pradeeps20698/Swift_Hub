"""Email-OTP auth gate for Swift Hub.

Flow:
  1. User enters their email.
  2. We generate a 6-digit code, store its hash in Postgres, and email it.
     (If SMTP isn't configured, we show the code on-screen for dev/testing.)
  3. User enters the code.
  4. On success, we look up / auto-provision the user in swift_hub_users
     and set st.session_state["sh_user_email"] for the rest of the session.

Domain restrictions and blocked users still apply.
"""
from __future__ import annotations

import re

import streamlit as st
from streamlit_cookies_controller import CookieController

from swift_db import (
    consume_login_code,
    count_users,
    get_user,
    init_schema,
    log_access,
    store_login_code,
    upsert_user,
)
from swift_otp import generate_code, hash_code, send_code, smtp_configured
from swift_session import COOKIE_NAME, DEFAULT_TTL_SECONDS, make_token, verify_token

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
SESSION_KEY = "sh_user_email"


def _cookie_controller() -> CookieController:
    if "sh_cookie_ctrl" not in st.session_state:
        st.session_state["sh_cookie_ctrl"] = CookieController(key="sh_cookie_ctrl")
    return st.session_state["sh_cookie_ctrl"]


def _set_session_cookie(email: str) -> None:
    token = make_token(email)
    try:
        _cookie_controller().set(
            COOKIE_NAME, token, max_age=DEFAULT_TTL_SECONDS, path="/"
        )
    except Exception:
        pass


def _clear_session_cookie() -> None:
    try:
        _cookie_controller().remove(COOKIE_NAME, path="/")
    except Exception:
        pass


def _restore_from_cookie() -> str | None:
    try:
        token = _cookie_controller().get(COOKIE_NAME)
    except Exception:
        return None
    if not token:
        return None
    return verify_token(token)


def _app_cfg():
    try:
        return st.secrets["app"]
    except Exception:
        return {}


def _allowed_domains() -> list[str]:
    cfg = _app_cfg()
    domains = cfg.get("allowed_email_domains")
    if domains:
        return [d.lower() for d in domains]
    single = cfg.get("allowed_email_domain")
    return [single.lower()] if single else []


def _bootstrap_admins() -> list[str]:
    return [e.lower() for e in (_app_cfg().get("bootstrap_admins") or [])]


def _ensure_bootstrap() -> None:
    init_schema()
    if count_users() == 0:
        for email in _bootstrap_admins():
            upsert_user(email=email, role="admin")


def is_admin(email: str) -> bool:
    u = get_user(email)
    return bool(u and u["role"] == "admin" and not u["is_blocked"])


# ---------------------------------------------------------------------------
# Login UI
# ---------------------------------------------------------------------------
def _domain_ok(email: str) -> bool:
    domains = _allowed_domains()
    if not domains:
        return True
    return any(email.endswith("@" + d) for d in domains)


def _request_code_ui() -> None:
    st.title("🚛 Swift Hub")
    st.write("Sign in with your company email.")

    with st.form("request_code_form"):
        email = st.text_input("Email", placeholder="you@srlpl.in")
        submit = st.form_submit_button("Send login code", type="primary")

    if not submit:
        return

    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        st.error("Enter a valid email address.")
        return
    if not _domain_ok(email):
        allowed = ", ".join("@" + d for d in _allowed_domains())
        st.error(f"Only {allowed} accounts are allowed.")
        return

    # Generate, store, send
    code = generate_code()
    try:
        store_login_code(email, hash_code(code), ttl_seconds=600)
    except Exception as e:
        st.error(f"Could not store login code: {e}")
        return

    sent, info = send_code(email, code)
    st.session_state["sh_pending_email"] = email
    if sent:
        st.success(f"A 6-digit login code has been sent to {email}. It expires in 10 minutes.")
    else:
        # Dev / fallback mode
        if not smtp_configured():
            st.warning(
                "SMTP not configured yet — showing code on screen for testing. "
                "Configure `[smtp]` in Streamlit Cloud Secrets to email codes."
            )
            st.code(code, language="text")
        else:
            st.error(f"Could not send email: {info}")
    st.rerun()


def _verify_code_ui() -> None:
    email = st.session_state.get("sh_pending_email", "")
    st.title("🚛 Swift Hub")
    st.write(f"Enter the 6-digit code sent to **{email}**.")

    with st.form("verify_code_form"):
        code = st.text_input("Login code", max_chars=6, placeholder="123456")
        c1, c2 = st.columns(2)
        verify = c1.form_submit_button("Verify", type="primary")
        change = c2.form_submit_button("Use a different email")

    if change:
        st.session_state.pop("sh_pending_email", None)
        st.rerun()
        return

    if not verify:
        return

    code = (code or "").strip()
    if not code.isdigit() or len(code) != 6:
        st.error("Enter the 6-digit code.")
        return

    try:
        ok = consume_login_code(email, hash_code(code))
    except Exception as e:
        st.error(f"Database error: {e}")
        return

    if not ok:
        st.error("Invalid or expired code. Request a new one.")
        return

    # Success — auto-provision user if needed
    row = get_user(email)
    if row is None:
        upsert_user(email=email, name="", role="user")
        row = get_user(email)

    if row["is_blocked"]:
        st.error(f"Access for {email} has been revoked.")
        return

    st.session_state[SESSION_KEY] = email
    st.session_state.pop("sh_pending_email", None)
    _set_session_cookie(email)
    log_access(email, action="login")
    st.rerun()


def require_login() -> dict:
    """Block the page until the user has verified an OTP. Returns user dict."""
    try:
        _ensure_bootstrap()
    except Exception as e:
        st.error(f"Database unavailable: {e}")
        st.stop()

    email = st.session_state.get(SESSION_KEY)
    if not email:
        # Try to restore from a previously-issued signed cookie
        cookie_email = _restore_from_cookie()
        if cookie_email:
            row = get_user(cookie_email)
            if row and not row["is_blocked"]:
                st.session_state[SESSION_KEY] = cookie_email
                email = cookie_email
            else:
                _clear_session_cookie()
        elif not st.session_state.get("sh_cookie_checked"):
            # First load: JS cookie component may not have populated yet.
            # Rerun once to give it a chance before showing the login UI.
            st.session_state["sh_cookie_checked"] = True
            st.rerun()

    if not email:
        if st.session_state.get("sh_pending_email"):
            _verify_code_ui()
        else:
            _request_code_ui()
        st.stop()

    row = get_user(email)
    if row is None or row["is_blocked"]:
        st.session_state.pop(SESSION_KEY, None)
        st.error("Your access has been revoked. Please sign in again.")
        st.stop()

    return {
        "email": email,
        "name": row.get("name") or "",
        "role": row["role"],
    }


def sidebar_user_box() -> None:
    email = st.session_state.get(SESSION_KEY)
    if not email:
        return
    row = get_user(email) or {}
    with st.sidebar:
        st.markdown(f"**{row.get('name') or email}**")
        st.caption(email)
        st.caption(f"Role: `{row.get('role', 'user')}`")
        if st.button("Sign out", use_container_width=True):
            st.session_state.pop(SESSION_KEY, None)
            _clear_session_cookie()
            st.rerun()

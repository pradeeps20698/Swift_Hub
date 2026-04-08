"""Email-OTP auth gate for Swift Hub.

Login persistence:
  - On successful OTP verify, we create a DB-backed session
    (`swift_hub_sessions`). Only the SHA-256 hash of the random token
    is stored server-side; the raw token lives only in the user's browser.
  - The raw token is persisted in browser localStorage via
    `streamlit-local-storage`. As a fallback (e.g. iframe sandbox blocks
    localStorage) it is also written to a `?s=` query param so refresh
    still works without exposing user identity in the URL.
  - Sessions are revocable: Sign Out marks the row revoked; admins can
    revoke any active session from the DB.
"""
from __future__ import annotations

import re

import streamlit as st
from streamlit_local_storage import LocalStorage

from swift_db import (
    consume_login_code,
    count_users,
    create_session,
    get_user,
    init_schema,
    log_access,
    lookup_session,
    revoke_all_sessions_for,
    revoke_session,
    store_login_code,
    upsert_user,
)
from swift_otp import generate_code, hash_code, send_code, smtp_configured

LS_KEY = "sh_sid"
QP_KEY = "s"
SESSION_KEY = "sh_user_email"
RAW_TOKEN_KEY = "sh_raw_token"

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


# ---------------------------------------------------------------------------
# Session-token storage (browser side)
# ---------------------------------------------------------------------------
def _local_storage() -> LocalStorage:
    if "sh_local_storage" not in st.session_state:
        st.session_state["sh_local_storage"] = LocalStorage()
    return st.session_state["sh_local_storage"]


def _read_token_from_browser() -> str | None:
    """Try localStorage first, then query-param fallback."""
    token: str | None = None
    try:
        token = _local_storage().getItem(LS_KEY)
    except Exception:
        token = None
    if token:
        return token
    try:
        qp = st.query_params.get(QP_KEY)
        if qp:
            return qp
    except Exception:
        pass
    return None


def _write_token_to_browser(raw_token: str) -> None:
    try:
        _local_storage().setItem(LS_KEY, raw_token, key="sh_ls_set")
    except Exception:
        pass
    # Also stash in URL as a reliable fallback for environments where
    # localStorage isn't writable from the iframe.
    try:
        st.query_params[QP_KEY] = raw_token
    except Exception:
        pass


def _clear_token_from_browser() -> None:
    try:
        _local_storage().deleteItem(LS_KEY, key="sh_ls_del")
    except Exception:
        pass
    try:
        if QP_KEY in st.query_params:
            del st.query_params[QP_KEY]
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------
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

    row = get_user(email)
    if row is None:
        upsert_user(email=email, name="", role="user")
        row = get_user(email)

    if row["is_blocked"]:
        st.error(f"Access for {email} has been revoked.")
        return

    # Create a server-side session and hand the raw token to the browser
    raw_token = create_session(email)
    st.session_state[SESSION_KEY] = email
    st.session_state[RAW_TOKEN_KEY] = raw_token
    st.session_state.pop("sh_pending_email", None)
    _write_token_to_browser(raw_token)
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
    raw_token = st.session_state.get(RAW_TOKEN_KEY)

    # Always re-validate the session against the DB on every render so a
    # revoked session (e.g. via Sign Out from another tab) kicks the user
    # out of any tab on its next interaction.
    if email and raw_token:
        if not lookup_session(raw_token):
            st.session_state.pop(SESSION_KEY, None)
            st.session_state.pop(RAW_TOKEN_KEY, None)
            _clear_token_from_browser()
            email = None

    if not email:
        # Try to restore from a previously-issued session token in the browser
        raw_token = _read_token_from_browser()
        if raw_token:
            session_email = lookup_session(raw_token)
            if session_email:
                row = get_user(session_email)
                if row and not row["is_blocked"]:
                    st.session_state[SESSION_KEY] = session_email
                    st.session_state[RAW_TOKEN_KEY] = raw_token
                    email = session_email
                    # Migrate URL fallback into localStorage and clean URL
                    _write_token_to_browser(raw_token)
                else:
                    revoke_session(raw_token)
                    _clear_token_from_browser()
            else:
                _clear_token_from_browser()
        elif not st.session_state.get("sh_ls_checked"):
            # First load: localStorage component returns None on initial
            # render; rerun once so the JS roundtrip can complete.
            st.session_state["sh_ls_checked"] = True
            st.rerun()

    if not email:
        if st.session_state.get("sh_pending_email"):
            _verify_code_ui()
        else:
            _request_code_ui()
        st.stop()

    row = get_user(email)
    if row is None or row["is_blocked"]:
        raw = st.session_state.pop(RAW_TOKEN_KEY, None)
        if raw:
            revoke_session(raw)
        st.session_state.pop(SESSION_KEY, None)
        _clear_token_from_browser()
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
            # Revoke ALL active sessions for this user so every open
            # dashboard tab gets kicked out on its next interaction.
            try:
                revoke_all_sessions_for(email)
            except Exception:
                pass
            st.session_state.pop(RAW_TOKEN_KEY, None)
            st.session_state.pop(SESSION_KEY, None)
            _clear_token_from_browser()
            st.rerun()

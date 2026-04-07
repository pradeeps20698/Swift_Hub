"""Reusable auth helper for Swift Hub and child dashboards.

Uses Streamlit's native st.login() (OIDC) with Google as the provider.
Restricts access to a configured email domain.
"""
from __future__ import annotations

import streamlit as st


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


def _allowed_emails() -> list[str]:
    cfg = _app_cfg()
    emails = cfg.get("allowed_emails") or []
    return [e.lower() for e in emails]


def _blocked_emails() -> list[str]:
    cfg = _app_cfg()
    emails = cfg.get("blocked_emails") or []
    return [e.lower() for e in emails]


def require_login(provider: str | None = None) -> dict:
    """Block the page until the user is logged in with an allowed email.

    Returns the user info dict on success.
    """
    if not getattr(st.user, "is_logged_in", False):
        st.title("Swift Hub")
        st.write("Please sign in to continue.")
        if st.button("Sign in with Google", type="primary"):
            if provider:
                st.login(provider)
            else:
                st.login()
        st.stop()

    email = (getattr(st.user, "email", "") or "").lower()
    domains = _allowed_domains()
    allow_list = _allowed_emails()
    block_list = _blocked_emails()

    denied_reason = None
    if email in block_list:
        denied_reason = f"Access for {email} has been revoked."
    elif allow_list:
        # Explicit allowlist takes precedence — user must be on it.
        if email not in allow_list:
            denied_reason = f"{email} is not authorized to access Swift Hub."
    elif domains:
        if not any(email.endswith("@" + d) for d in domains):
            allowed = ", ".join("@" + d for d in domains)
            denied_reason = f"Access restricted to {allowed} accounts. You are signed in as {email}."

    if denied_reason:
        st.error(denied_reason)
        if st.button("Sign out"):
            st.logout()
        st.stop()

    return {
        "email": email,
        "name": getattr(st.user, "name", ""),
        "picture": getattr(st.user, "picture", ""),
    }


def sidebar_user_box() -> None:
    """Render a small user box + logout button in the sidebar."""
    if not getattr(st.user, "is_logged_in", False):
        return
    with st.sidebar:
        pic = getattr(st.user, "picture", "")
        name = getattr(st.user, "name", "")
        email = getattr(st.user, "email", "")
        if pic:
            st.image(pic, width=64)
        st.markdown(f"**{name}**")
        st.caption(email)
        if st.button("Sign out", use_container_width=True):
            st.logout()

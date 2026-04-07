"""Reusable auth helper for Swift Hub and child dashboards.

Uses Streamlit's native st.login() (OIDC) with Google as the provider.
Restricts access to a configured email domain.
"""
from __future__ import annotations

import streamlit as st


def _allowed_domain() -> str:
    try:
        return st.secrets["app"]["allowed_email_domain"]
    except Exception:
        return ""


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
    domain = _allowed_domain().lower()
    if domain and not email.endswith("@" + domain):
        st.error(f"Access restricted to @{domain} accounts. You are signed in as {email}.")
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

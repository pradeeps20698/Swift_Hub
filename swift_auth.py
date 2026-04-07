"""Reusable auth helper for Swift Hub and child dashboards.

Uses Streamlit's native st.login() (OIDC) with Google as the provider.
Restricts access to a configured email domain.
"""
from __future__ import annotations

import streamlit as st


def _allowed_domains() -> list[str]:
    try:
        app_cfg = st.secrets["app"]
    except Exception:
        return []
    domains = app_cfg.get("allowed_email_domains")
    if domains:
        return [d.lower() for d in domains]
    single = app_cfg.get("allowed_email_domain")
    return [single.lower()] if single else []


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
    if domains and not any(email.endswith("@" + d) for d in domains):
        allowed = ", ".join("@" + d for d in domains)
        st.error(f"Access restricted to {allowed} accounts. You are signed in as {email}.")
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

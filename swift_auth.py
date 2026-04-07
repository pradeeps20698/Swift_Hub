"""Reusable auth helper for Swift Hub and child dashboards.

Uses Streamlit's native st.login() (OIDC) with Google as the provider.
Access is gated against a Postgres-backed user table (swift_hub_users).
On first run, the table is auto-created and bootstrap admins from
secrets are seeded.
"""
from __future__ import annotations

import streamlit as st

from swift_db import (
    count_users,
    get_user,
    init_users_table,
    upsert_user,
)


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
    cfg = _app_cfg()
    return [e.lower() for e in (cfg.get("bootstrap_admins") or [])]


def _ensure_bootstrap() -> None:
    """Create the table and seed bootstrap admins if it's empty."""
    init_users_table()
    if count_users() == 0:
        for email in _bootstrap_admins():
            upsert_user(email=email, role="admin")


def is_admin(email: str) -> bool:
    u = get_user(email)
    return bool(u and u["role"] == "admin" and not u["is_blocked"])


def require_login() -> dict:
    """Block the page until the user is logged in and authorized.

    Returns a dict with email, name, picture, role.
    """
    if not getattr(st.user, "is_logged_in", False):
        st.title("Swift Hub")
        st.write("Please sign in to continue.")
        if st.button("Sign in with Google", type="primary"):
            st.login()
        st.stop()

    email = (getattr(st.user, "email", "") or "").lower()
    name = getattr(st.user, "name", "") or ""

    # Make sure the table exists and has at least one admin.
    try:
        _ensure_bootstrap()
    except Exception as e:
        st.error(f"Database unavailable: {e}")
        if st.button("Sign out"):
            st.logout()
        st.stop()

    domains = _allowed_domains()
    domain_ok = (not domains) or any(email.endswith("@" + d) for d in domains)

    user_row = get_user(email)

    # Auto-provision: if the email matches an allowed domain and isn't in
    # the table yet, add them as a regular user. Admins must promote them
    # later from the Manage Users panel.
    if user_row is None and domain_ok:
        upsert_user(email=email, name=name, role="user")
        user_row = get_user(email)

    if user_row is None or user_row["is_blocked"]:
        reason = (
            f"Access for {email} has been revoked."
            if user_row and user_row["is_blocked"]
            else f"{email} is not authorized to access Swift Hub. Contact an administrator."
        )
        st.error(reason)
        if st.button("Sign out"):
            st.logout()
        st.stop()

    # Keep name fresh if Google has it.
    if name and name != (user_row.get("name") or ""):
        try:
            upsert_user(email=email, name=name, role=user_row["role"], is_blocked=False)
        except Exception:
            pass

    return {
        "email": email,
        "name": name,
        "picture": getattr(st.user, "picture", ""),
        "role": user_row["role"],
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

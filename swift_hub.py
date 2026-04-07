"""Swift Hub — central landing page for all Swift dashboards.

Users sign in once with their Google account, then launch
individual dashboards from tiles below. Admins also get a
"Manage Users" panel.
"""
from __future__ import annotations

import pandas as pd
import streamlit as st

from swift_auth import is_admin, require_login, sidebar_user_box
from swift_db import delete_user, list_users, set_blocked, upsert_user

st.set_page_config(
    page_title="Swift Hub",
    page_icon="🚛",
    layout="wide",
)

user = require_login()
sidebar_user_box()

st.title("🚛 Swift Hub")
st.caption(f"Welcome, {user['name'] or user['email']}  ·  role: {user['role']}")

st.divider()

# ---- Dashboard tiles ---------------------------------------------------------
DASHBOARDS = [
    {
        "title": "Trip Log",
        "icon": "📋",
        "description": "Trip records, status and history.",
        "url": "https://swifttriplog-ehjssp2jl5js85rstgqz47.streamlit.app/",
    },
    {
        "title": "Live Tracking",
        "icon": "📍",
        "description": "Real-time vehicle locations and movement.",
        "url": "https://swiftlivetracking-bbycn4zvrcmtuat2gudgub.streamlit.app/",
    },
    {
        "title": "Billing",
        "icon": "💰",
        "description": "Invoices, payments and billing reports.",
        "url": "https://swiftbilling-iocaaipkggpttjxjo9lgcm.streamlit.app/",
    },
    {
        "title": "Driver Performance",
        "icon": "🏆",
        "description": "Driver KPIs, scores and rankings.",
        "url": "https://swiftdriverperformance-e7uksnstfkdzqdqgeuqmz3.streamlit.app/",
    },
]

cols = st.columns(2)
for i, d in enumerate(DASHBOARDS):
    with cols[i % 2]:
        with st.container(border=True):
            st.subheader(f"{d['icon']} {d['title']}")
            st.write(d["description"])
            st.link_button("Open", d["url"], use_container_width=True)

# ---- Admin: Manage Users -----------------------------------------------------
if is_admin(user["email"]):
    st.divider()
    st.header("👤 Manage Users")
    st.caption("Add, promote, block or remove users. Changes apply on next sign-in / page reload.")

    # Add / update form
    with st.expander("➕ Add or update a user", expanded=False):
        with st.form("add_user_form", clear_on_submit=True):
            c1, c2, c3 = st.columns([3, 2, 2])
            new_email = c1.text_input("Email", placeholder="user@srlpl.in")
            new_name = c2.text_input("Name (optional)")
            new_role = c3.selectbox("Role", ["user", "admin"])
            submitted = st.form_submit_button("Save user", type="primary")
            if submitted:
                if not new_email or "@" not in new_email:
                    st.error("Enter a valid email.")
                else:
                    upsert_user(email=new_email, name=new_name, role=new_role, is_blocked=False)
                    st.success(f"Saved {new_email} as {new_role}.")
                    st.rerun()

    # User list
    users = list_users()
    if not users:
        st.info("No users yet.")
    else:
        df = pd.DataFrame(users)
        df["created_at"] = pd.to_datetime(df["created_at"]).dt.strftime("%Y-%m-%d %H:%M")
        st.dataframe(
            df[["email", "name", "role", "is_blocked", "created_at"]],
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Actions")
        emails = [u["email"] for u in users]
        target = st.selectbox("Select user", emails)
        target_row = next(u for u in users if u["email"] == target)
        is_self = target == user["email"]

        a1, a2, a3, a4 = st.columns(4)
        if a1.button("Promote to admin", disabled=target_row["role"] == "admin"):
            upsert_user(email=target, name=target_row.get("name") or "", role="admin", is_blocked=target_row["is_blocked"])
            st.success(f"{target} is now admin.")
            st.rerun()
        if a2.button("Demote to user", disabled=target_row["role"] != "admin" or is_self):
            upsert_user(email=target, name=target_row.get("name") or "", role="user", is_blocked=target_row["is_blocked"])
            st.success(f"{target} is now user.")
            st.rerun()
        if target_row["is_blocked"]:
            if a3.button("Unblock"):
                set_blocked(target, False)
                st.success(f"Unblocked {target}.")
                st.rerun()
        else:
            if a3.button("Block", disabled=is_self):
                set_blocked(target, True)
                st.success(f"Blocked {target}.")
                st.rerun()
        if a4.button("Delete", type="secondary", disabled=is_self):
            delete_user(target)
            st.success(f"Deleted {target}.")
            st.rerun()

st.divider()
st.caption("© Swift Roadlink Pvt. Ltd.")

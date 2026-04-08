"""Swift Hub — central landing page for all Swift dashboards."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from swift_auth import is_admin, require_login, sidebar_user_box
from swift_db import (
    delete_user,
    get_permitted_dashboards,
    list_permissions,
    list_users,
    log_access,
    recent_logs,
    set_blocked,
    set_role_permissions,
    upsert_user,
)

st.set_page_config(
    page_title="Swift Hub",
    page_icon="🚛",
    layout="wide",
)

# ---- Dashboard catalogue -----------------------------------------------------
DASHBOARDS = [
    {
        "key": "trip_log",
        "title": "Trip Log",
        "icon": "📋",
        "description": "Trip records, status and history.",
        "url": "https://swifttriplog-ehjssp2jl5js85rstgqz47.streamlit.app/",
    },
    {
        "key": "live_tracking",
        "title": "Live Tracking",
        "icon": "📍",
        "description": "Real-time vehicle locations and movement.",
        "url": "https://swiftlivetracking-bbycn4zvrcmtuat2gudgub.streamlit.app/",
    },
    {
        "key": "billing",
        "title": "Billing",
        "icon": "💰",
        "description": "Invoices, payments and billing reports.",
        "url": "https://swiftbilling-iocaaipkggpttjxjo9lgcm.streamlit.app/",
    },
    {
        "key": "driver_performance",
        "title": "Driver Performance",
        "icon": "🏆",
        "description": "Driver KPIs, scores and rankings.",
        "url": "https://swiftdriverperformance-e7uksnstfkdzqdqgeuqmz3.streamlit.app/",
    },
]
DASH_KEYS = [d["key"] for d in DASHBOARDS]
DASH_BY_KEY = {d["key"]: d for d in DASHBOARDS}

user = require_login()
sidebar_user_box()

st.title("🚛 Swift Hub")
st.caption(f"Welcome, {user['name'] or user['email']}  ·  role: {user['role']}")

st.divider()

# ---- Tile rendering (filtered by role) ---------------------------------------
if user["role"] == "admin":
    visible = DASHBOARDS
else:
    permitted = get_permitted_dashboards(user["role"])
    visible = [d for d in DASHBOARDS if d["key"] in permitted]

if not visible:
    st.info("You don't have access to any dashboards yet. Contact an administrator.")
else:
    cols = st.columns(2)
    for i, d in enumerate(visible):
        with cols[i % 2]:
            with st.container(border=True):
                st.subheader(f"{d['icon']} {d['title']}")
                st.write(d["description"])
                # Use a real link_button + log click via query param fallback isn't reliable;
                # log on render of an "Open" button click.
                st.link_button("Open", d["url"], use_container_width=True)

# ---- Admin section -----------------------------------------------------------
if is_admin(user["email"]):
    st.divider()
    tab_users, tab_perms, tab_logs = st.tabs(["👤 Users", "🔐 Permissions", "📜 Access logs"])

    # --- Users tab ------------------------------------------------------------
    with tab_users:
        with st.expander("➕ Add or update a user", expanded=False):
            with st.form("add_user_form", clear_on_submit=True):
                c1, c2, c3 = st.columns([3, 2, 2])
                new_email = c1.text_input("Email", placeholder="user@srlpl.in")
                new_name = c2.text_input("Name (optional)")
                new_role = c3.text_input("Role", value="user", help="e.g. user, admin, ops, finance")
                submitted = st.form_submit_button("Save user", type="primary")
                if submitted:
                    if not new_email or "@" not in new_email:
                        st.error("Enter a valid email.")
                    else:
                        upsert_user(
                            email=new_email,
                            name=new_name,
                            role=new_role.strip().lower() or "user",
                            is_blocked=False,
                        )
                        st.success(f"Saved {new_email} as {new_role}.")
                        st.rerun()

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
            new_target_role = a1.text_input("Set role", value=target_row["role"], key="set_role_input")
            if a1.button("Update role"):
                upsert_user(
                    email=target,
                    name=target_row.get("name") or "",
                    role=new_target_role.strip().lower() or "user",
                    is_blocked=target_row["is_blocked"],
                )
                st.success(f"{target} role -> {new_target_role}")
                st.rerun()
            if target_row["is_blocked"]:
                if a2.button("Unblock"):
                    set_blocked(target, False)
                    st.success(f"Unblocked {target}.")
                    st.rerun()
            else:
                if a2.button("Block", disabled=is_self):
                    set_blocked(target, True)
                    st.success(f"Blocked {target}.")
                    st.rerun()
            if a3.button("Delete", disabled=is_self):
                delete_user(target)
                st.success(f"Deleted {target}.")
                st.rerun()

    # --- Permissions tab ------------------------------------------------------
    with tab_perms:
        st.caption("Map roles to dashboards. Admins always see everything.")
        existing = list_permissions()
        roles_in_use = sorted({u["role"] for u in list_users() if u["role"] != "admin"})
        roles_in_use = roles_in_use or ["user"]

        for role in roles_in_use:
            current = sorted([p["dashboard_key"] for p in existing if p["role"] == role])
            with st.container(border=True):
                st.markdown(f"**Role: `{role}`**")
                selected = st.multiselect(
                    "Allowed dashboards",
                    options=DASH_KEYS,
                    default=current,
                    format_func=lambda k: DASH_BY_KEY[k]["title"],
                    key=f"perms_{role}",
                )
                if st.button("Save", key=f"save_perms_{role}"):
                    set_role_permissions(role, selected)
                    st.success(f"Updated permissions for {role}.")
                    st.rerun()

    # --- Logs tab -------------------------------------------------------------
    with tab_logs:
        logs = recent_logs(limit=300)
        if not logs:
            st.info("No access logs yet.")
        else:
            ldf = pd.DataFrame(logs)
            ldf["ts"] = (
                pd.to_datetime(ldf["ts"], utc=True)
                .dt.tz_convert("Asia/Kolkata")
                .dt.strftime("%Y-%m-%d %H:%M:%S")
            )
            st.dataframe(
                ldf[["ts", "email", "action", "dashboard_key"]],
                use_container_width=True,
                hide_index=True,
            )

st.divider()
st.caption("© Swift Roadlink Pvt. Ltd.")

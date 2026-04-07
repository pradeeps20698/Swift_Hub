"""Swift Hub — central landing page for all Swift dashboards.

Users sign in once with their @srlpl.in Google account, then launch
individual dashboards from tiles below.
"""
from __future__ import annotations

import streamlit as st

from swift_auth import require_login, sidebar_user_box

st.set_page_config(
    page_title="Swift Hub",
    page_icon="🚛",
    layout="wide",
)

user = require_login()
sidebar_user_box()

st.title("🚛 Swift Hub")
st.caption(f"Welcome, {user['name'] or user['email']}")

st.divider()

# ---- Dashboard tiles ---------------------------------------------------------
DASHBOARDS = [
    {
        "title": "Operations",
        "icon": "📊",
        "description": "Live trip, vehicle and driver operations.",
        "url": "https://example.streamlit.app/operations",
    },
    {
        "title": "Finance",
        "icon": "💰",
        "description": "Revenue, expenses and P&L reporting.",
        "url": "https://example.streamlit.app/finance",
    },
    {
        "title": "Fleet",
        "icon": "🛻",
        "description": "Vehicle health, fuel and maintenance.",
        "url": "https://example.streamlit.app/fleet",
    },
    {
        "title": "HR",
        "icon": "👥",
        "description": "Driver and staff management.",
        "url": "https://example.streamlit.app/hr",
    },
]

cols = st.columns(2)
for i, d in enumerate(DASHBOARDS):
    with cols[i % 2]:
        with st.container(border=True):
            st.subheader(f"{d['icon']} {d['title']}")
            st.write(d["description"])
            st.link_button("Open", d["url"], use_container_width=True)

st.divider()
st.caption("© Swift Roadlink Pvt. Ltd.")

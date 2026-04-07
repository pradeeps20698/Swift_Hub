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

st.divider()
st.caption("© Swift Roadlink Pvt. Ltd.")

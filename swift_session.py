"""Signed session cookie helpers for Swift Hub.

Issues a stateless HMAC-signed token containing the user's email and an
expiry timestamp. Verified on each page load to restore the session after
a tab refresh, without storing anything server-side.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import streamlit as st

COOKIE_NAME = "sh_session"
DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days


def _secret() -> bytes:
    try:
        s = st.secrets["app"]["cookie_secret"]
    except Exception:
        try:
            s = st.secrets["auth"]["cookie_secret"]
        except Exception:
            s = "swift-hub-dev-secret-change-me"
    return s.encode("utf-8")


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def make_token(email: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    payload = {"email": email, "exp": int(time.time()) + ttl_seconds}
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(_secret(), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64e(sig)}"


def verify_token(token: str) -> str | None:
    """Return email if token is valid and not expired, else None."""
    if not token or "." not in token:
        return None
    try:
        body, sig_b64 = token.split(".", 1)
        expected = hmac.new(_secret(), body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64d(sig_b64)):
            return None
        payload = json.loads(_b64d(body).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        email = payload.get("email")
        return email if isinstance(email, str) and email else None
    except Exception:
        return None

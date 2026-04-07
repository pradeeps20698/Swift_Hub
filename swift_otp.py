"""Email OTP sender. Uses SMTP creds from st.secrets["smtp"], or falls
back to a dev mode that returns the code to the caller for on-screen display.
"""
from __future__ import annotations

import hashlib
import secrets as pysecrets
import smtplib
import ssl
from email.message import EmailMessage

import streamlit as st


def _smtp_cfg() -> dict | None:
    try:
        return dict(st.secrets["smtp"])
    except Exception:
        return None


def smtp_configured() -> bool:
    cfg = _smtp_cfg()
    return bool(cfg and cfg.get("host") and cfg.get("username") and cfg.get("password"))


def generate_code() -> str:
    return f"{pysecrets.randbelow(1_000_000):06d}"


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def send_code(email: str, code: str) -> tuple[bool, str]:
    """Send the code via SMTP. Returns (sent, message_or_error).

    If SMTP isn't configured, returns (False, "<reason>") so the caller can
    fall back to dev mode (showing the code on-screen for testing).
    """
    cfg = _smtp_cfg()
    if not smtp_configured():
        return False, "SMTP not configured"

    sender = cfg.get("sender") or cfg["username"]
    sender_name = cfg.get("sender_name", "Swift Hub")

    msg = EmailMessage()
    msg["Subject"] = f"Your Swift Hub login code: {code}"
    msg["From"] = f"{sender_name} <{sender}>"
    msg["To"] = email
    msg.set_content(
        f"Hi,\n\nYour Swift Hub one-time login code is:\n\n    {code}\n\n"
        "It expires in 10 minutes. If you didn't request this, you can ignore this email.\n\n"
        "— Swift Hub"
    )
    msg.add_alternative(
        f"""<html><body style="font-family:Arial,sans-serif">
        <p>Hi,</p>
        <p>Your Swift Hub one-time login code is:</p>
        <p style="font-size:28px;font-weight:bold;letter-spacing:4px">{code}</p>
        <p>It expires in 10 minutes.</p>
        <p style="color:#888">If you didn't request this, you can ignore this email.</p>
        <p>— Swift Hub</p>
        </body></html>""",
        subtype="html",
    )

    host = cfg["host"]
    port = int(cfg.get("port", 587))
    use_tls = bool(cfg.get("use_tls", True))

    try:
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.ehlo()
            if use_tls:
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
            s.login(cfg["username"], cfg["password"])
            s.send_message(msg)
        return True, "sent"
    except Exception as e:
        return False, f"SMTP error: {e}"

"""Email-OTP auth gate for Swift Hub.

Login persistence:
  - On successful OTP verify, we create a DB-backed session
    (`swift_hub_sessions`). Only the SHA-256 hash of the random token
    is stored server-side; the raw token lives only in the user's browser.
  - The raw token is persisted in browser localStorage via
    `streamlit-local-storage`. As a fallback (e.g. iframe sandbox blocks
    localStorage) it is also written to a `?s=` query param so refresh
    still works without exposing user identity in the URL.
  - Sessions are revocable: Sign Out marks the row revoked; admins can
    revoke any active session from the DB.
"""
from __future__ import annotations

import base64
import re
from pathlib import Path

import streamlit as st
from streamlit_local_storage import LocalStorage

from swift_db import (
    consume_login_code,
    count_users,
    create_session,
    get_user,
    init_schema,
    log_access,
    lookup_session,
    revoke_all_sessions_for,
    revoke_session,
    store_login_code,
    upsert_user,
)
from swift_otp import generate_code, hash_code, send_code, smtp_configured

LS_KEY = "sh_sid"
QP_KEY = "s"
SESSION_KEY = "sh_user_email"
RAW_TOKEN_KEY = "sh_raw_token"

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

# Hard allow-list: only these company domains may sign in. This is enforced
# in addition to any `allowed_email_domains` set in Streamlit secrets so
# misconfigured secrets can never accidentally open the dashboard to the
# public internet.
ALLOWED_DOMAINS_HARDCODED = ("srlpl.in", "swiftroadlink.com")


# ---------------------------------------------------------------------------
# Session-token storage (browser side)
# ---------------------------------------------------------------------------
def _local_storage() -> LocalStorage:
    if "sh_local_storage" not in st.session_state:
        st.session_state["sh_local_storage"] = LocalStorage()
    return st.session_state["sh_local_storage"]


def _is_child_mode() -> bool:
    return bool(st.session_state.get("sh_child_mode"))


def _read_token_from_browser() -> str | None:
    """Read the session token. In child-app mode we ONLY accept the URL
    query param (passed from Swift Hub on Open), never localStorage,
    so closing the tab loses the login and the user must re-open from
    Swift Hub. In Swift Hub itself we also read localStorage."""
    if not _is_child_mode():
        try:
            token = _local_storage().getItem(LS_KEY)
            if token:
                return token
        except Exception:
            pass
    try:
        qp = st.query_params.get(QP_KEY)
        if qp:
            return qp
    except Exception:
        pass
    return None


def _write_token_to_browser(raw_token: str) -> None:
    if _is_child_mode():
        # Child apps must NOT persist the token anywhere — login dies
        # with the tab.
        try:
            if QP_KEY in st.query_params:
                del st.query_params[QP_KEY]
        except Exception:
            pass
        return
    try:
        _local_storage().setItem(LS_KEY, raw_token, key="sh_ls_set")
    except Exception:
        pass
    try:
        st.query_params[QP_KEY] = raw_token
    except Exception:
        pass


def _clear_token_from_browser() -> None:
    if not _is_child_mode():
        try:
            _local_storage().deleteItem(LS_KEY, key="sh_ls_del")
        except Exception:
            pass
    try:
        if QP_KEY in st.query_params:
            del st.query_params[QP_KEY]
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------
def _app_cfg():
    try:
        return st.secrets["app"]
    except Exception:
        return {}


def _allowed_domains() -> list[str]:
    cfg = _app_cfg()
    domains = cfg.get("allowed_email_domains")
    if domains:
        configured = [d.lower() for d in domains]
    else:
        single = cfg.get("allowed_email_domain")
        configured = [single.lower()] if single else []
    # Always intersect with the hard allow-list. If secrets list extra
    # domains they are ignored; if secrets are empty we fall back to the
    # hard-coded company domains.
    if not configured:
        return list(ALLOWED_DOMAINS_HARDCODED)
    return [d for d in configured if d in ALLOWED_DOMAINS_HARDCODED] or list(
        ALLOWED_DOMAINS_HARDCODED
    )


def _bootstrap_admins() -> list[str]:
    return [e.lower() for e in (_app_cfg().get("bootstrap_admins") or [])]


@st.cache_resource(show_spinner=False)
def _ensure_bootstrap_once() -> bool:
    """Run schema bootstrap exactly once per worker process."""
    init_schema()
    if count_users() == 0:
        for email in _bootstrap_admins():
            upsert_user(email=email, role="admin")
    return True


def _ensure_bootstrap() -> None:
    _ensure_bootstrap_once()


@st.cache_data(ttl=30, show_spinner=False)
def _cached_get_user(email: str) -> dict | None:
    return get_user(email)


def is_admin(email: str) -> bool:
    u = _cached_get_user(email)
    return bool(u and u["role"] == "admin" and not u["is_blocked"])


# ---------------------------------------------------------------------------
# Login UI — branding & theme
# ---------------------------------------------------------------------------
_ASSETS = Path(__file__).parent / "assets"

# The car-carrier hero image is served as a static file (see
# .streamlit/config.toml -> enableStaticServing). This keeps it high-res and
# browser-cached instead of a heavy base64 data-URI re-sent on every rerun.
# The file lives at ./static/login_bg.jpg and is reachable at this URL.
_LOGIN_BG_URL = "app/static/login_bg.jpg"


def _login_bg_uri() -> str:
    """URL for the car-carrier hero image behind the login/hub content."""
    return _LOGIN_BG_URL


@st.cache_data(show_spinner=False)
def _logo_data_uri() -> str:
    """Return a data-URI for the Swift logo.

    Prefers a real raster logo dropped at ``assets/swift_logo.png``; falls
    back to the bundled SVG recreation so the page always shows a mark.
    """
    for name, mime in (
        ("swift_logo.png", None),
        ("swift_logo.jpg", "image/jpeg"),
        ("swift_logo.jpeg", "image/jpeg"),
        ("swift_logo.svg", "image/svg+xml"),
    ):
        path = _ASSETS / name
        if not path.exists():
            continue
        raw = path.read_bytes()
        if mime is None:
            # A ".png" may actually hold JPEG bytes — sniff the magic number
            # so the browser gets the right MIME and renders it.
            mime = "image/jpeg" if raw[:3] == b"\xff\xd8\xff" else "image/png"
        b64 = base64.b64encode(raw).decode()
        return f"data:{mime};base64,{b64}"
    return ""


def _inject_login_css() -> None:
    # Streamlit rebuilds the DOM on every rerun, so the <style> block must be
    # re-emitted each run (including the OTP-verify step) — do NOT guard this
    # behind session_state or later pages render unstyled.
    bg = _login_bg_uri()
    st.markdown(
        f"""
        <style>
        /* Login background: the Swift carrier photo fills the whole browser
           window (::before, cover) with a soft gold wash on the left. */
        [data-testid="stApp"] {{ background: #0b0f17; }}
        [data-testid="stAppViewContainer"] {{
            background: transparent;
            position: relative;
            z-index: 0;
        }}
        /* Full-bleed carrier photo filling the entire browser window. */
        [data-testid="stAppViewContainer"]::before {{
            content: ""; position: fixed; inset: 0; z-index: -1;
            background:
                /* soft, light gold/orange (logo colour) wash on the LEFT that
                   blends smoothly into the carrier photo — no hard divider. */
                linear-gradient(to right,
                    rgba(238,212,158,.82) 0%,
                    rgba(238,212,158,.60) 22%,
                    rgba(238,212,158,.36) 40%,
                    rgba(238,212,158,.16) 58%,
                    rgba(238,212,158,.04) 74%,
                    rgba(238,212,158,0) 88%),
                url("{bg}") center center / cover no-repeat;
        }}
        [data-testid="stHeader"] {{ background: transparent; }}
        /* Constrain the whole login column to a neat centred card so the
           form never spans full width and slices the background. */
        /* Vertically centre the login column within the viewport. */
        [data-testid="stMain"] {{
            display: flex !important;
            flex-direction: column !important;
            justify-content: center !important;
        }}
        /* Centre the login column within the left gold panel horizontally
           (around ~21% of the width). */
        [data-testid="stMainBlockContainer"],
        [data-testid="stAppViewContainer"] .block-container {{
            max-width: 600px !important;
            margin-left: max(calc(22vw - 300px), 24px) !important;
            margin-right: auto !important;
            padding-top: 3vh !important;
            padding-bottom: 3vh !important;
        }}

        /* Brand header */
        .swift-brand {{ text-align: center; margin-bottom: 16px; }}
        .swift-brand img {{
            width: 188px; height: 188px; object-fit: cover;
            border-radius: 30px;
            box-shadow: 0 14px 40px rgba(0,0,0,.55);
        }}
        .swift-title {{
            text-align: center;
            font-size: 3.1rem; font-weight: 800; letter-spacing: .5px;
            color: #1e1708; margin: 12px 0 6px;
            text-shadow: 0 1px 0 rgba(255,255,255,.25);
        }}
        .swift-title span {{ color: #7a4f0f; }}
        .swift-sub {{
            text-align: center; color: #4a3c1c;
            font-size: 1.22rem; margin: 0 0 30px; font-weight: 600;
        }}

        /* Glass login card wrapping the Streamlit form */
        [data-testid="stForm"] {{
            background: rgba(16,20,30,.88);
            border: 1px solid rgba(224,184,75,.32);
            border-radius: 22px;
            padding: 42px 40px 34px;
            backdrop-filter: blur(16px);
            box-shadow: 0 24px 70px rgba(0,0,0,.65);
        }}
        [data-testid="stForm"] label {{
            color: #D7DEE8 !important; font-weight: 600;
            font-size: 1.12rem !important;
        }}
        [data-testid="stForm"] input {{
            background: rgba(12,16,24,.85) !important;
            border: 1px solid rgba(255,255,255,.12) !important;
            border-radius: 12px !important;
            color: #F5F7FA !important;
            height: auto !important; line-height: 1.4 !important;
            padding: 19px 18px !important; font-size: 1.15rem !important;
        }}
        /* keep BaseWeb input wrappers transparent so our styled input shows */
        [data-testid="stForm"] [data-baseweb="input"],
        [data-testid="stForm"] [data-baseweb="base-input"] {{
            background: transparent !important;
        }}
        [data-testid="stForm"] input:focus {{
            border-color: #E0B84B !important;
            box-shadow: 0 0 0 2px rgba(224,184,75,.25) !important;
        }}
        /* Primary button -> gold gradient */
        [data-testid="stForm"] button[kind="primaryFormSubmit"] {{
            background: linear-gradient(90deg,#E0B84B 0%,#C79A2F 100%) !important;
            color: #1a1204 !important;
            border: none !important; border-radius: 12px !important;
            font-weight: 700 !important; height: 62px; font-size: 1.2rem !important;
            box-shadow: 0 8px 20px rgba(224,184,75,.28);
        }}
        [data-testid="stForm"] button[kind="primaryFormSubmit"]:hover {{
            filter: brightness(1.06);
        }}
        [data-testid="stForm"] button[kind="secondaryFormSubmit"] {{
            border-radius: 10px !important; height: 46px;
        }}
        .swift-foot {{
            text-align: center; color: #5a4a25;
            font-size: .8rem; margin-top: 20px; font-weight: 600;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def _login_header(subtitle: str) -> None:
    _inject_login_css()
    logo = _logo_data_uri()
    logo_html = f'<div class="swift-brand"><img src="{logo}" alt="Swift"/></div>' if logo else ""
    st.markdown(
        f"""
        {logo_html}
        <div class="swift-title">Swift <span>Hub</span></div>
        <div class="swift-sub">{subtitle}</div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Shared branding for the signed-in app pages (hub / dashboards)
# ---------------------------------------------------------------------------
def render_app_background(dark: float = 0.72) -> None:
    """Inject the Swift carrier photo as a full-page background. `dark` is the
    overlay opacity (higher = darker). Bordered containers get a semi-opaque
    panel so content stays readable while the photo shows through."""
    bg = _login_bg_uri()
    if not bg:
        return
    d2 = min(dark + 0.08, 0.98)
    st.markdown(
        f"""
        <style>
        [data-testid="stApp"] {{ background: #0b0f17; }}
        [data-testid="stAppViewContainer"] {{
            background: transparent; position: relative; z-index: 0;
        }}
        [data-testid="stAppViewContainer"]::before {{
            content: ""; position: fixed; inset: 0; z-index: -1;
            background:
                linear-gradient(180deg, rgba(9,12,20,{dark}) 0%, rgba(9,12,20,{d2}) 100%),
                url("{bg}") center center / cover no-repeat fixed;
        }}
        [data-testid="stHeader"] {{ background: transparent; }}
        /* Give bordered cards a readable, highlighted panel over the photo */
        [data-testid="stAppViewContainer"] div[data-testid="stVerticalBlockBorderWrapper"] {{
            background: rgba(18,22,32,.88) !important;
            border-radius: 16px !important;
            border: 2px solid rgba(224,184,75,.85) !important;
            box-shadow: 0 12px 34px rgba(0,0,0,.5) !important;
            backdrop-filter: blur(4px);
        }}
        /* Make divider / horizontal lines clearly visible (gold tint) */
        [data-testid="stAppViewContainer"] hr,
        [data-testid="stAppViewContainer"] [data-testid="stDivider"] hr {{
            border-color: rgba(224,184,75,.55) !important;
            background: rgba(224,184,75,.55) !important;
            opacity: 1 !important;
        }}
        /* Swift-gold primary buttons and dashboard "Open" link buttons */
        [data-testid="stAppViewContainer"] .stLinkButton a,
        [data-testid="stAppViewContainer"] button[kind="primary"],
        [data-testid="stAppViewContainer"] button[kind="primaryFormSubmit"] {{
            background: linear-gradient(90deg,#E0B84B 0%,#C79A2F 100%) !important;
            color: #1a1204 !important;
            border: none !important;
            font-weight: 700 !important;
            box-shadow: 0 6px 16px rgba(224,184,75,.28) !important;
        }}
        [data-testid="stAppViewContainer"] .stLinkButton a:hover,
        [data-testid="stAppViewContainer"] button[kind="primary"]:hover,
        [data-testid="stAppViewContainer"] button[kind="primaryFormSubmit"]:hover {{
            filter: brightness(1.06);
            color: #1a1204 !important;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def logo_img_html(size: int = 60, radius: int = 14) -> str:
    """Return an <img> tag for the Swift logo as a data-URI, or '' if none."""
    uri = _logo_data_uri()
    if not uri:
        return ""
    return (
        f'<img src="{uri}" alt="Swift" style="width:{size}px;height:{size}px;'
        f"object-fit:cover;border-radius:{radius}px;vertical-align:middle;"
        f'box-shadow:0 4px 14px rgba(0,0,0,.5)"/>'
    )


# ---------------------------------------------------------------------------
# Login UI
# ---------------------------------------------------------------------------
def _domain_ok(email: str) -> bool:
    domains = _allowed_domains() or list(ALLOWED_DOMAINS_HARDCODED)
    return any(email.endswith("@" + d) for d in domains)


def _request_code_ui() -> None:
    _login_header("Swift Roadlink Pvt. Ltd. · Car Carrier Logistics")

    with st.form("request_code_form"):
        email = st.text_input("Company email", placeholder="you@srlpl.in")
        submit = st.form_submit_button("Send login code", type="primary", use_container_width=True)

    st.markdown(
        "<div class='swift-foot'>Secure sign-in · a one-time code will be emailed to you</div>",
        unsafe_allow_html=True,
    )

    if not submit:
        return

    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        st.error("Enter a valid email address.")
        return
    if not _domain_ok(email):
        allowed = ", ".join("@" + d for d in _allowed_domains())
        st.error(f"Only {allowed} accounts are allowed.")
        return

    _issue_login_code(email)
    st.session_state["sh_pending_email"] = email
    st.rerun()


def _issue_login_code(email: str) -> None:
    """Generate, store and email a fresh login code, surfacing status to the UI."""
    with st.spinner("Sending login code…"):
        code = generate_code()
        try:
            store_login_code(email, hash_code(code), ttl_seconds=600)
        except Exception as e:
            st.error(f"Could not store login code: {e}")
            return

        sent, info = send_code(email, code)
    if sent:
        st.success(f"A 6-digit login code has been sent to {email}. It expires in 10 minutes.")
    else:
        if not smtp_configured():
            st.warning(
                "SMTP not configured yet — showing code on screen for testing. "
                "Configure `[smtp]` in Streamlit Cloud Secrets to email codes."
            )
            st.code(code, language="text")
        else:
            st.error(f"Could not send email: {info}")


def _verify_code_ui() -> None:
    email = st.session_state.get("sh_pending_email", "")
    _login_header(f"Enter the 6-digit code sent to <b>{email}</b>")

    with st.form("verify_code_form"):
        code = st.text_input("Login code", max_chars=6, placeholder="123456")
        c1, c2 = st.columns(2)
        verify = c1.form_submit_button("Verify", type="primary", use_container_width=True)
        resend = c2.form_submit_button("Resend code", use_container_width=True)
        change = st.form_submit_button("Use a different email", use_container_width=True)

    if change:
        st.session_state.pop("sh_pending_email", None)
        st.rerun()
        return

    if resend:
        _issue_login_code(email)
        st.rerun()
        return

    if not verify:
        return

    code = (code or "").strip()
    if not code.isdigit() or len(code) != 6:
        st.error("Enter the 6-digit code.")
        return

    try:
        ok = consume_login_code(email, hash_code(code))
    except Exception as e:
        st.error(f"Database error: {e}")
        return

    if not ok:
        st.error("Invalid or expired code. Request a new one.")
        return

    row = get_user(email)
    if row is None:
        upsert_user(email=email, name="", role="user")
        row = get_user(email)

    if row["is_blocked"]:
        st.error(f"Access for {email} has been revoked.")
        return

    # Create a server-side session and hand the raw token to the browser
    raw_token = create_session(email)
    st.session_state[SESSION_KEY] = email
    st.session_state[RAW_TOKEN_KEY] = raw_token
    st.session_state.pop("sh_pending_email", None)
    _write_token_to_browser(raw_token)
    log_access(email, action="login")
    st.rerun()


def require_login() -> dict:
    """Block the page until the user has verified an OTP. Returns user dict."""
    try:
        _ensure_bootstrap()
    except Exception as e:
        st.error(f"Database unavailable: {e}")
        st.stop()

    email = st.session_state.get(SESSION_KEY)

    # While the user is mid-OTP (a code has been requested) there's no point
    # touching browser localStorage — skipping it avoids an extra component
    # roundtrip/rerun and keeps the verify step snappy.
    if not email and not st.session_state.get("sh_pending_email"):
        # Try to restore from a previously-issued session token in the browser
        raw_token = _read_token_from_browser()
        if raw_token:
            session_email = lookup_session(raw_token)
            if session_email:
                row = _cached_get_user(session_email)
                if row and not row["is_blocked"]:
                    st.session_state[SESSION_KEY] = session_email
                    st.session_state[RAW_TOKEN_KEY] = raw_token
                    email = session_email
                    # Migrate URL fallback into localStorage and clean URL
                    _write_token_to_browser(raw_token)
                else:
                    revoke_session(raw_token)
                    _clear_token_from_browser()
            else:
                _clear_token_from_browser()
        elif not st.session_state.get("sh_ls_checked"):
            # First load: localStorage component returns None on initial
            # render; rerun once so the JS roundtrip can complete.
            st.session_state["sh_ls_checked"] = True
            st.rerun()

    if not email:
        if st.session_state.get("sh_pending_email"):
            _verify_code_ui()
        else:
            _request_code_ui()
        st.stop()

    row = _cached_get_user(email)
    if row is None or row["is_blocked"]:
        raw = st.session_state.pop(RAW_TOKEN_KEY, None)
        if raw:
            revoke_session(raw)
        st.session_state.pop(SESSION_KEY, None)
        _clear_token_from_browser()
        st.error("Your access has been revoked. Please sign in again.")
        st.stop()

    return {
        "email": email,
        "name": row.get("name") or "",
        "role": row["role"],
    }


def sidebar_user_box() -> None:
    email = st.session_state.get(SESSION_KEY)
    if not email:
        return
    row = _cached_get_user(email) or {}
    with st.sidebar:
        st.markdown(f"**{row.get('name') or email}**")
        st.caption(email)
        st.caption(f"Role: `{row.get('role', 'user')}`")
        if st.button("Sign out", use_container_width=True):
            # Revoke ALL active sessions for this user so every open
            # dashboard tab gets kicked out on its next interaction.
            try:
                revoke_all_sessions_for(email)
            except Exception:
                pass
            st.session_state.pop(RAW_TOKEN_KEY, None)
            st.session_state.pop(SESSION_KEY, None)
            _clear_token_from_browser()
            st.rerun()

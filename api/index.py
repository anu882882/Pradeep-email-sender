
import os
import time
import re
import requests

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)
from functools import wraps

app = Flask(__name__)

app.secret_key = os.environ.get("SESSION_SECRET", "local-development-only-change-me")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,
)

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "")
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_RECIPIENTS = 25
MIN_VERIFY_INTERVAL = 600
verification_times = {}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def valid_email(value):
    return bool(EMAIL_PATTERN.fullmatch(value or ""))


def verify_turnstile(token, remote_ip=None):
    # If Turnstile is configured, require a valid token.
    if not TURNSTILE_SECRET_KEY:
        return True

    if not token:
        return False

    data = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }
    if remote_ip:
        data["remoteip"] = remote_ip

    try:
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=data,
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()
        return result.get("success") is True
    except (requests.RequestException, ValueError):
        app.logger.exception("Turnstile verification failed")
        return False


def send_with_resend(recipient, subject, body, sender_name, html_mode=False):
    if not RESEND_API_KEY or not RESEND_FROM_EMAIL:
        return False, "Email service is not configured."

    payload = {
        "from": f"{sender_name.strip() or 'Mail Console'} <{RESEND_FROM_EMAIL}>",
        "to": [recipient],
        "subject": subject.strip(),
    }

    if html_mode:
        payload["html"] = body
    else:
        payload["text"] = body

    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=20,
        )

        if response.status_code in (200, 201):
            result = response.json()
            return True, result.get("id", "accepted")

        app.logger.error(
            "Resend API error: status=%s response=%s",
            response.status_code,
            response.text[:1000],
        )
        return False, f"Email provider returned HTTP {response.status_code}."

    except requests.RequestException:
        app.logger.exception("Resend request failed")
        return False, "Could not connect to the email provider."


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("index"))

    error = None

    if request.method == "POST":
        expected = os.environ.get("LOGIN_PASSWORD", "")
        password = request.form.get("password", "")

        if expected and password and password == expected:
            session.clear()
            session.permanent = True
            session["logged_in"] = True
            return redirect(url_for("index"))

        error = "Incorrect password or login is not configured."

    return render_template("login.html", error=error)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@login_required
def index():
    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
        turnstile_enabled=bool(TURNSTILE_SECRET_KEY and TURNSTILE_SITE_KEY),
    )


@app.post("/verify-turnstile")
@login_required
def verify():
    if not TURNSTILE_SECRET_KEY:
        session["verified_at"] = int(time.time())
        return jsonify({"ok": True, "message": "Verification not configured."})

    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if not ip:
        ip = request.remote_addr

    if not verify_turnstile(token, ip):
        return jsonify({"ok": False, "error": "Verification failed. Please try again."}), 400

    session["verified_at"] = int(time.time())
    return jsonify({"ok": True})


@app.post("/send-one")
@login_required
def send_one():
    now = int(time.time())
    verified_at = int(session.get("verified_at", 0))

    if TURNSTILE_SECRET_KEY and now - verified_at > MIN_VERIFY_INTERVAL:
        return jsonify({
            "ok": False,
            "error": "Verification expired. Please verify again."
        }), 403

    data = request.get_json(silent=True) or {}

    recipient = (data.get("recipient") or "").strip().lower()
    subject = (data.get("subject") or "").strip()
    body = data.get("body") or ""
    sender_name = (data.get("senderName") or "").strip()
    html_mode = bool(data.get("htmlMode", False))

    if not valid_email(recipient):
        return jsonify({"ok": False, "error": "Invalid recipient address."}), 400

    if not subject or not body.strip():
        return jsonify({"ok": False, "error": "Subject and message are required."}), 400

    if len(subject) > 200 or len(body) > 50000:
        return jsonify({"ok": False, "error": "Subject or message is too long."}), 400

    # Do not let the browser turn this endpoint into an unrestricted sender.
    # Require an explicit recipient-consent confirmation in the UI.
    if data.get("consentConfirmed") is not True:
        return jsonify({
            "ok": False,
            "error": "Confirm that these recipients agreed to receive your message."
        }), 400

    success, result = send_with_resend(
        recipient, subject, body, sender_name, html_mode
    )

    if success:
        return jsonify({
            "ok": True,
            "emailId": result,
            "message": "Accepted by email provider."
        })

    return jsonify({"ok": False, "error": result}), 502

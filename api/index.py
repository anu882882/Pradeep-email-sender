
import os
import re
import ssl
import time
import smtplib
import urllib.parse
import urllib.request
import json
from functools import wraps
from email.message import EmailMessage

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
    static_url_path="/static",
)

app.secret_key = os.environ.get("SESSION_SECRET", "")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
VERIFICATION_TTL = 600


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith(("/send-", "/verify-")):
                return jsonify({"success": False, "error": "Please sign in again."}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def verify_turnstile_token(token, remote_ip=None):
    secret = os.environ.get("TURNSTILE_SECRET_KEY", "")
    if not secret or not token:
        return False, "Spam Protection is not configured."

    fields = {"secret": secret, "response": token}
    if remote_ip:
        fields["remoteip"] = remote_ip

    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        TURNSTILE_VERIFY_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            result = json.loads(response.read().decode("utf-8"))

        if result.get("success") is True:
            expected_hostname = os.environ.get("TURNSTILE_HOSTNAME", "").strip().lower()
            actual_hostname = str(result.get("hostname", "")).lower()

            if expected_hostname and actual_hostname != expected_hostname:
                return False, "Verification hostname did not match."

            return True, ""

        return False, "Verification failed. Please try again."
    except Exception:
        app.logger.exception("Cloudflare Turnstile verification failed")
        return False, "Could not verify. Please retry."


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        expected = os.environ.get("LOGIN_PASSWORD", "")
        supplied = request.form.get("password", "")

        if expected and supplied and supplied == expected:
            session.clear()
            session["authenticated"] = True
            return redirect(url_for("index"))

        return render_template("login.html", error="Incorrect password. Please try again.")

    if session.get("authenticated"):
        return redirect(url_for("index"))

    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get("TURNSTILE_SITE_KEY", ""),
    )


@app.route("/verify-turnstile", methods=["POST"])
@login_required
def verify_turnstile():
    data = request.get_json(silent=True) or {}
    token = str(data.get("token", "")).strip()

    if not token:
        session.pop("turnstile_verified_at", None)
        return jsonify({"success": False, "error": "Complete the verification first."}), 400

    success, error = verify_turnstile_token(token, request.remote_addr)
    if not success:
        session.pop("turnstile_verified_at", None)
        return jsonify({"success": False, "error": error}), 400

    session["turnstile_verified_at"] = int(time.time())
    return jsonify({"success": True})


@app.route("/send-one", methods=["POST"])
@login_required
def send_one():
    verified_at = session.get("turnstile_verified_at", 0)
    if not isinstance(verified_at, (int, float)) or time.time() - verified_at > VERIFICATION_TTL:
        session.pop("turnstile_verified_at", None)
        return jsonify({
            "success": False,
            "error": "Spam Protection verification expired. Please verify again."
        }), 401

    data = request.get_json(silent=True) or {}
    sender_name = str(data.get("senderName", "")).strip()[:150]
    gmail = str(data.get("gmail", "")).strip()
    app_password = str(data.get("appPassword", "")).replace(" ", "")
    subject = str(data.get("subject", "")).strip()[:300]
    body = str(data.get("body", ""))
    recipient = str(data.get("recipient", "")).strip().lower()
    html_mode = data.get("htmlMode") is True

    if not all([sender_name, gmail, app_password, subject, body, recipient]):
        return jsonify({"success": False, "error": "Complete all required fields."}), 400

    if not EMAIL_PATTERN.fullmatch(gmail) or not EMAIL_PATTERN.fullmatch(recipient):
        return jsonify({"success": False, "error": "Invalid email address."}), 400

    if len(body) > 100000:
        return jsonify({"success": False, "error": "Message body is too long."}), 400

    message = EmailMessage()
    message["From"] = f"{sender_name} <{gmail}>"
    message["To"] = recipient
    message["Subject"] = subject

    if html_mode:
        message.set_content("This email contains HTML content. Please view it in an HTML-compatible email client.")
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=25) as server:
            server.login(gmail, app_password)
            server.send_message(message)

        return jsonify({"success": True, "recipient": recipient})

    except smtplib.SMTPAuthenticationError:
        return jsonify({
            "success": False,
            "error": "Gmail authentication failed. Check your Gmail and App Password."
        }), 400
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        app.logger.warning("Email send failed: %s", str(exc)[:250])
        return jsonify({"success": False, "error": "Mail server rejected or could not send the message."}), 502
    except Exception:
        app.logger.exception("Unexpected email sending error")
        return jsonify({"success": False, "error": "Unexpected server error."}), 500

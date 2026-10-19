
import os
import time
import requests

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
)

# Project root: parent directory of api/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR,
)

# Configure these in Vercel Environment Variables
app.secret_key = os.environ.get("SESSION_SECRET", "")

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")

# The Resend API code requires these two additional variables.
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "")

MAIL_GAP_SECONDS = max(
    0.0,
    float(os.environ.get("MAIL_GAP_SECONDS", "2"))
)


def is_logged_in():
    return session.get("logged_in") is True


def render_login(error=None):
    return render_template(
        "login.html",
        error=error,
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "templates_found": os.path.isdir(TEMPLATE_DIR),
        "login_template_found": os.path.isfile(
            os.path.join(TEMPLATE_DIR, "login.html")
        ),
        "index_template_found": os.path.isfile(
            os.path.join(TEMPLATE_DIR, "index.html")
        ),
    })


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if is_logged_in():
            return redirect(url_for("home"))
        return render_login()

    submitted_password = request.form.get("password", "")

    if not LOGIN_PASSWORD:
        app.logger.error("LOGIN_PASSWORD is not configured.")
        return render_login(
            "Login is not configured. Please contact the administrator."
        ), 500

    if submitted_password and submitted_password == LOGIN_PASSWORD:
        session.clear()
        session["logged_in"] = True
        return redirect(url_for("home"))

    return render_login("Incorrect password."), 401


@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
def home():
    if not is_logged_in():
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


@app.route("/verify-turnstile", methods=["POST"])
def verify_turnstile():
    if not is_logged_in():
        return jsonify({
            "ok": False,
            "error": "Please log in again.",
        }), 401

    if not TURNSTILE_SECRET_KEY:
        app.logger.error("TURNSTILE_SECRET_KEY is not configured.")
        return jsonify({
            "ok": False,
            "error": "Bot verification is not configured.",
        }), 500

    data = request.get_json(silent=True) or {}
    token = data.get("token", "")

    if not token:
        return jsonify({
            "ok": False,
            "error": "Complete the verification first.",
        }), 400

    try:
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": TURNSTILE_SECRET_KEY,
                "response": token,
                "remoteip": request.headers.get("CF-Connecting-IP", ""),
            },
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()

    except requests.RequestException:
        app.logger.exception("Turnstile verification request failed.")
        return jsonify({
            "ok": False,
            "error": "Verification service is temporarily unavailable.",
        }), 502

    if not result.get("success"):
        return jsonify({
            "ok": False,
            "error": "Verification failed. Please try again.",
        }), 400

    session["turnstile_verified_at"] = time.time()

    return jsonify({"ok": True})


def send_with_resend(recipient, subject, body, sender_name, html_mode):
    if not RESEND_API_KEY or not RESEND_FROM_EMAIL:
        return False, (
            "Email provider is not configured. "
            "Set RESEND_API_KEY and RESEND_FROM_EMAIL in Vercel."
        ), None

    if html_mode:
        content = {"html": body}
    else:
        content = {"text": body}

    payload = {
        "from": f"{sender_name} <{RESEND_FROM_EMAIL}>"
        if sender_name
        else RESEND_FROM_EMAIL,
        "to": [recipient],
        "subject": subject,
        **content,
    }

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

        if response.status_code not in (200, 201):
            app.logger.error(
                "Resend API error %s: %s",
                response.status_code,
                response.text[:1000],
            )
            return False, (
                f"Email provider rejected the request "
                f"(HTTP {response.status_code})."
            ), None

        result = response.json()
        email_id = result.get("id")

        if not email_id:
            return False, "Email provider returned no email ID.", None

        return True, "Accepted by email provider.", email_id

    except requests.Timeout:
        app.logger.exception("Resend API request timed out.")
        return False, "Email provider timed out. Please try again.", None

    except requests.RequestException:
        app.logger.exception("Resend API request failed.")
        return False, "Could not connect to the email provider.", None

    except ValueError:
        app.logger.exception("Invalid JSON returned by Resend.")
        return False, "Invalid response from the email provider.", None


@app.route("/send-one", methods=["POST"])
def send_one():
    if not is_logged_in():
        return jsonify({
            "ok": False,
            "error": "Please log in again.",
        }), 401

    verified_at = session.get("turnstile_verified_at", 0)

    if time.time() - verified_at > 600:
        session.pop("turnstile_verified_at", None)
        return jsonify({
            "ok": False,
            "error": "Verification expired. Please verify again.",
        }), 403

    data = request.get_json(silent=True) or {}

    recipient = str(data.get("recipient", "")).strip()
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))
    sender_name = str(data.get("senderName", "")).strip()
    html_mode = data.get("htmlMode") is True
    consent_confirmed = data.get("consentConfirmed") is True

    if not consent_confirmed:
        return jsonify({
            "ok": False,
            "error": "Please confirm you have permission to contact this recipient.",
        }), 400

    if not recipient or "@" not in recipient or recipient.startswith("@"):
        return jsonify({
            "ok": False,
            "error": "Enter a valid recipient email address.",
        }), 400

    if not subject:
        return jsonify({
            "ok": False,
            "error": "Subject cannot be empty.",
        }), 400

    if not body.strip():
        return jsonify({
            "ok": False,
            "error": "Message body cannot be empty.",
        }), 400

    success, message, email_id = send_with_resend(
        recipient=recipient,
        subject=subject,
        body=body,
        sender_name=sender_name,
        html_mode=html_mode,
    )

    if not success:
        return jsonify({
            "ok": False,
            "error": message,
        }), 502

    return jsonify({
        "ok": True,
        "message": message,
        "emailId": email_id,
    })


# Vercel imports this Flask application.
# Do not call app.run() in a serverless deployment.

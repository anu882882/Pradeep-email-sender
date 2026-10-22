
import os
import re
import time
import base64
import ssl
from email.message import EmailMessage
from email.utils import formataddr

import requests
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

app.secret_key = os.environ.get("SESSION_SECRET", "")
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REFRESH_TOKEN = os.environ.get("GOOGLE_REFRESH_TOKEN", "")

try:
    MAIL_GAP_SECONDS = max(
        0.0, min(float(os.environ.get("MAIL_GAP_SECONDS", "0.5")), 30.0)
    )
except (TypeError, ValueError):
    MAIL_GAP_SECONDS = 0.5

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"


def logged_in():
    return session.get("logged_in") is True


def google_credentials():
    if not all([
        GOOGLE_CLIENT_ID,
        GOOGLE_CLIENT_SECRET,
        GOOGLE_REFRESH_TOKEN,
    ]):
        raise RuntimeError(
            "Gmail API OAuth credentials are not configured."
        )

    creds = Credentials(
        token=None,
        refresh_token=GOOGLE_REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=[GMAIL_SEND_SCOPE],
    )

    creds.refresh(GoogleRequest())
    return creds


def gmail_service():
    credentials = google_credentials()
    return build(
        "gmail",
        "v1",
        credentials=credentials,
        cache_discovery=False,
    )


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if logged_in():
            return redirect(url_for("home"))
        return render_template("login.html")

    if not LOGIN_PASSWORD:
        return render_template(
            "login.html",
            error="LOGIN_PASSWORD is not configured."
        ), 500

    if request.form.get("password", "") == LOGIN_PASSWORD:
        session.clear()
        session["logged_in"] = True
        return redirect(url_for("home"))

    return render_template(
        "login.html",
        error="Incorrect password."
    ), 401


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def home():
    if not logged_in():
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


@app.post("/verify-turnstile")
def verify_turnstile():
    if not logged_in():
        return jsonify(ok=False, error="Please log in again."), 401

    if not TURNSTILE_SECRET_KEY or not TURNSTILE_SITE_KEY:
        return jsonify(
            ok=False,
            error="Cloudflare Turnstile keys are not configured.",
        ), 500

    data = request.get_json(silent=True) or {}
    token = data.get("token", "")

    if not token:
        return jsonify(
            ok=False, error="Complete Cloudflare verification first."
        ), 400

    try:
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": TURNSTILE_SECRET_KEY,
                "response": token,
            },
            timeout=8,
        )
        response.raise_for_status()
        result = response.json()
    except (requests.RequestException, ValueError):
        app.logger.exception("Turnstile verification failed")
        return jsonify(
            ok=False, error="Cloudflare verification is unavailable."
        ), 502

    if not result.get("success"):
        return jsonify(
            ok=False, error="Verification failed. Try again."
        ), 400

    session["turnstile_verified_at"] = time.time()
    return jsonify(ok=True)


def get_send_data(data):
    sender_name = str(data.get("senderName", "")).strip()[:120]
    sender_email = str(data.get("senderEmail", "")).strip().lower()
    subject = str(data.get("subject", "")).strip()[:250]
    body = str(data.get("body", ""))
    html_mode = data.get("htmlMode") is True

    if data.get("consentConfirmed") is not True:
        return None, (
            jsonify(
                ok=False,
                error="Confirm recipient consent before sending."
            ),
            400,
        )

    if (
        not EMAIL_RE.fullmatch(sender_email)
        or not sender_email.endswith("@gmail.com")
    ):
        return None, (
            jsonify(ok=False, error="Enter a valid Gmail address."),
            400,
        )

    if not subject or not body.strip():
        return None, (
            jsonify(
                ok=False,
                error="Subject and message body are required."
            ),
            400,
        )

    return {
        "sender_name": sender_name,
        "sender_email": sender_email,
        "subject": subject,
        "body": body,
        "html_mode": html_mode,
    }, None


def create_raw_message(sender_name, sender_email, recipient,
                       subject, body, html_mode):
    message = EmailMessage()

    message["From"] = (
        formataddr((sender_name, sender_email))
        if sender_name else sender_email
    )
    message["To"] = recipient
    message["Subject"] = subject

    if html_mode:
        message.set_content(
            "This email contains HTML content. "
            "Open it in an HTML-capable email client."
        )
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    encoded = base64.urlsafe_b64encode(
        message.as_bytes()
    ).decode("ascii")

    return {"raw": encoded}


def validate_recipients(values):
    if not isinstance(values, list) or not values:
        return None, "Enter at least one recipient."

    recipients = []
    seen = set()

    for value in values:
        email = str(value).strip().lower()

        if not EMAIL_RE.fullmatch(email):
            return None, "One or more recipient addresses are invalid."

        if email not in seen:
            seen.add(email)
            recipients.append(email)

    if len(recipients) > 25:
        return None, "Maximum 25 unique recipients allowed."

    return recipients, None


def send_gmail_api_batch(data, recipients):
    service = gmail_service()

    # Verify the actual Google account authorized by OAuth.
    profile = service.users().getProfile(userId="me").execute()
    authorized_email = profile.get("emailAddress", "").lower()

    if authorized_email != data["sender_email"]:
        raise ValueError(
            "The sender Gmail must match the Google account "
            "authorized for Gmail API."
        )

    results = []

    for index, recipient in enumerate(recipients):
        try:
            raw_message = create_raw_message(
                data["sender_name"],
                authorized_email,
                recipient,
                data["subject"],
                data["body"],
                data["html_mode"],
            )

            sent_message = (
                service.users()
                .messages()
                .send(userId="me", body=raw_message)
                .execute()
            )

            results.append({
                "recipient": recipient,
                "ok": True,
                "messageId": sent_message.get("id"),
            })

        except HttpError as exc:
            app.logger.warning(
                "Gmail API send failed for %s: %s",
                recipient,
                exc,
            )
            results.append({
                "recipient": recipient,
                "ok": False,
                "error": "Gmail API rejected or failed this message.",
            })

        if index < len(recipients) - 1 and MAIL_GAP_SECONDS > 0:
            time.sleep(MAIL_GAP_SECONDS)

    return results


def check_send_access():
    if not logged_in():
        return jsonify(ok=False, error="Please log in again."), 401

    verified_at = session.get("turnstile_verified_at", 0)

    if time.time() - verified_at > 600:
        session.pop("turnstile_verified_at", None)
        return jsonify(
            ok=False,
            error="Cloudflare verification expired. Verify again.",
        ), 403

    return None


@app.post("/send-batch")
def send_batch():
    access_error = check_send_access()
    if access_error:
        return access_error

    data = request.get_json(silent=True) or {}
    parsed, error = get_send_data(data)

    if error:
        return error

    recipients, recipient_error = validate_recipients(
        data.get("recipients", [])
    )

    if recipient_error:
        return jsonify(ok=False, error=recipient_error), 400

    try:
        results = send_gmail_api_batch(parsed, recipients)
        sent = sum(1 for result in results if result["ok"])
        failed = len(results) - sent

        return jsonify(
            ok=True,
            results=results,
            sent=sent,
            failed=failed,
        )

    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400

    except HttpError:
        app.logger.exception("Gmail API request failed")
        return jsonify(
            ok=False,
            error="Gmail API request failed. Check OAuth access and limits.",
        ), 502

    except (RuntimeError, Exception) as exc:
        app.logger.exception("Gmail API configuration or send failed")
        return jsonify(
            ok=False,
            error=(
                "Gmail API is not ready. Check OAuth settings and "
                "refresh token in Vercel."
            ),
        ), 502


@app.post("/send-one")
def send_one():
    access_error = check_send_access()
    if access_error:
        return access_error

    data = request.get_json(silent=True) or {}
    parsed, error = get_send_data(data)

    if error:
        return error

    recipient = str(data.get("recipient", "")).strip().lower()

    if not EMAIL_RE.fullmatch(recipient):
        return jsonify(
            ok=False, error="Invalid recipient address."
        ), 400

    try:
        results = send_gmail_api_batch(parsed, [recipient])

        if results and results[0]["ok"]:
            return jsonify(
                ok=True,
                message="Message accepted by Gmail API.",
                messageId=results[0].get("messageId"),
            )

        return jsonify(
            ok=False,
            error="Gmail API failed to send this message.",
        ), 502

    except (ValueError, RuntimeError):
        app.logger.exception("Gmail API configuration error")
        return jsonify(
            ok=False, error="Check your Gmail API OAuth configuration."
        ), 502

    except HttpError:
        app.logger.exception("Gmail API send-one failed")
        return jsonify(
            ok=False, error="Gmail API request failed."
        ), 502

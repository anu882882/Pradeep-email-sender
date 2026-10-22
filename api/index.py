
import os
import re
import time
import ssl
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

import requests
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)

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

try:
    MAIL_GAP_SECONDS = max(
        0.0,
        min(float(os.environ.get("MAIL_GAP_SECONDS", "0.5")), 30.0)
    )
except (TypeError, ValueError):
    MAIL_GAP_SECONDS = 0.5

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def logged_in():
    return session.get("logged_in") is True


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
            error="Set LOGIN_PASSWORD in Vercel Environment Variables."
        ), 500

    if request.form.get("password", "") == LOGIN_PASSWORD:
        session.clear()
        session["logged_in"] = True
        return redirect(url_for("home"))

    return render_template(
        "login.html", error="Incorrect password."
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
        turnstile_site_key=TURNSTILE_SITE_KEY
    )


@app.post("/verify-turnstile")
def verify_turnstile():
    if not logged_in():
        return jsonify(ok=False, error="Please log in again."), 401

    if not TURNSTILE_SECRET_KEY or not TURNSTILE_SITE_KEY:
        return jsonify(
            ok=False,
            error="Cloudflare Turnstile keys are not configured."
        ), 500

    data = request.get_json(silent=True) or {}
    token = data.get("token", "")

    if not token:
        return jsonify(
            ok=False,
            error="Complete Cloudflare verification first."
        ), 400

    try:
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": TURNSTILE_SECRET_KEY,
                "response": token,
                "remoteip": request.headers.get(
                    "CF-Connecting-IP", ""
                ),
            },
            timeout=8,
        )
        response.raise_for_status()
        result = response.json()

    except (requests.RequestException, ValueError):
        app.logger.exception("Turnstile verification request failed")
        return jsonify(
            ok=False,
            error="Cloudflare verification service is unavailable."
        ), 502

    if not result.get("success"):
        return jsonify(
            ok=False,
            error="Verification failed. Please try again."
        ), 400

    session["turnstile_verified_at"] = time.time()
    return jsonify(ok=True)


def build_message(
    sender_email, sender_name, recipient, subject, body, html_mode
):
    message = EmailMessage()
    message["From"] = (
        formataddr((sender_name, sender_email))
        if sender_name else sender_email
    )
    message["To"] = recipient
    message["Subject"] = subject

    if html_mode:
        message.set_content(
            "This message contains HTML content. "
            "Please use an HTML-capable email client."
        )
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    return message


def send_batch_smtp(
    sender_email, app_password, sender_name,
    recipients, subject, body, html_mode
):
    results = []

    # Reuse one SMTP connection for this batch.
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=25) as server:
        server.ehlo()
        server.starttls(context=ssl.create_default_context())
        server.ehlo()
        server.login(sender_email, app_password)

        for index, recipient in enumerate(recipients):
            try:
                message = build_message(
                    sender_email, sender_name, recipient,
                    subject, body, html_mode
                )
                refused = server.send_message(message)

                if refused:
                    results.append({
                        "recipient": recipient,
                        "ok": False,
                        "error": "Recipient was refused by the mail server."
                    })
                else:
                    results.append({
                        "recipient": recipient,
                        "ok": True
                    })

            except (
                smtplib.SMTPException,
                OSError,
                TimeoutError
            ) as exc:
                app.logger.warning(
                    "SMTP send failed for %s: %s", recipient, exc
                )
                results.append({
                    "recipient": recipient,
                    "ok": False,
                    "error": "SMTP sending failed for this recipient."
                })

            if (
                index < len(recipients) - 1
                and MAIL_GAP_SECONDS > 0
            ):
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
            error="Cloudflare verification expired. Verify again."
        ), 403

    return None


def parse_send_data(data):
    sender_name = str(data.get("senderName", "")).strip()[:120]
    sender_email = str(data.get("senderEmail", "")).strip().lower()
    app_password = str(data.get("appPassword", "")).replace(" ", "")
    subject = str(data.get("subject", "")).strip()[:250]
    body = str(data.get("body", ""))
    html_mode = data.get("htmlMode") is True

    if data.get("consentConfirmed") is not True:
        return None, (
            jsonify(
                ok=False,
                error="Confirm that recipients agreed to receive the email."
            ),
            400
        )

    if (
        not EMAIL_RE.fullmatch(sender_email)
        or not sender_email.endswith("@gmail.com")
    ):
        return None, (
            jsonify(ok=False, error="Enter a valid Gmail address."),
            400
        )

    if not app_password:
        return None, (
            jsonify(ok=False, error="Enter your Google App Password."),
            400
        )

    if not subject or not body.strip():
        return None, (
            jsonify(
                ok=False,
                error="Subject and message body are required."
            ),
            400
        )

    return {
        "sender_name": sender_name,
        "sender_email": sender_email,
        "app_password": app_password,
        "subject": subject,
        "body": body,
        "html_mode": html_mode,
    }, None


@app.post("/send-batch")
def send_batch():
    access_error = check_send_access()
    if access_error:
        return access_error

    data = request.get_json(silent=True) or {}
    parsed, error = parse_send_data(data)

    if error:
        return error

    raw_recipients = data.get("recipients", [])

    if not isinstance(raw_recipients, list) or not raw_recipients:
        return jsonify(
            ok=False, error="Enter at least one recipient."
        ), 400

    recipients = []
    seen = set()

    for value in raw_recipients:
        email = str(value).strip().lower()

        if not EMAIL_RE.fullmatch(email):
            return jsonify(
                ok=False,
                error="One or more recipient addresses are invalid."
            ), 400

        if email not in seen:
            seen.add(email)
            recipients.append(email)

    if len(recipients) > 25:
        return jsonify(
            ok=False, error="Maximum 25 unique recipients allowed."
        ), 400

    try:
        results = send_batch_smtp(
            parsed["sender_email"],
            parsed["app_password"],
            parsed["sender_name"],
            recipients,
            parsed["subject"],
            parsed["body"],
            parsed["html_mode"],
        )

        sent = sum(1 for item in results if item["ok"])
        failed = len(results) - sent

        return jsonify(
            ok=True,
            results=results,
            sent=sent,
            failed=failed,
        )

    except smtplib.SMTPAuthenticationError:
        return jsonify(
            ok=False,
            error="Gmail login failed. Check your Google App Password."
        ), 502

    except (smtplib.SMTPException, OSError, TimeoutError):
        app.logger.exception("SMTP batch failed")
        return jsonify(
            ok=False,
            error="SMTP connection failed. Check Gmail limits and credentials."
        ), 502


@app.post("/send-one")
def send_one():
    access_error = check_send_access()
    if access_error:
        return access_error

    data = request.get_json(silent=True) or {}
    parsed, error = parse_send_data(data)

    if error:
        return error

    recipient = str(data.get("recipient", "")).strip().lower()

    if not EMAIL_RE.fullmatch(recipient):
        return jsonify(
            ok=False, error="Invalid recipient address."
        ), 400

    try:
        results = send_batch_smtp(
            parsed["sender_email"],
            parsed["app_password"],
            parsed["sender_name"],
            [recipient],
            parsed["subject"],
            parsed["body"],
            parsed["html_mode"],
        )

        if results and results[0]["ok"]:
            return jsonify(ok=True, message="Accepted by Gmail SMTP.")

        return jsonify(
            ok=False,
            error=results[0].get("error", "Sending failed.")
        ), 502

    except smtplib.SMTPAuthenticationError:
        return jsonify(
            ok=False,
            error="Gmail login failed. Check your Google App Password."
        ), 502

    except (smtplib.SMTPException, OSError, TimeoutError):
        app.logger.exception("SMTP single send failed")
        return jsonify(
            ok=False,
            error="SMTP connection failed."
        ), 502

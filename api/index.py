import os
import re
import time
import ssl
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

import requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify

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

# Pause between messages on the same SMTP connection.
# Set MAIL_GAP_SECONDS in Vercel if you need to adjust it.
try:
    MAIL_GAP_SECONDS = max(
        0.0, min(float(os.environ.get("MAIL_GAP_SECONDS", "0.2")), 30.0)
    )
except (TypeError, ValueError):
    MAIL_GAP_SECONDS = 0.2

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def logged_in():
    return session.get("logged_in") is True


@app.get("/health")
def health():
    return jsonify(
        status="ok",
        login_template_found=os.path.isfile(
            os.path.join(BASE_DIR, "templates", "login.html")
        ),
        index_template_found=os.path.isfile(
            os.path.join(BASE_DIR, "templates", "index.html")
        ),
    )


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

    return render_template("login.html", error="Incorrect password."), 401


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def home():
    if not logged_in():
        return redirect(url_for("login"))

    return render_template("index.html", turnstile_site_key=TURNSTILE_SITE_KEY)


@app.post("/verify-turnstile")
def verify_turnstile():
    if not logged_in():
        return jsonify(ok=False, error="Please log in again."), 401

    if not TURNSTILE_SECRET_KEY:
        return jsonify(ok=False, error="Turnstile is not configured."), 500

    data = request.get_json(silent=True) or {}
    token = data.get("token", "")

    if not token:
        return jsonify(ok=False, error="Complete security verification first."), 400

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
    except (requests.RequestException, ValueError):
        app.logger.exception("Turnstile verification failed")
        return jsonify(ok=False, error="Verification service unavailable."), 502

    if not result.get("success"):
        return jsonify(ok=False, error="Verification failed. Try again."), 400

    session["turnstile_verified_at"] = time.time()
    return jsonify(ok=True)


def build_message(sender_email, sender_name, recipient, subject, body, html_mode):
    message = EmailMessage()
    message["From"] = (
        formataddr((sender_name, sender_email)) if sender_name else sender_email
    )
    message["To"] = recipient
    message["Subject"] = subject

    if html_mode:
        message.set_content(
            "This message contains HTML content. "
            "Open it in an HTML-capable email client."
        )
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    return message


def send_batch_smtp(sender_email, app_password, sender_name,
                    recipients, subject, body, html_mode):
    """
    Open and authenticate one SMTP connection for this batch, then send
    each message sequentially over that connection.
    """
    results = []

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=25) as server:
        server.ehlo()
        server.starttls(context=ssl.create_default_context())
        server.ehlo()
        server.login(sender_email, app_password)

        for index, recipient in enumerate(recipients):
            try:
                message = build_message(
                    sender_email, sender_name, recipient, subject, body, html_mode
                )
                refused = server.send_message(message)

                if refused:
                    results.append({
                        "recipient": recipient,
                        "ok": False,
                        "error": "Gmail refused this recipient."
                    })
                else:
                    results.append({"recipient": recipient, "ok": True})

            except smtplib.SMTPRecipientsRefused:
                results.append({
                    "recipient": recipient,
                    "ok": False,
                    "error": "Gmail rejected this recipient address."
                })
            except (smtplib.SMTPException, OSError, TimeoutError) as exc:
                app.logger.warning("SMTP send failed for %s: %s", recipient, exc)
                results.append({
                    "recipient": recipient,
                    "ok": False,
                    "error": "SMTP failed for this recipient."
                })

            if index < len(recipients) - 1 and MAIL_GAP_SECONDS:
                time.sleep(MAIL_GAP_SECONDS)

    return results


@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify(ok=False, error="Please log in again."), 401

    verified_at = session.get("turnstile_verified_at", 0)
    if time.time() - verified_at > 600:
        session.pop("turnstile_verified_at", None)
        return jsonify(
            ok=False,
            error="Verification expired. Verify again."
        ), 403

    data = request.get_json(silent=True) or {}

    sender_name = str(data.get("senderName", "")).strip()[:120]
    sender_email = str(data.get("senderEmail", "")).strip()
    app_password = str(data.get("appPassword", "")).replace(" ", "")
    subject = str(data.get("subject", "")).strip()[:250]
    body = str(data.get("body", ""))
    html_mode = data.get("htmlMode") is True
    raw_recipients = data.get("recipients", [])

    if data.get("consentConfirmed") is not True:
        return jsonify(
            ok=False,
            error="Confirm recipients agreed to receive this email."
        ), 400

    if not EMAIL_RE.fullmatch(sender_email) or not sender_email.lower().endswith("@gmail.com"):
        return jsonify(ok=False, error="Enter a valid Gmail address."), 400

    if not app_password:
        return jsonify(ok=False, error="Enter your Google App Password."), 400

    if not isinstance(raw_recipients, list) or not raw_recipients:
        return jsonify(ok=False, error="Enter at least one recipient."), 400

    recipients = []
    seen = set()
    for value in raw_recipients:
        email = str(value).strip().lower()
        if not EMAIL_RE.fullmatch(email):
            return jsonify(ok=False, error="One or more recipient addresses are invalid."), 400
        if email not in seen:
            seen.add(email)
            recipients.append(email)

    if len(recipients) > 25:
        return jsonify(ok=False, error="Maximum 25 unique recipients allowed."), 400

    if not subject or not body.strip():
        return jsonify(ok=False, error="Subject and message body are required."), 400

    try:
        results = send_batch_smtp(
            sender_email, app_password, sender_name,
            recipients, subject, body, html_mode
        )
        sent = sum(1 for item in results if item["ok"])
        failed = len(results) - sent
        return jsonify(
            ok=True,
            message="Batch finished.",
            results=results,
            sent=sent,
            failed=failed,
        )
    except smtplib.SMTPAuthenticationError:
        return jsonify(
            ok=False,
            error="Gmail authentication failed. Check your email and App Password."
        ), 502
    except (smtplib.SMTPException, OSError, TimeoutError):
        app.logger.exception("Gmail SMTP batch failed")
        return jsonify(
            ok=False,
            error="Gmail SMTP failed. Check credentials, connection, or sending limits."
        ), 502


# Keep the old endpoint available for compatibility with older frontend versions.
@app.post("/send-one")
def send_one():
    if not logged_in():
        return jsonify(ok=False, error="Please log in again."), 401

    verified_at = session.get("turnstile_verified_at", 0)
    if time.time() - verified_at > 600:
        session.pop("turnstile_verified_at", None)
        return jsonify(ok=False, error="Verification expired. Verify again."), 403

    data = request.get_json(silent=True) or {}
    recipient = str(data.get("recipient", "")).strip().lower()
    sender_email = str(data.get("senderEmail", "")).strip()
    app_password = str(data.get("appPassword", "")).replace(" ", "")
    sender_name = str(data.get("senderName", "")).strip()[:120]
    subject = str(data.get("subject", "")).strip()[:250]
    body = str(data.get("body", ""))
    html_mode = data.get("htmlMode") is True

    if data.get("consentConfirmed") is not True:
        return jsonify(ok=False, error="Confirm recipient consent first."), 400
    if not EMAIL_RE.fullmatch(sender_email) or not sender_email.lower().endswith("@gmail.com"):
        return jsonify(ok=False, error="Enter a valid Gmail address."), 400
    if not app_password:
        return jsonify(ok=False, error="Enter your Google App Password."), 400
    if not EMAIL_RE.fullmatch(recipient):
        return jsonify(ok=False, error="Invalid recipient address."), 400
    if not subject or not body.strip():
        return jsonify(ok=False, error="Subject and message body are required."), 400

    try:
        results = send_batch_smtp(
            sender_email, app_password, sender_name,
            [recipient], subject, body, html_mode
        )
        if results and results[0]["ok"]:
            return jsonify(ok=True, message="Accepted by Gmail SMTP.")
        return jsonify(ok=False, error=(results[0].get("error") if results else "Send failed.")), 502
    except smtplib.SMTPAuthenticationError:
        return jsonify(ok=False, error="Gmail authentication failed. Check your email and App Password."), 502
    except (smtplib.SMTPException, OSError, TimeoutError):
        app.logger.exception("Gmail SMTP send failed")
        return jsonify(ok=False, error="Gmail SMTP failed. Check credentials and connection."), 502


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
MAIL_GAP_SECONDS = max(
    0.0, min(float(os.environ.get("MAIL_GAP_SECONDS", "2")), 30.0)
)

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
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


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


def gmail_send(sender_email, app_password, sender_name,
               recipient, subject, body, html_mode):
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
            "Open it in an HTML-capable email client."
        )
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=25) as server:
        server.ehlo()
        server.starttls(context=ssl.create_default_context())
        server.ehlo()
        server.login(sender_email, app_password)
        server.send_message(message)


@app.post("/send-one")
def send_one():
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
    recipient = str(data.get("recipient", "")).strip()
    subject = str(data.get("subject", "")).strip()[:250]
    body = str(data.get("body", ""))
    html_mode = data.get("htmlMode") is True

    if data.get("consentConfirmed") is not True:
        return jsonify(
            ok=False,
            error="Confirm recipients agreed to receive this email."
        ), 400

    if not EMAIL_RE.fullmatch(sender_email):
        return jsonify(ok=False, error="Enter a valid Gmail address."), 400

    if not app_password:
        return jsonify(ok=False, error="Enter your Google App Password."), 400

    if not EMAIL_RE.fullmatch(recipient):
        return jsonify(ok=False, error="Invalid recipient address."), 400

    if not subject or not body.strip():
        return jsonify(
            ok=False,
            error="Subject and message body are required."
        ), 400

    try:
        gmail_send(
            sender_email, app_password, sender_name,
            recipient, subject, body, html_mode
        )
        return jsonify(ok=True, message="Accepted by Gmail SMTP.")

    except smtplib.SMTPAuthenticationError:
        return jsonify(
            ok=False,
            error="Gmail authentication failed. Check your email and App Password."
        ), 502

    except smtplib.SMTPRecipientsRefused:
        return jsonify(
            ok=False,
            error="Gmail rejected the recipient address."
        ), 502

    except (smtplib.SMTPException, OSError, TimeoutError):
        app.logger.exception("Gmail SMTP send failed")
        return jsonify(
            ok=False,
            error="Gmail SMTP failed. Check your credentials and connection."
        ), 502

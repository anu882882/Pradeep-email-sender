import os
import re
import ssl
import smtplib
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from email.utils import formataddr

from flask import Flask, request, render_template, redirect, url_for, jsonify, session

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

logging.basicConfig(level=logging.INFO)

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()

if not SESSION_SECRET or not LOGIN_PASSWORD:
    raise RuntimeError("SESSION_SECRET and LOGIN_PASSWORD must be configured.")

app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 5

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def authenticated():
    return session.get("authenticated") is True


def clean_header(value, limit=998):
    value = str(value or "")
    value = value.replace("\r", " ").replace("\n", " ")
    return value.strip()[:limit]


def valid_email(value):
    value = str(value or "").strip()
    return len(value) <= 254 and bool(EMAIL_RE.fullmatch(value))


def parse_recipients(value):
    items = re.split(r"[\s,;]+", str(value or ""))
    return list(dict.fromkeys(
        item.strip().lower()
        for item in items if item.strip()
    ))


@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))

    if request.method == "POST":
        import secrets

        password = str(request.form.get("password", ""))

        if secrets.compare_digest(password, LOGIN_PASSWORD):
            session.clear()
            session["authenticated"] = True
            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Incorrect password."
        ), 401

    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    if not authenticated():
        return redirect(url_for("login"))

    return render_template("index.html")


def send_one(data, recipient):
    message = EmailMessage()

    message["Subject"] = clean_header(data["subject"])
    message["From"] = formataddr((
        data["sender_name"],
        data["gmail"]
    ))
    message["To"] = recipient

    if data["is_html"]:
        message.set_content("This message contains HTML content.")
        message.add_alternative(
            data["message"],
            subtype="html"
        )
    else:
        message.set_content(data["message"])

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT
    ) as server:
        server.login(
            data["gmail"],
            data["app_password"]
        )
        server.send_message(message)

    return recipient


@app.route("/send", methods=["POST"])
def send():
    if not authenticated():
        return jsonify({
            "success": False,
            "message": "Your session has expired. Please sign in again."
        }), 401

    data = request.get_json(silent=True) or {}

    sender_name = clean_header(data.get("sender_name"), 200)
    gmail = str(data.get("gmail", "")).strip().lower()
    app_password = str(data.get("app_password", "")).replace(" ", "")
    subject = clean_header(data.get("subject"))
    body = str(data.get("message", ""))
    recipients = parse_recipients(data.get("recipients"))

    if not sender_name or not gmail or not app_password:
        return jsonify({
            "success": False,
            "message": "Complete all sender details."
        }), 400

    if not valid_email(gmail):
        return jsonify({
            "success": False,
            "message": "Enter a valid Gmail address."
        }), 400

    if not subject or not body.strip():
        return jsonify({
            "success": False,
            "message": "Subject and message are required."
        }), 400

    if not recipients:
        return jsonify({
            "success": False,
            "message": "Add at least one recipient."
        }), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "success": False,
            "message": f"Maximum {MAX_RECIPIENTS} recipients allowed."
        }), 400

    invalid = [
        email for email in recipients
        if not valid_email(email)
    ]

    if invalid:
        return jsonify({
            "success": False,
            "message": "Invalid recipient address: "
            + ", ".join(invalid[:5])
        }), 400

    if not data.get("consent_confirmed"):
        return jsonify({
            "success": False,
            "message": "Confirm that recipients have agreed to receive your emails."
        }), 400

    send_data = {
        "sender_name": sender_name,
        "gmail": gmail,
        "app_password": app_password,
        "subject": subject,
        "message": body,
        "is_html": bool(data.get("is_html")),
    }

    sent = []
    failed = []

    with ThreadPoolExecutor(
        max_workers=MAX_PARALLEL_SENDS
    ) as executor:

        jobs = {
            executor.submit(send_one, send_data, recipient): recipient
            for recipient in recipients
        }

        for future in as_completed(jobs):
            recipient = jobs[future]

            try:
                future.result()
                sent.append(recipient)
            except Exception:
                logging.exception(
                    "Email send failed for %s",
                    recipient
                )
                failed.append(recipient)

    return jsonify({
        "success": len(failed) == 0,
        "sent": len(sent),
        "failed": len(failed),
        "total": len(recipients),
        "failed_recipients": failed,
        "message": (
            f"SMTP accepted {len(sent)} message(s); "
            f"{len(failed)} failed."
        )
    })


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "templates": (BASE_DIR / "templates").exists(),
        "static": (BASE_DIR / "static").exists()
    })

import os
import re
import ssl
import json
import time
import smtplib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from email.utils import formataddr
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, Response, stream_with_context
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

app.secret_key = os.environ.get("SESSION_SECRET", "change-this-secret-before-deploying")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("VERCEL") == "1",
    MAX_CONTENT_LENGTH=1 * 1024 * 1024
)

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

MAX_RECIPIENTS = 25
BATCH_SIZE = 5
MAX_PARALLEL_SENDS = 5
BATCH_DELAY_SECONDS = 1

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Your session has expired. Please sign in again."}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def is_valid_email(email):
    return bool(EMAIL_PATTERN.fullmatch(email or ""))


def parse_recipients(raw_value):
    values = re.split(r"[,;\s]+", raw_value or "")
    recipients = []
    seen = set()

    for value in values:
        email = value.strip().lower()
        if email and email not in seen and is_valid_email(email):
            if email not in seen:
                recipients.append(email)
                seen.add(email)

    return recipients


def apply_spintax(value):
    pattern = re.compile(r"\{([^{}]+)\}")

    while True:
        match = pattern.search(value)
        if not match:
            break

        choices = [item.strip() for item in match.group(1).split("|") if item.strip()]
        replacement = choices[0] if len(choices) == 1 else (
            __import__("random").choice(choices) if choices else ""
        )
        value = value[:match.start()] + replacement + value[match.end():]

    return value


def html_to_text(value):
    value = re.sub(r"(?i)<br\s*/?>", "\n", value)
    value = re.sub(r"(?i)</(p|div|li)>", "\n", value)
    value = re.sub(r"<[^>]+>", "", value)
    return value.strip()


def create_email(data, recipient):
    sender_name = data["sender_name"]
    sender_email = data["gmail"]

    subject = apply_spintax(data["subject"])
    body = data["body"]

    body = body.replace("{{name}}", recipient.split("@")[0])
    body = body.replace("{{email}}", recipient)
    body = apply_spintax(body)

    message = EmailMessage()
    message["From"] = formataddr((sender_name, sender_email))
    message["To"] = recipient
    message["Subject"] = subject

    if data["is_html"]:
        message.set_content(html_to_text(body) or "Please view this email in an HTML-compatible email client.")
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    return message


def send_one(data, recipient):
    message = create_email(data, recipient)
    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=30
    ) as server:
        server.login(data["gmail"], data["app_password"])
        server.send_message(message)

    return True


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        password = request.form.get("password", "")

        if not LOGIN_PASSWORD:
            error = "Login is not configured. Set LOGIN_PASSWORD in Vercel."
        elif password == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("index"))
        else:
            error = "Incorrect password. Please try again."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/send", methods=["POST"])
@login_required
def send_emails():
    data = request.get_json(silent=True) or {}

    sender_name = str(data.get("sender_name", "")).strip()
    gmail = str(data.get("gmail", "")).strip().lower()
    app_password = re.sub(r"\s+", "", str(data.get("app_password", "")))
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))
    is_html = data.get("is_html") is True
    consent = data.get("consent") is True

    recipients = parse_recipients(data.get("recipients", ""))

    if not sender_name:
        return jsonify({"error": "Please enter Sender Name."}), 400

    if not is_valid_email(gmail):
        return jsonify({"error": "Please enter a valid Gmail address."}), 400

    if not app_password:
        return jsonify({"error": "Please enter your Gmail App Password."}), 400

    if not subject:
        return jsonify({"error": "Please enter Email Subject."}), 400

    if not body.strip():
        return jsonify({"error": "Please enter Message Body."}), 400

    if not consent:
        return jsonify({"error": "Please confirm recipient permission before sending."}), 400

    if not recipients:
        return jsonify({"error": "Please enter at least one valid recipient email."}), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({"error": f"Maximum {MAX_RECIPIENTS} recipients are allowed per send session."}), 400

    send_data = {
        "sender_name": sender_name,
        "gmail": gmail,
        "app_password": app_password,
        "subject": subject,
        "body": body,
        "is_html": is_html
    }

    def generate():
        total = len(recipients)
        sent = 0
        failed = 0

        yield json.dumps({
            "type": "start",
            "total": total
        }) + "\n"

        for batch_start in range(0, total, BATCH_SIZE):
            batch = recipients[batch_start:batch_start + BATCH_SIZE]

            with ThreadPoolExecutor(max_workers=MAX_PARALLEL_SENDS) as executor:
                futures = {
                    executor.submit(send_one, send_data, recipient): recipient
                    for recipient in batch
                }

                for future in as_completed(futures):
                    recipient = futures[future]

                    try:
                        future.result()
                        sent += 1
                        status = "sent"
                        detail = "Accepted by SMTP"
                    except Exception as exc:
                        failed += 1
                        status = "failed"
                        detail = str(exc).strip()[:180] or "SMTP sending failed"

                    yield json.dumps({
                        "type": "result",
                        "email": recipient,
                        "status": status,
                        "message": detail,
                        "sent": sent,
                        "failed": failed,
                        "remaining": total - sent - failed
                    }) + "\n"

            if batch_start + BATCH_SIZE < total:
                time.sleep(BATCH_DELAY_SECONDS)

        yield json.dumps({
            "type": "complete",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": 0
        }) + "\n"

    return Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no"
        }
    )


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

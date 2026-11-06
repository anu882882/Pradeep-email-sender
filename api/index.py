import os
import re
import ssl
import time
import json
import html
import random
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

app.secret_key = os.environ.get("SESSION_SECRET") or os.urandom(32).hex()
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 2
SEND_DELAY_SECONDS = 0.1

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
send_lock = threading.Lock()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Please sign in again."}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def valid_email(value):
    return bool(EMAIL_PATTERN.fullmatch(value or ""))


def parse_recipients(raw):
    values = re.split(r"[\n,;\t]+", raw or "")
    cleaned = []
    seen = set()

    for value in values:
        email = value.strip().lower()
        if email and email not in seen and valid_email(email):
            cleaned.append(email)
            seen.add(email)

    return cleaned


def apply_spintax(text):
    pattern = re.compile(r"\{([^{}]+)\}")

    while True:
        match = pattern.search(text)
        if not match:
            break

        choices = match.group(1).split("|")
        replacement = random.choice(choices).strip()
        text = text[:match.start()] + replacement + text[match.end():]

    return text


def plain_from_html(value):
    value = re.sub(r"(?i)<br\s*/?>", "\n", value)
    value = re.sub(r"(?i)</(p|div|li|h[1-6])\s*>", "\n", value)
    value = re.sub(r"<[^>]*>", "", value)
    return html.unescape(value).strip()


def build_message(data, recipient):
    sender_name = data["sender_name"].strip()
    sender_email = data["gmail"].strip()
    subject = apply_spintax(data["subject"].strip())

    body = data["body"]
    body = body.replace("{{email}}", recipient)
    body = body.replace("{{name}}", recipient.split("@")[0])
    body = apply_spintax(body)

    message = EmailMessage()
    message["From"] = formataddr((sender_name, sender_email))
    message["To"] = recipient
    message["Subject"] = subject

    if data["body_mode"] == "html":
        message.set_content(plain_from_html(body) or "Please view this message in an HTML-compatible email client.")
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    return message


def send_one(data, recipient):
    message = build_message(data, recipient)
    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=25
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
        elif password and password == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            session.permanent = False
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
    gmail = str(data.get("gmail", "")).strip()
    app_password = re.sub(r"\s+", "", str(data.get("app_password", "")))
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))
    body_mode = data.get("body_mode", "text")
    consent = data.get("consent") is True

    recipients = parse_recipients(data.get("recipients", ""))

    if not sender_name:
        return jsonify({"error": "Please enter Sender Name."}), 400

    if len(sender_name) > 100:
        return jsonify({"error": "Sender Name is too long."}), 400

    if not valid_email(gmail):
        return jsonify({"error": "Please enter a valid Gmail address."}), 400

    if not app_password:
        return jsonify({"error": "Please enter your Gmail App Password."}), 400

    if not subject:
        return jsonify({"error": "Please enter an email subject."}), 400

    if len(subject) > 200:
        return jsonify({"error": "Subject is too long."}), 400

    if not body.strip():
        return jsonify({"error": "Please enter your message body."}), 400

    if body_mode not in ("text", "html"):
        return jsonify({"error": "Invalid message format."}), 400

    if not consent:
        return jsonify({"error": "Please confirm recipient consent before sending."}), 400

    if not recipients:
        return jsonify({"error": "No valid email addresses were found."}), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({"error": f"Maximum {MAX_RECIPIENTS} recipients are allowed per session."}), 400

    send_data = {
        "sender_name": sender_name,
        "gmail": gmail,
        "app_password": app_password,
        "subject": subject,
        "body": body,
        "body_mode": body_mode
    }

    def generate():
        total = len(recipients)
        sent = 0
        failed = 0

        yield json.dumps({
            "type": "start",
            "total": total
        }) + "\n"

        # Two messages are processed concurrently per batch.
        for start in range(0, total, MAX_PARALLEL_SENDS):
            batch = recipients[start:start + MAX_PARALLEL_SENDS]

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
                        result = {
                            "type": "result",
                            "email": recipient,
                            "status": "sent",
                            "message": "Accepted by SMTP."
                        }
                    except Exception as exc:
                        failed += 1
                        error_text = str(exc).strip() or "SMTP sending failed."
                        result = {
                            "type": "result",
                            "email": recipient,
                            "status": "failed",
                            "message": error_text[:250]
                        }

                    result["sent"] = sent
                    result["failed"] = failed
                    result["remaining"] = total - sent - failed

                    yield json.dumps(result) + "\n"

            if start + MAX_PARALLEL_SENDS < total:
                time.sleep(SEND_DELAY_SECONDS)

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
    app.run(debug=False)

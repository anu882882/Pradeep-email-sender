from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, Response, stream_with_context
)
import smtplib
import ssl
import re
import os
import json
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static"
)
handler = app

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    "local-development-only-change-this-secret"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("VERCEL", "") == "1",
    MAX_CONTENT_LENGTH=2 * 1024 * 1024
)

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 2

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Referrer-Policy", "strict-origin-when-cross-origin"
    )
    return response


def valid_email(value):
    return bool(EMAIL_RE.fullmatch(str(value).strip()))


def authenticated():
    return session.get("authenticated") is True


def clean_header(value):
    return (
        str(value or "")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":
        password = str(request.form.get("password", ""))
        configured_password = os.environ.get("LOGIN_PASSWORD", "")

        if not configured_password:
            error = "LOGIN_PASSWORD is not configured."
        elif secrets.compare_digest(password, configured_password):
            session.clear()
            session["authenticated"] = True
            return redirect(url_for("home"))
        else:
            error = "Incorrect password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    if not authenticated():
        return redirect(url_for("login"))

    return render_template("index.html")


def send_one_email(
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    recipient
):
    context = ssl.create_default_context()

    message = MIMEText(
        body,
        "html" if is_html else "plain",
        "utf-8"
    )
    message["Subject"] = subject
    message["From"] = formataddr((sender_name, gmail))
    message["To"] = recipient
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        context=context,
        timeout=20
    ) as server:
        server.login(gmail, app_password)
        server.sendmail(gmail, [recipient], message.as_string())

    return recipient


@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not authenticated():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    data = request.get_json(silent=True) or {}

    sender_name = clean_header(data.get("sender_name", ""))
    gmail = clean_header(data.get("gmail", ""))
    app_password = str(data.get("app_password", "")).strip()
    subject = clean_header(data.get("subject", ""))
    body = str(data.get("body", ""))
    is_html = bool(data.get("is_html", False))
    recipients = data.get("recipients", [])

    if not sender_name:
        return jsonify({
            "success": False,
            "message": "Sender Name is required."
        }), 400

    if not valid_email(gmail):
        return jsonify({
            "success": False,
            "message": "Enter a valid sender email address."
        }), 400

    if not app_password:
        return jsonify({
            "success": False,
            "message": "Google App Password is required."
        }), 400

    if not subject:
        return jsonify({
            "success": False,
            "message": "Email subject is required."
        }), 400

    if not body.strip():
        return jsonify({
            "success": False,
            "message": "Message Body is required."
        }), 400

    if not isinstance(recipients, list):
        return jsonify({
            "success": False,
            "message": "Invalid recipient list."
        }), 400

    clean_recipients = []

    for item in recipients:
        email = str(item).strip().lower()

        if valid_email(email) and email not in clean_recipients:
            clean_recipients.append(email)

    clean_recipients = clean_recipients[:MAX_RECIPIENTS]

    if not clean_recipients:
        return jsonify({
            "success": False,
            "message": "No valid recipients found."
        }), 400

    @stream_with_context
    def generate():
        total = len(clean_recipients)
        sent_count = 0
        failed_count = 0

        yield json.dumps({
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total
        }) + "\n"

        with ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_SENDS
        ) as executor:
            future_map = {
                executor.submit(
                    send_one_email,
                    gmail,
                    app_password,
                    sender_name,
                    subject,
                    body,
                    is_html,
                    recipient
                ): recipient
                for recipient in clean_recipients
            }

            for future in as_completed(future_map):
                recipient = future_map[future]

                try:
                    future.result()
                    sent_count += 1
                    result = "sent"
                    error_message = None

                except smtplib.SMTPAuthenticationError:
                    failed_count += 1
                    result = "failed"
                    error_message = (
                        "Gmail authentication failed. Check your "
                        "Gmail address and Google App Password."
                    )

                except Exception as exc:
                    failed_count += 1
                    result = "failed"
                    error_message = str(exc)

                event = {
                    "type": "progress",
                    "email": recipient,
                    "result": result,
                    "total": total,
                    "sent": sent_count,
                    "failed": failed_count,
                    "remaining": total - sent_count - failed_count
                }

                if error_message:
                    event["error"] = error_message

                yield json.dumps(event) + "\n"

        yield json.dumps({
            "type": "complete",
            "success": True,
            "message": "Sending completed.",
            "total": total,
            "sent": sent_count,
            "failed": failed_count,
            "remaining": total - sent_count - failed_count
        }) + "\n"

    return Response(
        generate(),
        content_type="application/x-ndjson; charset=utf-8",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no"
        }
    )


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "Secure Mail Console",
        "mailer": "Gmail SMTP",
        "parallel_sends": MAX_PARALLEL_SENDS
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG", "") == "1"
    )

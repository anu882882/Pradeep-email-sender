import os
import re
import ssl
import smtplib
import json
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, Response, stream_with_context
)

from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(ROOT, "templates"),
    static_folder=os.path.join(ROOT, "static")
)

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    "RakshakSecureSession_2026"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

# LOGIN
LOGIN_PASSWORD = os.environ.get(
    "APP_LOGIN_PASSWORD",
    "Love882@#"
)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

MAX_RECIPIENTS = 25
BATCH_SIZE = 5

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(email):
    return bool(
        EMAIL_RE.fullmatch(str(email).strip())
    )


def get_recipients(raw):
    raw = str(raw or "")
    raw = raw.replace(",", "\n")
    raw = raw.replace(";", "\n")

    result = []
    seen = set()

    for item in raw.split():
        email = item.strip().lower()

        if email and email not in seen:
            seen.add(email)
            result.append(email)

    return result


def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("logged_in"):

            if request.path.startswith("/api/"):
                return jsonify({
                    "success": False,
                    "error": "Login required."
                }), 401

            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


# ================= LOGIN =================

@app.route("/login", methods=["GET", "POST"])
def login():

    if session.get("logged_in"):
        return redirect(url_for("home"))

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        if password != LOGIN_PASSWORD:

            return render_template(
                "login.html",
                error="Incorrect password."
            )

        session.clear()
        session["logged_in"] = True

        return redirect(
            url_for("home")
        )

    return render_template(
        "login.html"
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ================= HOME =================

@app.route("/")
@login_required
def home():

    return render_template(
        "index.html"
    )


# ================= HEALTH =================

@app.route("/api/health")
def health():

    return jsonify({
        "ok": True,
        "service": "Secure Mail Console"
    })


# ================= SEND ONE =================

def send_one(
    sender_name,
    gmail,
    app_password,
    recipient,
    subject,
    message
):

    try:

        body = message.replace(
            "{name}",
            recipient.split("@")[0]
        )

        mail = MIMEText(
            body,
            "plain",
            "utf-8"
        )

        mail["Subject"] = Header(
            subject,
            "utf-8"
        )

        mail["From"] = formataddr(
            (
                sender_name,
                gmail
            )
        )

        mail["To"] = recipient

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=25
        ) as smtp:

            smtp.login(
                gmail,
                app_password
            )

            refused = smtp.sendmail(
                gmail,
                [recipient],
                mail.as_string()
            )

        if refused:

            return {
                "email": recipient,
                "status": "failed",
                "message": "SMTP rejected recipient."
            }

        return {
            "email": recipient,
            "status": "sent",
            "message": "SMTP accepted."
        }

    except smtplib.SMTPAuthenticationError:

        return {
            "email": recipient,
            "status": "failed",
            "message": "Gmail authentication failed."
        }

    except Exception as error:

        return {
            "email": recipient,
            "status": "failed",
            "message": str(error)
        }


# ================= LIVE SEND =================

@app.route("/api/send-live", methods=["POST"])
@login_required
def send_live():

    data = request.get_json(
        silent=True
    ) or {}

    sender_name = str(
        data.get("sender_name", "")
    ).strip()

    gmail = str(
        data.get("gmail", "")
    ).strip()

    app_password = str(
        data.get("app_password", "")
    ).strip()

    subject = str(
        data.get("subject", "")
    ).strip()

    message = str(
        data.get("message", "")
    )

    recipient_list = get_recipients(
        data.get("recipients", "")
    )

    if not sender_name:
        return jsonify({
            "success": False,
            "error": "Sender name required."
        }), 400

    if not valid_email(gmail):
        return jsonify({
            "success": False,
            "error": "Invalid Gmail address."
        }), 400

    if not app_password:
        return jsonify({
            "success": False,
            "error": "Gmail App Password required."
        }), 400

    if not subject:
        return jsonify({
            "success": False,
            "error": "Subject required."
        }), 400

    if not message.strip():
        return jsonify({
            "success": False,
            "error": "Message required."
        }), 400

    if not recipient_list:
        return jsonify({
            "success": False,
            "error": "Add recipients."
        }), 400

    if len(recipient_list) > MAX_RECIPIENTS:
        return jsonify({
            "success": False,
            "error": "Maximum 25 recipients."
        }), 400

    invalid = [
        email
        for email in recipient_list
        if not valid_email(email)
    ]

    if invalid:
        return jsonify({
            "success": False,
            "error": "Invalid recipient email.",
            "invalid": invalid
        }), 400

    def stream():

        total = len(recipient_list)
        sent = 0
        failed = 0

        yield json.dumps({
            "type": "start",
            "total": total,
            "batch": BATCH_SIZE
        }) + "\n"

        # 5 recipients per batch
        for start in range(
            0,
            total,
            BATCH_SIZE
        ):

            batch = recipient_list[
                start:start + BATCH_SIZE
            ]

            with ThreadPoolExecutor(
                max_workers=BATCH_SIZE
            ) as executor:

                futures = [
                    executor.submit(
                        send_one,
                        sender_name,
                        gmail,
                        app_password,
                        recipient,
                        subject,
                        message
                    )
                    for recipient in batch
                ]

                for future in as_completed(
                    futures
                ):

                    result = future.result()

                    if result["status"] == "sent":
                        sent += 1
                    else:
                        failed += 1

                    completed = sent + failed

                    yield json.dumps({
                        "type": "recipient",
                        "email": result["email"],
                        "status": result["status"],
                        "message": result["message"],
                        "total": total,
                        "sent": sent,
                        "failed": failed,
                        "remaining": total - completed,
                        "percent": round(
                            completed / total * 100,
                            1
                        )
                    }) + "\n"

        yield json.dumps({
            "type": "complete",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": 0
        }) + "\n"

    return Response(
        stream_with_context(stream()),
        content_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )


@app.route("/api/send", methods=["POST"])
@login_required
def send():

    return send_live()


# ================= PROTECTION =================

@app.route("/api/protection")
@login_required
def protection():

    return jsonify({
        "active": True,
        "real_smtp_check": True,
        "duplicate_filter": True,
        "invalid_filter": True,
        "max_recipients": 25,
        "batch_size": 5,
        "fake_cloudflare": False
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        )
    )

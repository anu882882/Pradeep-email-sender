
import os
import re
import time
import ssl
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

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

# Set SESSION_SECRET in Vercel Environment Variables.
app.secret_key = os.environ.get("SESSION_SECRET", "")

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))

MAIL_GAP_SECONDS = max(
    0.0,
    min(float(os.environ.get("MAIL_GAP_SECONDS", "1")), 30.0)
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def logged_in():
    return session.get("logged_in") is True


def open_smtp(sender, password):
    context = ssl.create_default_context()

    if SMTP_PORT == 465:
        server = smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=25,
            context=context,
        )
    else:
        server = smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT,
            timeout=25,
        )
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()

    try:
        server.login(sender, password)
        return server
    except Exception:
        try:
            server.quit()
        except Exception:
            pass
        raise


def error_text(exc):
    message = str(exc).strip()
    if not message:
        message = type(exc).__name__
    return message[:250]


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "login_configured": bool(LOGIN_PASSWORD),
        "session_secret_configured": bool(app.secret_key),
        "smtp_host": SMTP_HOST,
        "smtp_port": SMTP_PORT,
        "mail_gap_seconds": MAIL_GAP_SECONDS,
    })


@app.route("/login", methods=["GET", "POST"])
def login():
    if not app.secret_key:
        return render_template(
            "login.html",
            error="SESSION_SECRET is not configured in Vercel."
        ), 500

    if request.method == "POST":
        if not LOGIN_PASSWORD:
            return render_template(
                "login.html",
                error="LOGIN_PASSWORD is not configured in Vercel."
            ), 500

        password = request.form.get("password", "")

        if password == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("index"))

        return render_template(
            "login.html",
            error="Incorrect password. Please try again."
        ), 401

    if logged_in():
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    if not logged_in():
        return redirect(url_for("login"))

    return render_template("index.html")


@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not logged_in():
        return jsonify({
            "success": False,
            "error": "Session expired. Please sign in again."
        }), 401

    data = request.get_json(silent=True) or {}

    if data.get("consentConfirmed") is not True:
        return jsonify({
            "success": False,
            "error": "Confirm that recipients agreed to receive these emails."
        }), 400

    sender = str(data.get("sender", "")).strip()
    password = str(data.get("appPassword", "")).strip()
    sender_name = str(data.get("senderName", "")).strip()
    subject = str(data.get("subject", "")).strip()
    body = data.get("body", "")
    body_mode = data.get("bodyMode", "text")
    recipients = data.get("recipients", [])

    if not app.secret_key:
        return jsonify({
            "success": False,
            "error": "SESSION_SECRET is not configured."
        }), 500

    if (
        not EMAIL_RE.fullmatch(sender)
        or not sender.lower().endswith("@gmail.com")
    ):
        return jsonify({
            "success": False,
            "error": "Enter a valid Gmail sender address."
        }), 400

    if not password:
        return jsonify({
            "success": False,
            "error": "Enter your Gmail App Password."
        }), 400

    if not subject:
        return jsonify({
            "success": False,
            "error": "Enter an email subject."
        }), 400

    if not isinstance(body, str) or not body.strip():
        return jsonify({
            "success": False,
            "error": "Enter the message body."
        }), 400

    if body_mode not in ("text", "html"):
        body_mode = "text"

    if (
        not isinstance(recipients, list)
        or not recipients
        or len(recipients) > 5
    ):
        return jsonify({
            "success": False,
            "error": "Each batch must contain between 1 and 5 recipients."
        }), 400

    valid_recipients = []
    seen = set()

    for item in recipients:
        if not isinstance(item, str):
            continue

        address = item.strip()

        if (
            EMAIL_RE.fullmatch(address)
            and address.lower() not in seen
        ):
            valid_recipients.append(address)
            seen.add(address.lower())

    if not valid_recipients:
        return jsonify({
            "success": False,
            "error": "No valid recipient addresses were provided."
        }), 400

    results = []
    sent = 0
    failed = 0
    server = None
    connection_lost = False

    try:
        server = open_smtp(sender, password)

    except (smtplib.SMTPException, OSError, ValueError) as exc:
        return jsonify({
            "success": False,
            "error": "SMTP connection/login failed: " + error_text(exc),
            "sent": 0,
            "failed": len(valid_recipients),
            "total": len(valid_recipients),
            "results": [
                {
                    "recipient": recipient,
                    "status": "failed",
                    "message": "SMTP connection/login failed: "
                               + error_text(exc)
                }
                for recipient in valid_recipients
            ]
        }), 502

    try:
        for index, recipient in enumerate(valid_recipients):
            message = EmailMessage()
            message["From"] = (
                formataddr((sender_name, sender))
                if sender_name else sender
            )
            message["To"] = recipient
            message["Subject"] = subject

            if body_mode == "html":
                message.set_content(
                    "This message contains HTML content. "
                    "Please use an HTML-compatible email client."
                )
                message.add_alternative(body, subtype="html")
            else:
                message.set_content(body)

            try:
                refused = server.send_message(message)

                if refused:
                    failed += 1
                    results.append({
                        "recipient": recipient,
                        "status": "failed",
                        "message": "SMTP server refused this recipient."
                    })
                else:
                    sent += 1
                    results.append({
                        "recipient": recipient,
                        "status": "sent",
                        "message": "SMTP server accepted the message."
                    })

            except (
                smtplib.SMTPServerDisconnected,
                ConnectionError,
                TimeoutError,
                OSError,
            ) as exc:
                failed += 1
                results.append({
                    "recipient": recipient,
                    "status": "failed",
                    "message": "SMTP connection lost: " + error_text(exc)
                })
                connection_lost = True
                break

            except (smtplib.SMTPException, ValueError) as exc:
                failed += 1
                results.append({
                    "recipient": recipient,
                    "status": "failed",
                    "message": error_text(exc)
                })

            if (
                not connection_lost
                and index < len(valid_recipients) - 1
                and MAIL_GAP_SECONDS > 0
            ):
                time.sleep(MAIL_GAP_SECONDS)

    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass

    processed = {item["recipient"].lower() for item in results}

    if connection_lost:
        for recipient in valid_recipients:
            if recipient.lower() not in processed:
                failed += 1
                results.append({
                    "recipient": recipient,
                    "status": "failed",
                    "message": (
                        "Not attempted because the SMTP connection was lost."
                    )
                })

    return jsonify({
        "success": failed == 0 and sent == len(valid_recipients),
        "sent": sent,
        "failed": failed,
        "total": len(valid_recipients),
        "results": results,
        "mail_gap_seconds": MAIL_GAP_SECONDS,
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )

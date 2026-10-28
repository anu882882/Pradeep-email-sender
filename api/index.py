
import os
import re
import ssl
import time
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
    static_folder=os.path.join(BASE_DIR, "static")
)

app.secret_key = os.environ.get("SESSION_SECRET", "")
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
MAIL_GAP_SECONDS = max(
    1.0, min(float(os.environ.get("MAIL_GAP_SECONDS", "1")), 30.0)
)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def logged_in():
    return session.get("logged_in") is True

def smtp_send(to_email, subject, body, html_mode=False):
    message = EmailMessage()
    message["From"] = formataddr(("Mail Console", SMTP_USER))
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)

    if html_mode:
        message.add_alternative(body, subtype="html")

    context = ssl.create_default_context()
    last_error = "Unknown SMTP error"

    for attempt in range(3):
        try:
            if SMTP_PORT == 465:
                with smtplib.SMTP_SSL(
                    SMTP_HOST, SMTP_PORT, timeout=20, context=context
                ) as server:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                    refused = server.send_message(message)
            else:
                with smtplib.SMTP(
                    SMTP_HOST, SMTP_PORT, timeout=20
                ) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(SMTP_USER, SMTP_PASSWORD)
                    refused = server.send_message(message)

            if refused:
                return False, "Recipient rejected by SMTP server"

            return True, "SMTP accepted the message"

        except smtplib.SMTPRecipientsRefused:
            return False, "Recipient address rejected by SMTP server"
        except smtplib.SMTPAuthenticationError:
            return False, "SMTP login failed; check SMTP_USER and SMTP_PASSWORD"
        except smtplib.SMTPDataError as exc:
            return False, f"SMTP rejected message: {exc.smtp_code}"
        except (smtplib.SMTPServerDisconnected, TimeoutError, OSError,
                smtplib.SMTPConnectError, smtplib.SMTPHeloError) as exc:
            last_error = str(exc)
            if attempt < 2:
                time.sleep(attempt + 1)
        except smtplib.SMTPException as exc:
            return False, f"SMTP error: {str(exc)[:180]}"

    return False, f"Temporary connection failure: {last_error[:180]}"

@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "smtp_configured": bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD),
        "login_configured": bool(LOGIN_PASSWORD)
    })

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        if not LOGIN_PASSWORD:
            error = "LOGIN_PASSWORD is not configured."
        elif request.form.get("password", "") == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("index"))
        else:
            error = "Incorrect password."

    return render_template("login.html", error=error)

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.get("/")
def index():
    if not logged_in():
        return redirect(url_for("login"))
    return render_template("index.html", smtp_user=SMTP_USER)

@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify({"error": "Please sign in again."}), 401

    if not SMTP_USER or not SMTP_PASSWORD:
        return jsonify({"error": "SMTP_USER or SMTP_PASSWORD is missing."}), 500

    data = request.get_json(silent=True) or {}
    recipients = data.get("recipients", [])
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True
    consent = data.get("consentConfirmed") is True

    if not consent:
        return jsonify({"error": "Confirm you have permission to email these recipients."}), 400

    if not isinstance(recipients, list) or not recipients:
        return jsonify({"error": "Add at least one recipient."}), 400

    # Limit each request; send only to recipients you are authorized to contact.
    recipients = list(dict.fromkeys(
        str(email).strip() for email in recipients
        if isinstance(email, str) and EMAIL_RE.fullmatch(email.strip())
    ))

    if not recipients:
        return jsonify({"error": "No valid recipient addresses found."}), 400

    if len(recipients) > 25:
        return jsonify({"error": "Maximum 25 recipients per batch."}), 400

    if not subject or not body:
        return jsonify({"error": "Subject and message are required."}), 400

    results = []

    for index, recipient in enumerate(recipients):
        ok, detail = smtp_send(recipient, subject, body, html_mode)
        results.append({
            "email": recipient,
            "status": "sent" if ok else "failed",
            "detail": detail
        })

        if index < len(recipients) - 1:
            time.sleep(MAIL_GAP_SECONDS)

    sent = sum(1 for item in results if item["status"] == "sent")
    failed = len(results) - sent

    return jsonify({
        "total": len(results),
        "sent": sent,
        "failed": failed,
        "results": results
    })

# Vercel imports this WSGI app.

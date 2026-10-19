import os
import re
import json
import ssl
import smtplib
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, Response
)
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "")

BATCH_SIZE = 5
MAX_RECIPIENTS = 25
SMTP_TIMEOUT = 20

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(email):
    return EMAIL_PATTERN.fullmatch(email) is not None


def parse_recipients(raw):
    items = re.split(r"[,;\s]+", raw or "")
    seen = set()
    result = []

    for item in items:
        email = item.strip().lower()
        if email and email not in seen and is_valid_email(email):
            seen.add(email)
            result.append(email)

    return result


def verify_turnstile(token, remote_ip=None):
    secret = os.environ.get("TURNSTILE_SECRET_KEY", "")
    if not secret or not token:
        return False

    data = {
        "secret": secret,
        "response": token,
    }
    if remote_ip:
        data["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            result = json.loads(response.read().decode())
        return result.get("success") is True
    except Exception:
        return False


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


@app.get("/")
@login_required
def index():
    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get("TURNSTILE_SITE_KEY", "")
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    site_key = os.environ.get("TURNSTILE_SITE_KEY", "")

    if request.method == "POST":
        password = request.form.get("password", "")
        token = request.form.get("cf-turnstile-response", "")

        expected = os.environ.get("LOGIN_PASSWORD", "")
        if not expected or not app.secret_key:
            error = "Login environment variables are not configured."
        elif password != expected:
            error = "Incorrect password."
        elif not verify_turnstile(token, request.remote_addr):
            error = "Please complete Cloudflare verification."
        else:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("index"))

    return render_template(
        "login.html",
        error=error,
        turnstile_site_key=site_key
    )


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def send_one_email(recipient, sender_name, gmail, app_password,
                   subject, body, html_mode):
    message = EmailMessage()
    message["From"] = f"{sender_name} <{gmail}>"
    message["To"] = recipient
    message["Subject"] = subject

    if html_mode:
        message.set_content("This email contains an HTML message.")
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(
        "smtp.gmail.com", 465, context=context,
        timeout=SMTP_TIMEOUT
    ) as server:
        server.login(gmail, app_password)
        server.send_message(message)

    return True


@app.post("/send-batch")
@login_required
def send_batch():
    data = request.get_json(silent=True) or {}

    token = data.get("turnstile_token", "")
    if not verify_turnstile(token, request.remote_addr):
        return jsonify({
            "error": "Cloudflare verification failed. Please verify again."
        }), 403

    sender_name = (data.get("sender_name") or "").strip()
    gmail = (data.get("gmail") or "").strip()
    app_password = (data.get("app_password") or "").strip()
    subject = (data.get("subject") or "").strip()
    body = data.get("body") or ""
    html_mode = data.get("html_mode") is True
    recipients = parse_recipients(data.get("recipients") or "")

    if not sender_name or not gmail or not is_valid_email(gmail):
        return jsonify({"error": "Enter a valid sender name and Gmail."}), 400
    if not app_password:
        return jsonify({"error": "Enter your Gmail App Password."}), 400
    if not subject or not body.strip():
        return jsonify({"error": "Subject and message body are required."}), 400
    if not recipients:
        return jsonify({"error": "Enter valid recipient email addresses."}), 400
    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "error": f"Maximum {MAX_RECIPIENTS} recipients per request."
        }), 400

    # Each batch submits no more than five messages concurrently.
    results = []
    for start in range(0, len(recipients), BATCH_SIZE):
        batch = recipients[start:start + BATCH_SIZE]

        with ThreadPoolExecutor(max_workers=BATCH_SIZE) as executor:
            futures = {
                executor.submit(
                    send_one_email,
                    recipient, sender_name, gmail, app_password,
                    subject, body, html_mode
                ): recipient
                for recipient in batch
            }

            for future in as_completed(futures):
                recipient = futures[future]
                try:
                    future.result()
                    results.append({
                        "recipient": recipient,
                        "status": "sent"
                    })
                except Exception:
                    # Avoid returning SMTP credentials or internal errors.
                    results.append({
                        "recipient": recipient,
                        "status": "failed"
                    })

    sent = sum(item["status"] == "sent" for item in results)
    failed = len(results) - sent

    return jsonify({
        "total": len(recipients),
        "sent": sent,
        "failed": failed,
        "remaining": 0,
        "results": results,
    })


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


# Vercel's Python runtime imports this WSGI app.

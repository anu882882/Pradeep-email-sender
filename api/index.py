import os
import re
import json
import ssl
import smtplib
import secrets
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from email.utils import formataddr

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, Response, jsonify
)

app = Flask(__name__, template_folder="../templates", static_folder="../static")

app.secret_key = os.environ.get("SESSION_SECRET", "")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def verify_turnstile(token):
    """Verify a fresh Turnstile token on the server."""
    if not token or not TURNSTILE_SECRET_KEY:
        return False

    data = urllib.parse.urlencode({
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
        "remoteip": request.headers.get("X-Forwarded-For", "").split(",")[0].strip(),
    }).encode()

    try:
        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as response:
            result = json.loads(response.read().decode("utf-8"))
        return result.get("success") is True
    except Exception:
        app.logger.warning("Turnstile verification failed.")
        return False


def parse_recipients(raw):
    items = re.split(r"[,;\s]+", raw or "")
    unique = []
    seen = set()

    for item in items:
        email = item.strip().lower()
        if email and email not in seen:
            seen.add(email)
            unique.append(email)

    return unique


def send_one_email(sender_email, app_password, sender_name,
                   recipient, subject, body, is_html):
    """Send one message using the sender's Gmail App Password."""
    msg = EmailMessage()
    msg["From"] = formataddr((sender_name or sender_email, sender_email))
    msg["To"] = recipient
    msg["Subject"] = subject

    if is_html:
        msg.set_content("This email contains HTML content. Please view it in an HTML-compatible email client.")
        msg.add_alternative(body, subtype="html")
    else:
        msg.set_content(body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=25) as smtp:
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)

    return recipient


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def home():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if not LOGIN_PASSWORD or not app.secret_key:
        return (
            "Server configuration is incomplete. Set LOGIN_PASSWORD "
            "and SESSION_SECRET in your deployment environment.",
            503,
        )

    if request.method == "POST":
        password = request.form.get("password", "")
        token = request.form.get("cf-turnstile-response", "")

        if not secrets.compare_digest(password, LOGIN_PASSWORD):
            error = "Incorrect password. Please try again."
        elif not verify_turnstile(token):
            error = "Verification failed. Please try again."
        else:
            session.clear()
            session["authenticated"] = True
            session.permanent = False
            return redirect(url_for("home"))

    return render_template(
        "login.html",
        error=error,
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.post("/send-batch")
def send_batch():
    if not session.get("authenticated"):
        return jsonify({"error": "Your session has expired. Please sign in again."}), 401

    payload = request.get_json(silent=True) or {}

    sender_email = str(payload.get("sender_email", "")).strip()
    app_password = str(payload.get("app_password", "")).replace(" ", "")
    sender_name = str(payload.get("sender_name", "")).strip()[:120]
    subject = str(payload.get("subject", "")).strip()[:250]
    body = str(payload.get("body", ""))
    is_html = payload.get("is_html") is True
    token = str(payload.get("turnstile_token", ""))

    recipients = parse_recipients(payload.get("recipients", ""))

    if not verify_turnstile(token):
        return jsonify({"error": "Cloudflare verification failed. Please verify again."}), 400

    if not EMAIL_PATTERN.fullmatch(sender_email):
        return jsonify({"error": "Enter a valid Gmail address."}), 400

    if not app_password:
        return jsonify({"error": "Enter your Gmail App Password."}), 400

    if not recipients:
        return jsonify({"error": "Add at least one recipient email address."}), 400

    if len(recipients) > 25:
        return jsonify({"error": "Maximum 25 recipients per request."}), 400

    invalid = [email for email in recipients if not EMAIL_PATTERN.fullmatch(email)]
    if invalid:
        return jsonify({"error": "Invalid recipient address(es): " + ", ".join(invalid[:5])}), 400

    if not subject or not body.strip():
        return jsonify({"error": "Subject and message body are required."}), 400

    def generate():
        total = len(recipients)
        yield json.dumps({"type": "start", "total": total}) + "\n"

        results = {}
        # Send in groups of five; each worker sends one email.
        for start in range(0, total, 5):
            group = recipients[start:start + 5]

            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {
                    executor.submit(
                        send_one_email,
                        sender_email,
                        app_password,
                        sender_name,
                        recipient,
                        subject,
                        body,
                        is_html,
                    ): recipient
                    for recipient in group
                }

                for future in as_completed(futures):
                    recipient = futures[future]
                    try:
                        future.result()
                        results[recipient] = {
                            "status": "sent",
                            "message": "Sent successfully",
                        }
                    except Exception as exc:
                        app.logger.warning(
                            "Email delivery failed for %s: %s",
                            recipient, type(exc).__name__
                        )
                        results[recipient] = {
                            "status": "failed",
                            "message": "Sending failed. Check Gmail settings and recipient address.",
                        }

            # Report results in the original recipient order.
            for recipient in group:
                result = results[recipient]
                yield json.dumps({
                    "type": "result",
                    "recipient": recipient,
                    **result,
                }) + "\n"

        yield json.dumps({"type": "done"}) + "\n"

    return Response(
        generate(),
        mimetype="application/x-ndjson",
        headers={"X-Accel-Buffering": "no"},
    )


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Request is too large."}), 413

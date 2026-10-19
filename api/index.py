import os
import re
import json
import ssl
import smtplib
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, Response, stream_with_context
)

app = Flask(__name__, template_folder="../templates", static_folder="../static")
app.secret_key = os.environ.get("SESSION_SECRET", "change-this-to-a-long-random-secret")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_RECIPIENTS = 25
BATCH_SIZE = 5


def verify_turnstile(token, remote_ip=None):
    """Verify Turnstile with Cloudflare; never trust the browser token alone."""
    secret = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
    if not secret or not token:
        return False

    payload = {
        "secret": secret,
        "response": token,
    }
    if remote_ip:
        payload["remoteip"] = remote_ip

    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))
        return result.get("success") is True
    except Exception:
        app.logger.warning("Turnstile verification failed or timed out.")
        return False


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith("/send-batch"):
                return jsonify({"error": "Please sign in again."}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def parse_recipients(raw):
    recipients = []
    seen = set()
    for item in re.split(r"[,;\s]+", raw or ""):
        email = item.strip().lower()
        if email and email not in seen:
            seen.add(email)
            recipients.append(email)
    return recipients


def send_one_email(sender_email, app_password, sender_name, recipient, subject, body, html_mode):
    msg = EmailMessage()
    msg["From"] = f"{sender_name} <{sender_email}>" if sender_name else sender_email
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)

    if html_mode:
        msg.add_alternative(body, subtype="html")

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=20) as smtp:
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)

    return recipient


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/", methods=["GET"])
@login_required
def home():
    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get("TURNSTILE_SITE_KEY", ""),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("home"))

    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        token = request.form.get("cf-turnstile-response", "")
        expected = os.environ.get("LOGIN_PASSWORD", "")

        if not expected:
            error = "Set LOGIN_PASSWORD in your deployment environment."
        elif not verify_turnstile(token, request.remote_addr):
            error = "Verification failed. Please try again."
        elif password != expected:
            error = "Incorrect password."
        else:
            session.clear()
            session["authenticated"] = True
            return redirect(url_for("home"))

    return render_template(
        "login.html",
        error=error,
        turnstile_site_key=os.environ.get("TURNSTILE_SITE_KEY", ""),
    )


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/send-batch", methods=["POST"])
@login_required
def send_batch():
    data = request.get_json(silent=True) or {}

    token = str(data.get("turnstile_token", "")).strip()
    if not verify_turnstile(token, request.remote_addr):
        return jsonify({
            "error": "Cloudflare verification failed or expired. Please wait for verification and try again."
        }), 400

    sender_email = str(data.get("sender_email", "")).strip()
    app_password = str(data.get("app_password", "")).strip()
    sender_name = str(data.get("sender_name", "")).strip()
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))
    html_mode = data.get("mode") == "html"
    recipients = parse_recipients(str(data.get("recipients", "")))

    if not EMAIL_RE.fullmatch(sender_email):
        return jsonify({"error": "Enter a valid sender email address."}), 400
    if not app_password:
        return jsonify({"error": "Enter your Gmail app password."}), 400
    if not subject or not body.strip():
        return jsonify({"error": "Subject and message body are required."}), 400
    if not recipients:
        return jsonify({"error": "Add at least one recipient."}), 400
    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({"error": f"Maximum {MAX_RECIPIENTS} recipients per request."}), 400

    invalid = [email for email in recipients if not EMAIL_RE.fullmatch(email)]
    if invalid:
        return jsonify({"error": "Invalid recipient address: " + ", ".join(invalid[:5])}), 400

    def generate():
        total = len(recipients)
        yield json.dumps({"type": "start", "total": total}) + "\n"

        sent = 0
        failed = 0

        # Send no more than five messages concurrently.
        for start in range(0, total, BATCH_SIZE):
            batch = recipients[start:start + BATCH_SIZE]
            with ThreadPoolExecutor(max_workers=BATCH_SIZE) as executor:
                future_map = {
                    executor.submit(
                        send_one_email,
                        sender_email, app_password, sender_name,
                        recipient, subject, body, html_mode
                    ): recipient
                    for recipient in batch
                }

                for future in as_completed(future_map):
                    recipient = future_map[future]
                    try:
                        future.result()
                        sent += 1
                        result = {"type": "result", "ok": True}
                    except Exception:
                        failed += 1
                        app.logger.exception("Email send failed.")
                        result = {"type": "result", "ok": False}

                    result.update({
                        "sent": sent,
                        "failed": failed,
                        "remaining": total - sent - failed,
                    })
                    yield json.dumps(result) + "\n"

        yield json.dumps({
            "type": "done",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": total - sent - failed,
        }) + "\n"

    return Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
        headers={"X-Accel-Buffering": "no"},
    )


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=False)

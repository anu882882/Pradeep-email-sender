from flask import (
    Flask, render_template, request, jsonify, redirect,
    url_for, session, Response, stream_with_context
)
import smtplib
import ssl
import re
import os
import json
import urllib.request
import urllib.parse
import secrets
import time
from collections import defaultdict, deque
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
    PERMANENT_SESSION_LIFETIME=8 * 60 * 60,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024
)

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Referrer-Policy", "strict-origin-when-cross-origin"
    )
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()"
    )
    return response

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 2

TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()

_RATE_EVENTS = defaultdict(deque)
_RATE_WINDOW_SECONDS = 60
_LOGIN_MAX_ATTEMPTS = 8
_SEND_MAX_REQUESTS = 6


def rate_limited(key, limit):
    now = time.time()
    events = _RATE_EVENTS[key]
    while events and now - events[0] > _RATE_WINDOW_SECONDS:
        events.popleft()
    if len(events) >= limit:
        return True
    events.append(now)
    return False


EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    return bool(EMAIL_RE.fullmatch(str(value).strip()))


def authenticated():
    return session.get("authenticated") is True


def clean_header(value):
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()


def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return False, "TURNSTILE_SECRET_KEY is not configured."
    if not token:
        return False, "Cloudflare verification is required."

    payload = {"secret": TURNSTILE_SECRET_KEY, "response": token}
    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
        if result.get("success") is True:
            return True, None
        return False, "Cloudflare verification failed."
    except Exception:
        return False, "Unable to verify Cloudflare."


@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))

    error = None
    if request.method == "POST":
        remote_ip = request.headers.get(
            "X-Forwarded-For", request.remote_addr or "unknown"
        ).split(",")[0].strip()

        if rate_limited("login:" + remote_ip, _LOGIN_MAX_ATTEMPTS):
            error = "Too many login attempts. Please wait one minute and try again."
        else:
            password = str(request.form.get("password", ""))
            token = str(request.form.get("cf-turnstile-response", "")).strip()
            configured_password = os.environ.get("LOGIN_PASSWORD", "").strip()

            if not configured_password:
                error = "LOGIN_PASSWORD is not configured in Vercel Environment Variables."
            elif not TURNSTILE_SITE_KEY or not TURNSTILE_SECRET_KEY:
                error = "Cloudflare Turnstile keys are not configured in Vercel."
            else:
                verified, verify_error = verify_turnstile(token, remote_ip)
                if not verified:
                    error = verify_error or "Cloudflare verification failed."
                elif secrets.compare_digest(password, configured_password):
                    session.clear()
                    session["authenticated"] = True
                    session.permanent = True
                    return redirect(url_for("home"))
                else:
                    error = "Incorrect password."

    return render_template(
        "login.html",
        error=error,
        turnstile_site_key=TURNSTILE_SITE_KEY
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    if not authenticated():
        return redirect(url_for("login"))
    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY
    )


def send_one_email(
    gmail, app_password, sender_name, subject, body, is_html, recipient
):
    context = ssl.create_default_context()
    content_type = "html" if is_html else "plain"
    message = MIMEText(body, content_type, "utf-8")
    message["Subject"] = subject
    message["From"] = formataddr((sender_name, gmail))
    message["To"] = recipient
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()
    message["MIME-Version"] = "1.0"

    with smtplib.SMTP_SSL(
        "smtp.gmail.com", 465, context=context, timeout=15
    ) as server:
        server.login(gmail, app_password)
        server.sendmail(gmail, [recipient], message.as_string())

    return {"email": recipient, "result": "sent"}


@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not authenticated():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    session_key = str(session.get("_rate_key") or "")
    if not session_key:
        session_key = secrets.token_urlsafe(18)
        session["_rate_key"] = session_key

    if rate_limited("send:" + session_key, _SEND_MAX_REQUESTS):
        return jsonify({
            "success": False,
            "message": "Send rate limit reached. Wait one minute before trying again."
        }), 429

    data = request.get_json(silent=True) or {}

    sender_name = clean_header(data.get("sender_name", ""))
    gmail = clean_header(data.get("gmail", ""))
    app_password = str(data.get("app_password", "")).strip()
    subject = clean_header(data.get("subject", ""))
    body = str(data.get("body", ""))
    is_html = bool(data.get("is_html", False))
    recipients = data.get("recipients", [])
    turnstile_token = str(data.get("turnstile_token", "")).strip()

    if not sender_name:
        return jsonify({"success": False, "message": "Sender Name is required."}), 400
    if not valid_email(gmail):
        return jsonify({"success": False, "message": "Enter a valid Gmail address."}), 400
    if not app_password:
        return jsonify({"success": False, "message": "Google App Password is required."}), 400
    if not subject:
        return jsonify({"success": False, "message": "Email subject is required."}), 400
    if not body.strip():
        return jsonify({"success": False, "message": "Message body is required."}), 400
    if not isinstance(recipients, list):
        return jsonify({"success": False, "message": "Invalid recipient list."}), 400

    clean_recipients = []
    for item in recipients:
        email = str(item).strip().lower()
        if valid_email(email) and email not in clean_recipients:
            clean_recipients.append(email)

    clean_recipients = clean_recipients[:MAX_RECIPIENTS]
    if not clean_recipients:
        return jsonify({"success": False, "message": "No valid recipients found."}), 400

    verified, verify_error = verify_turnstile(
        turnstile_token,
        request.headers.get("X-Forwarded-For", request.remote_addr)
    )
    if not verified:
        return jsonify({"success": False, "message": verify_error}), 403

    @stream_with_context
    def generate():
        total = len(clean_recipients)
        sent_count = 0
        failed_count = 0

        yield json.dumps({
            "type": "start", "total": total, "sent": 0,
            "failed": 0, "remaining": total
        }) + "\n"

        executor = ThreadPoolExecutor(max_workers=MAX_PARALLEL_SENDS)
        try:
            future_map = {
                executor.submit(
                    send_one_email,
                    gmail, app_password, sender_name, subject,
                    body, is_html, recipient
                ): recipient
                for recipient in clean_recipients
            }

            for future in as_completed(future_map):
                recipient = future_map[future]
                try:
                    result = future.result()
                    if result.get("result") == "sent":
                        sent_count += 1
                        yield json.dumps({
                            "type": "progress", "email": recipient,
                            "result": "sent", "total": total,
                            "sent": sent_count, "failed": failed_count,
                            "remaining": total - sent_count - failed_count
                        }) + "\n"
                except smtplib.SMTPAuthenticationError:
                    failed_count += 1
                    yield json.dumps({
                        "type": "progress", "email": recipient,
                        "result": "failed",
                        "error": "Gmail authentication failed. Check Gmail and App Password.",
                        "total": total, "sent": sent_count,
                        "failed": failed_count,
                        "remaining": total - sent_count - failed_count
                    }) + "\n"
                except smtplib.SMTPException as exc:
                    failed_count += 1
                    yield json.dumps({
                        "type": "progress", "email": recipient,
                        "result": "failed", "error": f"SMTP error: {str(exc)}",
                        "total": total, "sent": sent_count,
                        "failed": failed_count,
                        "remaining": total - sent_count - failed_count
                    }) + "\n"
                except Exception as exc:
                    failed_count += 1
                    yield json.dumps({
                        "type": "progress", "email": recipient,
                        "result": "failed", "error": str(exc),
                        "total": total, "sent": sent_count,
                        "failed": failed_count,
                        "remaining": total - sent_count - failed_count
                    }) + "\n"
        finally:
            executor.shutdown(wait=True)

        yield json.dumps({
            "type": "complete", "success": True,
            "message": "YATENDRA ❤️", "total": total,
            "sent": sent_count, "failed": failed_count,
            "remaining": total - sent_count - failed_count
        }) + "\n"

    return Response(
        generate(),
        content_type="application/x-ndjson; charset=utf-8",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"}
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

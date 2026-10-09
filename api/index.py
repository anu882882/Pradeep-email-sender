
from flask import (
    Flask, Response, jsonify, redirect, render_template,
    request, session, url_for, stream_with_context
)
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path
import json
import os
import random
import re
import secrets
import smtplib
import ssl
import time
import urllib.parse
import urllib.request

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static"
)
handler = app

app.secret_key = os.environ.get("SESSION_SECRET", "")
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 20
MAX_RECIPIENTS = 25

try:
    MAIL_GAP_SECONDS = max(0.0, float(os.environ.get("MAIL_GAP_SECONDS", "0")))
except (TypeError, ValueError):
    MAIL_GAP_SECONDS = 0.0

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)
SPINTAX_RE = re.compile(r"\{([^{}]+)\}")


def authenticated():
    return session.get("authenticated") is True


def valid_email(value):
    return bool(EMAIL_RE.fullmatch(str(value or "").strip()))


def safe_header(value):
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()


def ndjson(data):
    return json.dumps(data, ensure_ascii=False) + "\n"


def render_spintax(text):
    text = str(text or "")

    for _ in range(10):
        changed = False

        def replace(match):
            nonlocal changed
            options = [
                option.strip()
                for option in match.group(1).split("|")
                if option.strip()
            ]
            if len(options) < 2:
                return match.group(0)
            changed = True
            return random.choice(options)

        text = SPINTAX_RE.sub(replace, text)

        if not changed:
            break

    return text


def build_recipient_queue(raw):
    if not isinstance(raw, list):
        return []

    recipients = []
    seen = set()

    for item in raw:
        email = str(item or "").strip().lower()

        if not valid_email(email) or email in seen:
            continue

        seen.add(email)
        recipients.append(email)

        if len(recipients) >= MAX_RECIPIENTS:
            break

    return recipients


def progress_event(event, total, sent, failed, **extra):
    completed = sent + failed
    result = {
        "type": event,
        "total": total,
        "sent": sent,
        "failed": failed,
        "completed": completed,
        "remaining": max(0, total - completed)
    }
    result.update(extra)
    return ndjson(result)


def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return False, "Cloudflare Turnstile secret is not configured."

    if not token:
        return False, "Please complete Cloudflare verification."

    values = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token
    }

    if remote_ip:
        values["remoteip"] = remote_ip

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=urllib.parse.urlencode(values).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))

        if result.get("success"):
            return True, None

        return False, "Cloudflare verification failed. Please try again."

    except Exception:
        return False, "Unable to verify Cloudflare right now."


def create_message(sender_name, gmail, recipient, subject, body, html_mode):
    message = MIMEText(
        render_spintax(body),
        "html" if html_mode else "plain",
        "utf-8"
    )

    message["Subject"] = render_spintax(subject)
    message["From"] = formataddr((sender_name, gmail))
    message["To"] = recipient
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    return message


def create_smtp(gmail, app_password):
    smtp = smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=ssl.create_default_context(),
        timeout=SMTP_TIMEOUT
    )

    try:
        smtp.ehlo()
        smtp.login(gmail, app_password)
        return smtp
    except Exception:
        try:
            smtp.quit()
        except Exception:
            pass
        raise


@app.before_request
def protect_dashboard():
    # Only public routes are login and static assets.
    if request.endpoint in ("login", "static"):
        return None

    if not authenticated():
        if request.endpoint == "send_batch":
            return jsonify({
                "success": False,
                "message": "Please sign in first."
            }), 401

        return redirect(url_for("login"))

    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":
        password = request.form.get("password", "")

        if not LOGIN_PASSWORD or not app.secret_key:
            error = "Login is not configured. Set LOGIN_PASSWORD and SESSION_SECRET."
        elif secrets.compare_digest(password, LOGIN_PASSWORD):
            session.clear()
            session["authenticated"] = True
            return redirect(url_for("home"))
        else:
            error = "Incorrect password. Please try again."

    return render_template("login.html", error=error)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get("TURNSTILE_SITE_KEY", "")
    )


@app.route("/send-batch", methods=["POST"])
def send_batch():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Invalid request."
        }), 400

    sender_name = safe_header(data.get("sender_name", ""))
    gmail = safe_header(data.get("gmail", "")).lower()
    app_password = str(data.get("app_password", "")).strip()
    subject = safe_header(data.get("subject", ""))
    body = str(data.get("body", ""))
    html_mode = data.get("is_html") is True
    recipients = build_recipient_queue(data.get("recipients", []))
    token = str(data.get("turnstile_token", "")).strip()

    checks = [
        (bool(sender_name), "Sender Name is required."),
        (valid_email(gmail), "Enter a valid email address."),
        (bool(app_password), "Google App Password is required."),
        (bool(subject), "Email subject is required."),
        (bool(body.strip()), "Message body is required."),
        (bool(recipients), "Enter at least one valid recipient.")
    ]

    for passed, message in checks:
        if not passed:
            return jsonify({"success": False, "message": message}), 400

    forwarded = request.headers.get("X-Forwarded-For", "")
    remote_ip = forwarded.split(",")[0].strip() if forwarded else request.remote_addr

    passed, error = verify_turnstile(token, remote_ip)
    if not passed:
        return jsonify({"success": False, "message": error}), 403

    @stream_with_context
    def generate():
        total = len(recipients)
        sent = 0
        failed = 0
        smtp = None

        yield progress_event("start", total, sent, failed)

        try:
            smtp = create_smtp(gmail, app_password)
            yield progress_event("connected", total, sent, failed)

            for index, recipient in enumerate(recipients):
                try:
                    message = create_message(
                        sender_name,
                        gmail,
                        recipient,
                        subject,
                        body,
                        html_mode
                    )

                    smtp.sendmail(
                        gmail,
                        [recipient],
                        message.as_string()
                    )

                    sent += 1
                    yield progress_event(
                        "progress", total, sent, failed,
                        email=recipient, result="sent"
                    )

                except Exception as exc:
                    failed += 1
                    yield progress_event(
                        "progress", total, sent, failed,
                        email=recipient,
                        result="failed",
                        error=str(exc)
                    )

                if MAIL_GAP_SECONDS > 0 and index < total - 1:
                    time.sleep(MAIL_GAP_SECONDS)

        except smtplib.SMTPAuthenticationError:
            yield progress_event(
                "error", total, sent, failed,
                message="Gmail login failed. Check your Gmail and App Password."
            )
            return

        except Exception as exc:
            yield progress_event(
                "error", total, sent, failed,
                message=f"SMTP connection failed: {exc}"
            )
            return

        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    pass

        yield progress_event(
            "complete", total, sent, failed,
            success=True,
            message="PRADEEP ❤️"
        )

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
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

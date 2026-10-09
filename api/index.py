from flask import Flask, Response, jsonify, redirect, render_template, request, session, stream_with_context, url_for
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
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"),
            static_folder=str(BASE_DIR / "static"), static_url_path="/static")
handler = app

app.secret_key = os.getenv("SESSION_SECRET", "")
LOGIN_PASSWORD = os.getenv("LOGIN_PASSWORD", "")
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "")
SMTP_HOST, SMTP_PORT, SMTP_TIMEOUT = "smtp.gmail.com", 465, 20
MAX_RECIPIENTS = 25
try:
    MAIL_GAP_SECONDS = max(0.0, float(os.getenv("MAIL_GAP_SECONDS", "0")))
except (TypeError, ValueError):
    MAIL_GAP_SECONDS = 0.0

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
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
            options = [item.strip() for item in match.group(1).split("|") if item.strip()]
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
    result, seen = [], set()
    for item in raw:
        email = str(item or "").strip().lower()
        if not valid_email(email) or email in seen:
            continue
        seen.add(email)
        result.append(email)
        if len(result) >= MAX_RECIPIENTS:
            break
    return result

def make_progress(event, total, sent, failed, elapsed=0.0, **extra):
    completed = sent + failed
    remaining = max(0, total - completed)
    speed = completed / elapsed if elapsed > 0 else 0.0
    eta = remaining / speed if speed > 0 else 0.0
    data = {
        "type": event, "total": total, "sent": sent, "failed": failed,
        "completed": completed, "remaining": remaining,
        "elapsed_seconds": round(elapsed, 2),
        "speed": round(speed, 2), "eta_seconds": round(eta, 2)
    }
    data.update(extra)
    return ndjson(data)

def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return False, "TURNSTILE_SECRET_KEY is not configured."
    if not token:
        return False, "Cloudflare verification is required."
    values = {"secret": TURNSTILE_SECRET_KEY, "response": token}
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
        return (True, None) if result.get("success") else (False, "Cloudflare verification failed.")
    except Exception:
        return False, "Unable to verify Cloudflare."

def create_message(sender_name, sender_email, recipient, subject, body, html_mode):
    message = MIMEText(render_spintax(body), "html" if html_mode else "plain", "utf-8")
    message["Subject"] = render_spintax(subject)
    message["From"] = formataddr((sender_name, sender_email))
    message["To"] = recipient
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()
    return message

def create_smtp(gmail, app_password):
    smtp = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ssl.create_default_context(), timeout=SMTP_TIMEOUT)
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

@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))
    error = None
    if request.method == "POST":
        password = str(request.form.get("password", ""))
        if not LOGIN_PASSWORD:
            error = "LOGIN_PASSWORD is not configured."
        elif secrets.compare_digest(password, LOGIN_PASSWORD):
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
    return render_template("index.html", turnstile_site_key=os.getenv("TURNSTILE_SITE_KEY", ""))

@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not authenticated():
        return jsonify({"success": False, "message": "Authentication required."}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "Invalid JSON request."}), 400

    sender_name = safe_header(data.get("sender_name", ""))
    gmail = safe_header(data.get("gmail", "")).lower()
    app_password = str(data.get("app_password", "")).strip()
    subject = safe_header(data.get("subject", ""))
    body = str(data.get("body", ""))
    html_mode = data.get("is_html", False) is True
    recipients = build_recipient_queue(data.get("recipients", []))
    turnstile_token = str(data.get("turnstile_token", "")).strip()

    checks = [
        (bool(sender_name), "Sender Name is required."),
        (valid_email(gmail), "Enter a valid Gmail address."),
        (bool(app_password), "Google App Password is required."),
        (bool(subject), "Email subject is required."),
        (bool(body.strip()), "Message body is required."),
        (bool(recipients), "No valid recipients found.")
    ]
    for passed, message in checks:
        if not passed:
            return jsonify({"success": False, "message": message}), 400

    forwarded = request.headers.get("X-Forwarded-For")
    remote_ip = forwarded.split(",")[0].strip() if forwarded else request.remote_addr
    passed, error = verify_turnstile(turnstile_token, remote_ip)
    if not passed:
        return jsonify({"success": False, "message": error}), 403

    @stream_with_context
    def generate():
        total, sent, failed, smtp = len(recipients), 0, 0, None
        start = time.perf_counter()
        yield make_progress("start", total, sent, failed)
        try:
            smtp = create_smtp(gmail, app_password)
            yield make_progress("connected", total, sent, failed, elapsed=time.perf_counter() - start)
            for position, recipient in enumerate(recipients, start=1):
                try:
                    message = create_message(sender_name, gmail, recipient, subject, body, html_mode)
                    smtp.sendmail(gmail, [recipient], message.as_string())
                    sent += 1
                    yield make_progress("progress", total, sent, failed,
                        elapsed=time.perf_counter() - start, email=recipient, result="sent", position=position)
                except smtplib.SMTPAuthenticationError:
                    failed += 1
                    yield make_progress("progress", total, sent, failed,
                        elapsed=time.perf_counter() - start, email=recipient, result="failed", position=position,
                        error="Gmail authentication failed. Check Gmail and App Password.")
                except Exception as exc:
                    failed += 1
                    yield make_progress("progress", total, sent, failed,
                        elapsed=time.perf_counter() - start, email=recipient, result="failed", position=position,
                        error=str(exc))
                if MAIL_GAP_SECONDS > 0 and position < total:
                    time.sleep(MAIL_GAP_SECONDS)
        except smtplib.SMTPAuthenticationError:
            yield make_progress("error", total, sent, failed, elapsed=time.perf_counter() - start,
                message="Gmail authentication failed. Check Gmail address and Google App Password.")
            return
        except Exception as exc:
            yield make_progress("error", total, sent, failed, elapsed=time.perf_counter() - start,
                message=f"SMTP/server error: {exc}")
            return
        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    pass
        elapsed = time.perf_counter() - start
        yield make_progress("complete", total, sent, failed, elapsed=elapsed,
            success=True, message="PRADEEP ❤️", total_time_seconds=round(elapsed, 2),
            average_speed=round(total / elapsed, 2) if elapsed > 0 else 0)

    return Response(generate(), content_type="application/x-ndjson; charset=utf-8",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"})

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "Secure Mail Console",
        "mailer": "Gmail SMTP SSL", "spintax": "always_on",
        "max_recipients": MAX_RECIPIENTS, "mail_gap_seconds": MAIL_GAP_SECONDS})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

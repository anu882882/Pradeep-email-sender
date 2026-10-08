from flask import (
    Flask, Response, jsonify, redirect, render_template,
    request, session, stream_with_context, url_for
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


# ============================================================
# APP
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

handler = app


# ============================================================
# ENV
# ============================================================

app.secret_key = os.getenv("SESSION_SECRET", "")
LOGIN_PASSWORD = os.getenv("LOGIN_PASSWORD", "")

TURNSTILE_SECRET_KEY = os.getenv(
    "TURNSTILE_SECRET_KEY",
    ""
)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 20

MAX_RECIPIENTS = 25


def get_mail_gap():
    try:
        return max(
            0.0,
            float(os.getenv("MAIL_GAP_SECONDS", "0"))
        )
    except (TypeError, ValueError):
        return 0.0


MAIL_GAP_SECONDS = get_mail_gap()


# ============================================================
# PATTERNS
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+"
    r"(?:\.[A-Za-z0-9-]+)+$"
)

SPINTAX_RE = re.compile(r"\{([^{}]+)\}")


# ============================================================
# HELPERS
# ============================================================

def authenticated():
    return session.get("authenticated") is True


def valid_email(value):
    return bool(
        EMAIL_RE.fullmatch(
            str(value or "").strip()
        )
    )


def safe_header(value):
    return (
        str(value or "")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()
    )


def ndjson(data):
    return (
        json.dumps(
            data,
            ensure_ascii=False
        ) + "\n"
    )


def format_seconds(seconds):
    seconds = max(0.0, float(seconds))

    minutes = int(seconds // 60)
    remaining = seconds % 60

    return f"{minutes:02d}:{remaining:05.2f}"


# ============================================================
# SPINTAX
# ============================================================

def render_spintax(text):
    text = str(text or "")

    for _ in range(10):

        changed = False

        def replace(match):
            nonlocal changed

            options = [
                item.strip()
                for item in match.group(1).split("|")
                if item.strip()
            ]

            if len(options) < 2:
                return match.group(0)

            changed = True
            return random.choice(options)

        updated = SPINTAX_RE.sub(
            replace,
            text
        )

        text = updated

        if not changed:
            break

    return text


# ============================================================
# RECIPIENTS
# ============================================================

def build_recipient_queue(raw):

    if not isinstance(raw, list):
        return []

    result = []
    seen = set()

    for item in raw:

        email = (
            str(item or "")
            .strip()
            .lower()
        )

        if not valid_email(email):
            continue

        if email in seen:
            continue

        seen.add(email)
        result.append(email)

        if len(result) >= MAX_RECIPIENTS:
            break

    return result


# ============================================================
# PROGRESS EVENT
# ============================================================

def make_progress(
    event,
    total,
    sent,
    failed,
    elapsed=0.0,
    started_at=None,
    **extra
):

    completed = sent + failed

    speed = (
        completed / elapsed
        if elapsed > 0
        else 0.0
    )

    remaining = max(
        0,
        total - completed
    )

    eta = (
        remaining / speed
        if speed > 0
        else 0.0
    )

    data = {
        "type": event,
        "total": total,
        "sent": sent,
        "failed": failed,
        "completed": completed,
        "remaining": remaining,

        "elapsed_seconds": round(
            elapsed,
            2
        ),

        "elapsed_display": format_seconds(
            elapsed
        ),

        "speed": round(
            speed,
            2
        ),

        "speed_display": (
            f"{speed:.2f} emails/sec"
        ),

        "eta_seconds": round(
            eta,
            2
        ),

        "eta_display": format_seconds(
            eta
        ),
    }

    if started_at is not None:
        data["started_at"] = started_at

    data.update(extra)

    return ndjson(data)


# ============================================================
# TURNSTILE
# ============================================================

def verify_turnstile(token, remote_ip=None):

    if not TURNSTILE_SECRET_KEY:
        return (
            False,
            "TURNSTILE_SECRET_KEY is not configured."
        )

    if not token:
        return (
            False,
            "Cloudflare verification is required."
        )

    values = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        values["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(
        values
    ).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={
            "Content-Type":
                "application/x-www-form-urlencoded"
        },
        method="POST",
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=10
        ) as response:

            result = json.loads(
                response.read().decode("utf-8")
            )

        if result.get("success"):
            return True, None

        return (
            False,
            "Cloudflare verification failed."
        )

    except Exception:
        return (
            False,
            "Unable to verify Cloudflare."
        )


# ============================================================
# EMAIL
# ============================================================

def create_message(
    sender_name,
    sender_email,
    recipient,
    subject,
    body,
    html_mode
):

    final_subject = render_spintax(
        subject
    )

    final_body = render_spintax(
        body
    )

    message = MIMEText(
        final_body,
        "html" if html_mode else "plain",
        "utf-8"
    )

    message["Subject"] = final_subject

    message["From"] = formataddr(
        (
            sender_name,
            sender_email
        )
    )

    message["To"] = recipient

    message["Date"] = formatdate(
        localtime=True
    )

    message["Message-ID"] = make_msgid()

    return message


# ============================================================
# SMTP
# ============================================================

def create_smtp(gmail, app_password):

    context = ssl.create_default_context()

    smtp = smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT
    )

    try:

        smtp.ehlo()

        smtp.login(
            gmail,
            app_password
        )

        return smtp

    except Exception:

        try:
            smtp.quit()
        except Exception:
            pass

        raise


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if authenticated():
        return redirect(
            url_for("home")
        )

    error = None

    if request.method == "POST":

        password = str(
            request.form.get(
                "password",
                ""
            )
        )

        if not LOGIN_PASSWORD:

            error = (
                "LOGIN_PASSWORD is not configured."
            )

        elif secrets.compare_digest(
            password,
            LOGIN_PASSWORD
        ):

            session.clear()
            session["authenticated"] = True

            return redirect(
                url_for("home")
            )

        else:
            error = "Incorrect password."

    return render_template(
        "login.html",
        error=error
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    if not authenticated():
        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html",
        turnstile_site_key=os.getenv(
            "TURNSTILE_SITE_KEY",
            ""
        )
    )


# ============================================================
# SEND BATCH
# ============================================================

@app.route(
    "/send-batch",
    methods=["POST"]
)
def send_batch():

    if not authenticated():

        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify({
            "success": False,
            "message": "Invalid JSON request."
        }), 400

    sender_name = safe_header(
        data.get("sender_name", "")
    )

    gmail = safe_header(
        data.get("gmail", "")
    ).lower()

    app_password = str(
        data.get("app_password", "")
    ).strip()

    subject = safe_header(
        data.get("subject", "")
    )

    body = str(
        data.get("body", "")
    )

    html_mode = (
        data.get("is_html", False)
        is True
    )

    recipients = build_recipient_queue(
        data.get("recipients", [])
    )

    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    ).strip()

    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    if not sender_name:
        return jsonify({
            "success": False,
            "message": "Sender Name is required."
        }), 400

    if not valid_email(gmail):
        return jsonify({
            "success": False,
            "message": "Enter a valid Gmail address."
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
            "message": "Message body is required."
        }), 400

    if not recipients:
        return jsonify({
            "success": False,
            "message": "No valid recipients found."
        }), 400

    # --------------------------------------------------------
    # TURNSTILE
    # --------------------------------------------------------

    forwarded = request.headers.get(
        "X-Forwarded-For"
    )

    remote_ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else request.remote_addr
    )

    passed, error = verify_turnstile(
        turnstile_token,
        remote_ip
    )

    if not passed:

        return jsonify({
            "success": False,
            "message": error
        }), 403

    # --------------------------------------------------------
    # STREAM
    # --------------------------------------------------------

    @stream_with_context
    def generate():

        total = len(recipients)

        sent = 0
        failed = 0

        smtp = None

        start_time = time.perf_counter()

        started_at = time.strftime(
            "%H:%M:%S"
        )

        yield make_progress(
            "start",
            total,
            sent,
            failed,
            elapsed=0,
            started_at=started_at
        )

        try:

            smtp = create_smtp(
                gmail,
                app_password
            )

            elapsed = (
                time.perf_counter()
                - start_time
            )

            yield make_progress(
                "connected",
                total,
                sent,
                failed,
                elapsed=elapsed,
                started_at=started_at
            )

            # ------------------------------------------------
            # SEND
            # ------------------------------------------------

            for position, recipient in enumerate(
                recipients,
                start=1
            ):

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

                    elapsed = (
                        time.perf_counter()
                        - start_time
                    )

                    yield make_progress(
                        "progress",
                        total,
                        sent,
                        failed,
                        elapsed=elapsed,
                        started_at=started_at,
                        email=recipient,
                        result="sent",
                        position=position
                    )

                except smtplib.SMTPAuthenticationError:

                    failed += 1

                    elapsed = (
                        time.perf_counter()
                        - start_time
                    )

                    yield make_progress(
                        "progress",
                        total,
                        sent,
                        failed,
                        elapsed=elapsed,
                        started_at=started_at,
                        email=recipient,
                        result="failed",
                        position=position,
                        error=(
                            "Gmail authentication failed. "
                            "Check Gmail and App Password."
                        )
                    )

                except smtplib.SMTPException as exc:

                    failed += 1

                    elapsed = (
                        time.perf_counter()
                        - start_time
                    )

                    yield make_progress(
                        "progress",
                        total,
                        sent,
                        failed,
                        elapsed=elapsed,
                        started_at=started_at,
                        email=recipient,
                        result="failed",
                        position=position,
                        error=f"SMTP error: {exc}"
                    )

                except Exception as exc:

                    failed += 1

                    elapsed = (
                        time.perf_counter()
                        - start_time
                    )

                    yield make_progress(
                        "progress",
                        total,
                        sent,
                        failed,
                        elapsed=elapsed,
                        started_at=started_at,
                        email=recipient,
                        result="failed",
                        position=position,
                        error=str(exc)
                    )

                if (
                    MAIL_GAP_SECONDS > 0
                    and position < total
                ):
                    time.sleep(
                        MAIL_GAP_SECONDS
                    )

        except smtplib.SMTPAuthenticationError:

            elapsed = (
                time.perf_counter()
                - start_time
            )

            yield make_progress(
                "error",
                total,
                sent,
                failed,
                elapsed=elapsed,
                started_at=started_at,
                message=(
                    "Gmail authentication failed. "
                    "Check Gmail address and "
                    "Google App Password."
                )
            )

            return

        except smtplib.SMTPException as exc:

            elapsed = (
                time.perf_counter()
                - start_time
            )

            yield make_progress(
                "error",
                total,
                sent,
                failed,
                elapsed=elapsed,
                started_at=started_at,
                message=f"SMTP error: {exc}"
            )

            return

        except Exception as exc:

            elapsed = (
                time.perf_counter()
                - start_time
            )

            yield make_progress(
                "error",
                total,
                sent,
                failed,
                elapsed=elapsed,
                started_at=started_at,
                message=f"Server error: {exc}"
            )

            return

        finally:

            if smtp is not None:

                try:
                    smtp.quit()
                except Exception:
                    pass

        # ----------------------------------------------------
        # COMPLETE
        # ----------------------------------------------------

        total_time = (
            time.perf_counter()
            - start_time
        )

        average_speed = (
            total / total_time
            if total_time > 0
            else 0
        )

        yield make_progress(
            "complete",
            total,
            sent,
            failed,
            elapsed=total_time,
            started_at=started_at,
            success=True,
            message="PRADEEP ❤️",
            total_time_seconds=round(
                total_time,
                2
            ),
            total_time_display=format_seconds(
                total_time
            ),
            average_speed=round(
                average_speed,
                2
            ),
            average_speed_display=(
                f"{average_speed:.2f} emails/sec"
            )
        )

    return Response(
        generate(),
        content_type=(
            "application/x-ndjson; "
            "charset=utf-8"
        ),
        headers={
            "Cache-Control":
                "no-cache, no-transform",
            "X-Accel-Buffering":
                "no-cache"
        }
    )


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "Secure Mail Console",
        "mailer": "Gmail SMTP SSL",
        "spintax": "always_on",
        "max_recipients": MAX_RECIPIENTS,
        "mail_gap_seconds": MAIL_GAP_SECONDS
    })


# ============================================================
# LOCAL
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

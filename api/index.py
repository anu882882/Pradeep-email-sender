from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    Response,
    stream_with_context,
)

from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid

from pathlib import Path

import html
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


# =========================================================
# APPLICATION
# =========================================================

ROOT = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(ROOT / "templates"),
    static_folder=str(ROOT / "static"),
    static_url_path="/static",
)

handler = app

app.secret_key = os.getenv("SESSION_SECRET", "")


# =========================================================
# SETTINGS
# =========================================================

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 20

MAX_RECIPIENTS = 25

# Optional pacing value from Vercel Environment Variables.
# Example:
# MAIL_GAP_SECONDS=1
try:
    MAIL_GAP_SECONDS = max(
        0.0,
        float(os.getenv("MAIL_GAP_SECONDS", "0"))
    )
except (TypeError, ValueError):
    MAIL_GAP_SECONDS = 0.0

TURNSTILE_SECRET = os.getenv(
    "TURNSTILE_SECRET_KEY",
    ""
)


# =========================================================
# REGEX
# =========================================================

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)

SPINTAX_PATTERN = re.compile(
    r"\{([^{}]+)\}"
)


# =========================================================
# GENERAL HELPERS
# =========================================================

def valid_email(value):
    value = str(value or "").strip()
    return bool(EMAIL_PATTERN.fullmatch(value))


def clean_header(value):
    return (
        str(value or "")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()
    )


def is_logged_in():
    return session.get("authenticated") is True


def json_line(payload):
    return (
        json.dumps(
            payload,
            ensure_ascii=False
        )
        + "\n"
    )


# =========================================================
# SPINTAX
# =========================================================

def spin(text):
    text = str(text or "")

    def choose(match):
        choices = [
            item.strip()
            for item in match.group(1).split("|")
            if item.strip()
        ]

        if len(choices) < 2:
            return match.group(0)

        return random.choice(choices)

    # Repeat a few times so nested/generated
    # Spintax can also be resolved.
    for _ in range(10):
        updated = SPINTAX_PATTERN.sub(
            choose,
            text
        )

        if updated == text:
            break

        text = updated

    return text


# =========================================================
# RECIPIENT PROCESSING
# =========================================================

def normalize_recipients(values):

    if not isinstance(values, list):
        return []

    output = []
    seen = set()

    for value in values:

        address = (
            str(value or "")
            .strip()
            .lower()
        )

        if not valid_email(address):
            continue

        if address in seen:
            continue

        seen.add(address)
        output.append(address)

        if len(output) >= MAX_RECIPIENTS:
            break

    return output


# =========================================================
# TURNSTILE
# =========================================================

def check_turnstile(token, remote_ip=None):

    if not TURNSTILE_SECRET:
        return (
            False,
            "TURNSTILE_SECRET_KEY is not configured."
        )

    if not token:
        return (
            False,
            "Cloudflare verification is required."
        )

    form = {
        "secret": TURNSTILE_SECRET,
        "response": token,
    }

    if remote_ip:
        form["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(
        form
    ).encode("utf-8")

    request_object = urllib.request.Request(
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
            request_object,
            timeout=10
        ) as response:

            result = json.loads(
                response.read().decode("utf-8")
            )

        if result.get("success") is True:
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


# =========================================================
# MESSAGE CREATION
# =========================================================

def build_message(
    sender_name,
    gmail,
    recipient,
    subject,
    body,
    html_mode=False,
):

    final_subject = spin(subject)
    final_body = spin(body)

    content_type = (
        "html"
        if html_mode
        else "plain"
    )

    message = MIMEText(
        final_body,
        content_type,
        "utf-8"
    )

    message["Subject"] = final_subject

    message["From"] = formataddr(
        (
            sender_name,
            gmail
        )
    )

    message["To"] = recipient

    message["Date"] = formatdate(
        localtime=True
    )

    message["Message-ID"] = make_msgid()

    return message


# =========================================================
# SMTP SENDER
# =========================================================

def send_recipient(
    smtp,
    gmail,
    sender_name,
    subject,
    body,
    html_mode,
    recipient,
):

    email_message = build_message(
        sender_name=sender_name,
        gmail=gmail,
        recipient=recipient,
        subject=subject,
        body=body,
        html_mode=html_mode,
    )

    smtp.sendmail(
        gmail,
        [recipient],
        email_message.as_string()
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if is_logged_in():
        return redirect(
            url_for("home")
        )

    error = None

    if request.method == "POST":

        entered = str(
            request.form.get(
                "password",
                ""
            )
        )

        expected = os.getenv(
            "LOGIN_PASSWORD",
            ""
        )

        if not expected:

            error = (
                "LOGIN_PASSWORD is not configured."
            )

        elif secrets.compare_digest(
            entered,
            expected
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


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if not is_logged_in():
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


# =========================================================
# SEND BATCH
# =========================================================

@app.route(
    "/send-batch",
    methods=["POST"]
)
def send_batch():

    if not is_logged_in():

        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    payload = request.get_json(
        silent=True
    ) or {}

    sender_name = clean_header(
        payload.get(
            "sender_name"
        )
    )

    gmail = clean_header(
        payload.get(
            "gmail"
        )
    ).lower()

    app_password = str(
        payload.get(
            "app_password",
            ""
        )
    ).strip()

    subject = clean_header(
        payload.get(
            "subject"
        )
    )

    body = str(
        payload.get(
            "body",
            ""
        )
    )

    html_mode = bool(
        payload.get(
            "is_html",
            False
        )
    )

    recipients = normalize_recipients(
        payload.get(
            "recipients",
            []
        )
    )

    turnstile_token = str(
        payload.get(
            "turnstile_token",
            ""
        )
    ).strip()


    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

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


    # -----------------------------------------------------
    # TURNSTILE
    # -----------------------------------------------------

    forwarded_for = request.headers.get(
        "X-Forwarded-For"
    )

    remote_ip = (
        forwarded_for.split(",")[0].strip()
        if forwarded_for
        else request.remote_addr
    )

    verified, error_message = check_turnstile(
        turnstile_token,
        remote_ip
    )

    if not verified:

        return jsonify({
            "success": False,
            "message": error_message
        }), 403


    # -----------------------------------------------------
    # STREAM
    # -----------------------------------------------------

    @stream_with_context
    def event_stream():

        total = len(recipients)
        sent = 0
        failed = 0

        smtp = None

        def progress(event_type, **extra):

            result = {
                "type": event_type,
                "total": total,
                "sent": sent,
                "failed": failed,
                "remaining":
                    total - sent - failed
            }

            result.update(extra)

            return json_line(result)


        yield progress("start")


        try:

            # One authenticated SMTP session.
            context = ssl.create_default_context()

            smtp = smtplib.SMTP_SSL(
                SMTP_SERVER,
                SMTP_PORT,
                context=context,
                timeout=SMTP_TIMEOUT
            )

            smtp.ehlo()

            smtp.login(
                gmail,
                app_password
            )

            yield progress(
                "connected"
            )


            # -------------------------------------------------
            # Sequential processing
            # -------------------------------------------------

            for index, recipient in enumerate(
                recipients
            ):

                try:

                    send_recipient(
                        smtp=smtp,
                        gmail=gmail,
                        sender_name=sender_name,
                        subject=subject,
                        body=body,
                        html_mode=html_mode,
                        recipient=recipient,
                    )

                    sent += 1

                    yield progress(
                        "progress",
                        email=recipient,
                        result="sent"
                    )


                except smtplib.SMTPAuthenticationError:

                    failed += 1

                    yield progress(
                        "progress",
                        email=recipient,
                        result="failed",
                        error=(
                            "Gmail authentication failed. "
                            "Check Gmail and App Password."
                        )
                    )


                except smtplib.SMTPException as exc:

                    failed += 1

                    yield progress(
                        "progress",
                        email=recipient,
                        result="failed",
                        error=f"SMTP error: {exc}"
                    )


                except Exception as exc:

                    failed += 1

                    yield progress(
                        "progress",
                        email=recipient,
                        result="failed",
                        error=str(exc)
                    )


                # Optional pacing between recipients.
                if (
                    MAIL_GAP_SECONDS > 0
                    and index < total - 1
                ):

                    time.sleep(
                        MAIL_GAP_SECONDS
                    )


        except smtplib.SMTPAuthenticationError:

            yield progress(
                "error",
                message=(
                    "Gmail authentication failed. "
                    "Check Gmail address and App Password."
                )
            )

            return


        except smtplib.SMTPException as exc:

            yield progress(
                "error",
                message=f"SMTP error: {exc}"
            )

            return


        except Exception as exc:

            yield progress(
                "error",
                message=f"Server error: {exc}"
            )

            return


        finally:

            if smtp is not None:

                try:
                    smtp.quit()
                except Exception:
                    pass


        # -----------------------------------------------------
        # COMPLETE
        # -----------------------------------------------------

        yield progress(
            "complete",
            success=True,
            message="PRADEEP ❤️"
        )


    return Response(
        event_stream(),
        content_type=(
            "application/x-ndjson; charset=utf-8"
        ),
        headers={
            "Cache-Control":
                "no-cache, no-transform",
            "X-Accel-Buffering":
                "no",
        }
    )


# =========================================================
# HEALTH
# =========================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "Secure Mail Console",
        "mailer": "Gmail SMTP SSL",
        "spintax": "always_on",
        "max_recipients": MAX_RECIPIENTS,
        "mail_gap_seconds":
            MAIL_GAP_SECONDS
    })


# =========================================================
# LOCAL
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

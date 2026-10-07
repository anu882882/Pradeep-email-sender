from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    stream_with_context,
    url_for,
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


# =========================================================
# APP CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parents[1]

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

handler = app

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    ""
)


# =========================================================
# MAIL CONFIGURATION
# =========================================================

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 20

MAX_RECIPIENTS = 25

try:
    MAIL_GAP_SECONDS = max(
        0.0,
        float(
            os.environ.get(
                "MAIL_GAP_SECONDS",
                "0"
            )
        )
    )
except (TypeError, ValueError):
    MAIL_GAP_SECONDS = 0.0


# =========================================================
# SECURITY CONFIGURATION
# =========================================================

TURNSTILE_SECRET_KEY = os.environ.get(
    "TURNSTILE_SECRET_KEY",
    ""
)


# =========================================================
# VALIDATORS
# =========================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+"
    r"(?:\.[A-Za-z0-9-]+)+$"
)

SPINTAX_RE = re.compile(
    r"\{([^{}]+)\}"
)


def valid_email(value):
    value = str(value or "").strip()
    return bool(
        EMAIL_RE.fullmatch(value)
    )


def clean_header(value):
    return (
        str(value or "")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()
    )


def logged_in():
    return (
        session.get("authenticated")
        is True
    )


# =========================================================
# JSON STREAM HELPERS
# =========================================================

def stream_json(data):
    return (
        json.dumps(
            data,
            ensure_ascii=False,
            separators=(",", ":")
        )
        + "\n"
    )


def make_status(
    event,
    total,
    sent,
    failed,
    **extra
):
    result = {
        "type": event,
        "total": total,
        "sent": sent,
        "failed": failed,
        "remaining": (
            total - sent - failed
        ),
    }

    result.update(extra)

    return result


# =========================================================
# SPINTAX ENGINE
# =========================================================

def expand_spintax(value):
    """
    Expands expressions such as:

        {Hi|Hello|Hey}

    One selection is made for every email.
    """

    text = str(value or "")

    for _ in range(12):

        changed = False

        def replace(match):

            nonlocal changed

            choices = [
                item.strip()
                for item in match.group(1).split("|")
                if item.strip()
            ]

            if len(choices) < 2:
                return match.group(0)

            changed = True

            return random.choice(choices)

        updated = SPINTAX_RE.sub(
            replace,
            text
        )

        text = updated

        if not changed:
            break

    return text


# =========================================================
# RECIPIENT NORMALIZATION
# =========================================================

def prepare_recipients(raw):

    if not isinstance(raw, list):
        return []

    cleaned = []
    seen = set()

    for item in raw:

        address = (
            str(item or "")
            .strip()
            .lower()
        )

        if not valid_email(address):
            continue

        if address in seen:
            continue

        seen.add(address)
        cleaned.append(address)

        if len(cleaned) == MAX_RECIPIENTS:
            break

    return cleaned


# =========================================================
# TURNSTILE VERIFICATION
# =========================================================

def verify_turnstile(
    token,
    remote_ip=None
):

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

    body = urllib.parse.urlencode(
        values
    ).encode("utf-8")

    req = urllib.request.Request(
        (
            "https://challenges.cloudflare.com/"
            "turnstile/v0/siteverify"
        ),
        data=body,
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
                response.read().decode(
                    "utf-8"
                )
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
# EMAIL BUILDER
# =========================================================

def create_email(
    sender_name,
    gmail,
    recipient,
    subject,
    body,
    is_html
):

    rendered_subject = (
        expand_spintax(subject)
    )

    rendered_body = (
        expand_spintax(body)
    )

    message = MIMEText(
        rendered_body,
        "html" if is_html else "plain",
        "utf-8"
    )

    message["Subject"] = (
        rendered_subject
    )

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

    message["MIME-Version"] = "1.0"

    return message


# =========================================================
# SMTP CONNECTION
# =========================================================

def open_smtp(
    gmail,
    app_password
):

    context = ssl.create_default_context()

    server = smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT
    )

    try:

        server.ehlo()

        server.login(
            gmail,
            app_password
        )

        return server

    except Exception:

        try:
            server.quit()
        except Exception:
            pass

        raise


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if logged_in():
        return redirect(
            url_for("home")
        )

    error = None

    if request.method == "POST":

        supplied_password = str(
            request.form.get(
                "password",
                ""
            )
        )

        configured_password = (
            os.environ.get(
                "LOGIN_PASSWORD",
                ""
            )
        )

        if not configured_password:

            error = (
                "LOGIN_PASSWORD is not configured."
            )

        elif secrets.compare_digest(
            supplied_password,
            configured_password
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
# MAIN PAGE
# =========================================================

@app.route("/")
def home():

    if not logged_in():

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html",
        turnstile_site_key=(
            os.environ.get(
                "TURNSTILE_SITE_KEY",
                ""
            )
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

    if not logged_in():

        return jsonify({
            "success": False,
            "message":
                "Authentication required."
        }), 401


    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify({
            "success": False,
            "message":
                "Invalid request."
        }), 400


    # -----------------------------------------------------
    # INPUTS
    # -----------------------------------------------------

    sender_name = clean_header(
        data.get(
            "sender_name"
        )
    )

    gmail = clean_header(
        data.get(
            "gmail"
        )
    ).lower()

    app_password = str(
        data.get(
            "app_password",
            ""
        )
    ).strip()

    subject = clean_header(
        data.get(
            "subject"
        )
    )

    body = str(
        data.get(
            "body",
            ""
        )
    )

    is_html = (
        data.get(
            "is_html",
            False
        )
        is True
    )

    recipients = prepare_recipients(
        data.get(
            "recipients",
            []
        )
    )

    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    ).strip()


    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    checks = [
        (
            bool(sender_name),
            "Sender Name is required."
        ),
        (
            valid_email(gmail),
            "Enter a valid Gmail address."
        ),
        (
            bool(app_password),
            "Google App Password is required."
        ),
        (
            bool(subject),
            "Email subject is required."
        ),
        (
            bool(body.strip()),
            "Message body is required."
        ),
        (
            bool(recipients),
            "No valid recipients found."
        ),
    ]

    for passed, message in checks:

        if not passed:

            return jsonify({
                "success": False,
                "message": message
            }), 400


    # -----------------------------------------------------
    # TURNSTILE
    # -----------------------------------------------------

    forwarded = request.headers.get(
        "X-Forwarded-For"
    )

    remote_ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else request.remote_addr
    )

    verified, verification_error = (
        verify_turnstile(
            turnstile_token,
            remote_ip
        )
    )

    if not verified:

        return jsonify({
            "success": False,
            "message":
                verification_error
        }), 403


    # =====================================================
    # STREAMING WORKER
    # =====================================================

    @stream_with_context
    def stream():

        total = len(recipients)

        sent = 0
        failed = 0

        smtp = None

        yield stream_json(
            make_status(
                "start",
                total,
                sent,
                failed
            )
        )

        try:

            smtp = open_smtp(
                gmail,
                app_password
            )

            yield stream_json(
                make_status(
                    "connected",
                    total,
                    sent,
                    failed
                )
            )


            for position, recipient in enumerate(
                recipients
            ):

                try:

                    message = create_email(
                        sender_name=sender_name,
                        gmail=gmail,
                        recipient=recipient,
                        subject=subject,
                        body=body,
                        is_html=is_html
                    )

                    smtp.sendmail(
                        gmail,
                        [recipient],
                        message.as_string()
                    )

                    sent += 1

                    yield stream_json(
                        make_status(
                            "progress",
                            total,
                            sent,
                            failed,
                            email=recipient,
                            result="sent"
                        )
                    )


                except smtplib.SMTPAuthenticationError:

                    failed += 1

                    yield stream_json(
                        make_status(
                            "progress",
                            total,
                            sent,
                            failed,
                            email=recipient,
                            result="failed",
                            error=(
                                "Gmail authentication failed. "
                                "Check Gmail and App Password."
                            )
                        )
                    )


                except smtplib.SMTPException as exc:

                    failed += 1

                    yield stream_json(
                        make_status(
                            "progress",
                            total,
                            sent,
                            failed,
                            email=recipient,
                            result="failed",
                            error=(
                                f"SMTP error: {exc}"
                            )
                        )
                    )


                except Exception as exc:

                    failed += 1

                    yield stream_json(
                        make_status(
                            "progress",
                            total,
                            sent,
                            failed,
                            email=recipient,
                            result="failed",
                            error=str(exc)
                        )
                    )


                # Optional pacing between
                # consecutive recipients.
                if (
                    MAIL_GAP_SECONDS > 0
                    and position < total - 1
                ):

                    time.sleep(
                        MAIL_GAP_SECONDS
                    )


        except smtplib.SMTPAuthenticationError:

            yield stream_json(
                make_status(
                    "error",
                    total,
                    sent,
                    failed,
                    message=(
                        "Gmail authentication failed. "
                        "Check Gmail and App Password."
                    )
                )
            )

            return


        except smtplib.SMTPException as exc:

            yield stream_json(
                make_status(
                    "error",
                    total,
                    sent,
                    failed,
                    message=f"SMTP error: {exc}"
                )
            )

            return


        except Exception as exc:

            yield stream_json(
                make_status(
                    "error",
                    total,
                    sent,
                    failed,
                    message=f"Server error: {exc}"
                )
            )

            return


        finally:

            if smtp is not None:

                try:
                    smtp.quit()
                except Exception:
                    pass


        yield stream_json(
            make_status(
                "complete",
                total,
                sent,
                failed,
                success=True,
                message="PRADEEP ❤️"
            )
        )


    # =====================================================
    # RESPONSE
    # =====================================================

    return Response(
        stream(),
        content_type=(
            "application/x-ndjson; "
            "charset=utf-8"
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
        "service":
            "Secure Mail Console",
        "mailer":
            "Gmail SMTP SSL",
        "spintax":
            "always_on",
        "max_recipients":
            MAX_RECIPIENTS,
        "mail_gap_seconds":
            MAIL_GAP_SECONDS,
    })


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

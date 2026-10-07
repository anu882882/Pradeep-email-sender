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


# ============================================================
# PROJECT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "templates"),
    static_folder=str(PROJECT_ROOT / "static"),
    static_url_path="/static",
)

# Vercel WSGI entry point
handler = app


# ============================================================
# ENVIRONMENT
# ============================================================

app.secret_key = os.getenv(
    "SESSION_SECRET",
    ""
)

LOGIN_PASSWORD = os.getenv(
    "LOGIN_PASSWORD",
    ""
)

TURNSTILE_SECRET_KEY = os.getenv(
    "TURNSTILE_SECRET_KEY",
    ""
)


# ============================================================
# MAIL SETTINGS
# ============================================================

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 20

MAX_RECIPIENTS = 25


def read_gap():
    raw = os.getenv(
        "MAIL_GAP_SECONDS",
        "0"
    )

    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 0.0

    return max(0.0, value)


MAIL_GAP_SECONDS = read_gap()


# ============================================================
# PATTERNS
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+"
    r"(?:\.[A-Za-z0-9-]+)+$"
)

SPINTAX_RE = re.compile(
    r"\{([^{}]+)\}"
)


# ============================================================
# BASIC HELPERS
# ============================================================

def authenticated():
    return session.get(
        "authenticated"
    ) is True


def valid_email(value):
    address = str(
        value or ""
    ).strip()

    return bool(
        EMAIL_RE.fullmatch(address)
    )


def safe_header(value):
    """
    Removes CR/LF so user-controlled values
    cannot create additional email headers.
    """

    return (
        str(value or "")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()
    )


def ndjson(payload):
    return (
        json.dumps(
            payload,
            ensure_ascii=False
        )
        + "\n"
    )


# ============================================================
# SPINTAX
# ============================================================

def render_spintax(value):
    """
    Example:

        {Hi|Hello|Hey} {there|friend}

    produces one variation for each email.
    """

    text = str(value or "")

    for _ in range(10):

        found = False

        def replacement(match):

            nonlocal found

            options = [
                part.strip()
                for part in match.group(1).split("|")
                if part.strip()
            ]

            if len(options) < 2:
                return match.group(0)

            found = True

            return random.choice(options)

        updated = SPINTAX_RE.sub(
            replacement,
            text
        )

        text = updated

        if not found:
            break

    return text


# ============================================================
# RECIPIENT QUEUE
# ============================================================

def build_recipient_queue(raw):

    if not isinstance(raw, list):
        return []

    queue = []
    known = set()

    for item in raw:

        address = (
            str(item or "")
            .strip()
            .lower()
        )

        if not valid_email(address):
            continue

        if address in known:
            continue

        known.add(address)
        queue.append(address)

        if len(queue) >= MAX_RECIPIENTS:
            break

    return queue


# ============================================================
# PROGRESS
# ============================================================

def progress_event(
    event,
    total,
    sent,
    failed,
    **extra
):

    payload = {
        "type": event,
        "total": total,
        "sent": sent,
        "failed": failed,
        "remaining": (
            total - sent - failed
        ),
    }

    payload.update(extra)

    return ndjson(payload)


# ============================================================
# TURNSTILE
# ============================================================

def validate_turnstile(
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

    encoded = urllib.parse.urlencode(
        values
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
                response.read().decode(
                    "utf-8"
                )
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
# EMAIL FACTORY
# ============================================================

def make_email(
    sender_name,
    sender_email,
    recipient,
    subject,
    body,
    html_mode
):

    # Generate a different Spintax result
    # for every recipient.
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

    message["Subject"] = (
        final_subject
    )

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
# SMTP SESSION
# ============================================================

def create_smtp_session(
    gmail,
    app_password
):

    tls = ssl.create_default_context()

    smtp = smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=tls,
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
# LOGIN ROUTE
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
# REQUEST PARSER
# ============================================================

def parse_mail_request():

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return None, (
            "Invalid JSON request."
        )

    sender_name = safe_header(
        data.get(
            "sender_name",
            ""
        )
    )

    gmail = safe_header(
        data.get(
            "gmail",
            ""
        )
    ).lower()

    app_password = str(
        data.get(
            "app_password",
            ""
        )
    ).strip()

    subject = safe_header(
        data.get(
            "subject",
            ""
        )
    )

    body = str(
        data.get(
            "body",
            ""
        )
    )

    html_mode = (
        data.get(
            "is_html",
            False
        )
        is True
    )

    recipients = build_recipient_queue(
        data.get(
            "recipients",
            []
        )
    )

    token = str(
        data.get(
            "turnstile_token",
            ""
        )
    ).strip()

    return {
        "sender_name": sender_name,
        "gmail": gmail,
        "app_password": app_password,
        "subject": subject,
        "body": body,
        "is_html": html_mode,
        "recipients": recipients,
        "turnstile_token": token,
    }, None


# ============================================================
# REQUEST VALIDATION
# ============================================================

def validate_mail_request(data):

    if not data["sender_name"]:
        return "Sender Name is required."

    if not valid_email(
        data["gmail"]
    ):
        return "Enter a valid Gmail address."

    if not data["app_password"]:
        return (
            "Google App Password is required."
        )

    if not data["subject"]:
        return "Email subject is required."

    if not data["body"].strip():
        return "Message body is required."

    if not data["recipients"]:
        return "No valid recipients found."

    return None


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
            "message":
                "Authentication required."
        }), 401


    mail_data, parse_error = (
        parse_mail_request()
    )

    if parse_error:

        return jsonify({
            "success": False,
            "message": parse_error
        }), 400


    validation_error = (
        validate_mail_request(
            mail_data
        )
    )

    if validation_error:

        return jsonify({
            "success": False,
            "message":
                validation_error
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

    passed, turnstile_error = (
        validate_turnstile(
            mail_data["turnstile_token"],
            remote_ip
        )
    )

    if not passed:

        return jsonify({
            "success": False,
            "message":
                turnstile_error
        }), 403


    # ========================================================
    # STREAM GENERATOR
    # ========================================================

    @stream_with_context
    def generate():

        recipients = mail_data[
            "recipients"
        ]

        total = len(recipients)

        sent = 0
        failed = 0

        smtp = None


        # ----------------------------------------------------
        # INITIAL STATE
        # ----------------------------------------------------

        yield progress_event(
            "start",
            total,
            sent,
            failed
        )


        try:

            # ------------------------------------------------
            # CONNECT + AUTHENTICATE
            # ------------------------------------------------

            smtp = create_smtp_session(
                mail_data["gmail"],
                mail_data["app_password"]
            )

            yield progress_event(
                "connected",
                total,
                sent,
                failed
            )


            # ------------------------------------------------
            # QUEUE
            # ------------------------------------------------

            for number, recipient in enumerate(
                recipients,
                start=1
            ):

                try:

                    message = make_email(
                        sender_name=(
                            mail_data[
                                "sender_name"
                            ]
                        ),
                        sender_email=(
                            mail_data[
                                "gmail"
                            ]
                        ),
                        recipient=recipient,
                        subject=(
                            mail_data[
                                "subject"
                            ]
                        ),
                        body=(
                            mail_data[
                                "body"
                            ]
                        ),
                        html_mode=(
                            mail_data[
                                "is_html"
                            ]
                        ),
                    )

                    smtp.sendmail(
                        mail_data["gmail"],
                        [recipient],
                        message.as_string()
                    )

                    sent += 1

                    yield progress_event(
                        "progress",
                        total,
                        sent,
                        failed,
                        email=recipient,
                        result="sent",
                        position=number
                    )


                except smtplib.SMTPAuthenticationError:

                    failed += 1

                    yield progress_event(
                        "progress",
                        total,
                        sent,
                        failed,
                        email=recipient,
                        result="failed",
                        error=(
                            "Gmail authentication "
                            "failed. Check Gmail "
                            "and App Password."
                        ),
                        position=number
                    )


                except smtplib.SMTPException as exc:

                    failed += 1

                    yield progress_event(
                        "progress",
                        total,
                        sent,
                        failed,
                        email=recipient,
                        result="failed",
                        error=(
                            f"SMTP error: {exc}"
                        ),
                        position=number
                    )


                except Exception as exc:

                    failed += 1

                    yield progress_event(
                        "progress",
                        total,
                        sent,
                        failed,
                        email=recipient,
                        result="failed",
                        error=str(exc),
                        position=number
                    )


                # ------------------------------------------------
                # OPTIONAL PACING
                # ------------------------------------------------

                if (
                    MAIL_GAP_SECONDS > 0
                    and number < total
                ):

                    time.sleep(
                        MAIL_GAP_SECONDS
                    )


        except smtplib.SMTPAuthenticationError:

            yield progress_event(
                "error",
                total,
                sent,
                failed,
                message=(
                    "Gmail authentication failed. "
                    "Check Gmail address and "
                    "Google App Password."
                )
            )

            return


        except smtplib.SMTPException as exc:

            yield progress_event(
                "error",
                total,
                sent,
                failed,
                message=(
                    f"SMTP error: {exc}"
                )
            )

            return


        except Exception as exc:

            yield progress_event(
                "error",
                total,
                sent,
                failed,
                message=(
                    f"Server error: {exc}"
                )
            )

            return


        finally:

            if smtp is not None:

                try:
                    smtp.quit()
                except Exception:
                    pass


        # ----------------------------------------------------
        # FINAL EVENT
        # ----------------------------------------------------

        yield progress_event(
            "complete",
            total,
            sent,
            failed,
            success=True,
            message="PRADEEP ❤️"
        )


    # ========================================================
    # NDJSON RESPONSE
    # ========================================================

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
                "no",
        }
    )


# ============================================================
# HEALTH CHECK
# ============================================================

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


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

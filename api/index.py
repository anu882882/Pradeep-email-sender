from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    Response,
    stream_with_context
)

from pathlib import Path
from email.mime.text import MIMEText
from email.utils import formataddr

import os
import re
import ssl
import json
import random
import secrets
import smtplib
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]


server = Flask(
    __name__,
    template_folder=str(ROOT / "templates"),
    static_folder=str(ROOT / "static"),
    static_url_path="/static"
)

server.secret_key = os.getenv(
    "SESSION_SECRET",
    "temporary-session-key"
)


LIMIT = 25

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)

SPIN_PATTERN = re.compile(
    r"\{([^{}]+)\}"
)


def clean_email(value):
    return str(value or "").strip().lower()


def email_ok(value):
    return bool(
        EMAIL_PATTERN.fullmatch(
            clean_email(value)
        )
    )


def logged_in():
    return session.get("mail_console_auth") is True


def spin_text(value):
    """
    Converts:
        {Hi|Hello|Hey}
    into one random option.

    Spintax is intentionally always enabled.
    """

    source = str(value or "")

    def choose(match):

        choices = [
            item.strip()
            for item in match.group(1).split("|")
        ]

        choices = [
            item
            for item in choices
            if item
        ]

        if len(choices) < 2:
            return match.group(0)

        return random.choice(choices)

    previous = None
    current = source

    # Multiple passes allow separate groups
    # to be processed reliably.
    for _ in range(5):

        if current == previous:
            break

        previous = current

        current = SPIN_PATTERN.sub(
            choose,
            current
        )

    return current


def verify_cloudflare(token, ip_address=None):

    secret = os.getenv(
        "TURNSTILE_SECRET_KEY",
        ""
    ).strip()

    if not secret:
        return False, "Turnstile secret is missing."

    if not token:
        return False, "Cloudflare verification is required."

    payload = {
        "secret": secret,
        "response": token
    }

    if ip_address:
        payload["remoteip"] = ip_address

    encoded = urllib.parse.urlencode(
        payload
    ).encode("utf-8")

    request_object = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        method="POST",
        headers={
            "Content-Type":
            "application/x-www-form-urlencoded"
        }
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
            return True, ""

        return False, "Cloudflare verification failed."

    except Exception:
        return False, "Cloudflare verification unavailable."


@server.route(
    "/login",
    methods=["GET", "POST"]
)
def login_page():

    if logged_in():
        return redirect(
            url_for("dashboard")
        )

    error_message = ""

    if request.method == "POST":

        entered = request.form.get(
            "password",
            ""
        )

        expected = os.getenv(
            "LOGIN_PASSWORD",
            ""
        )

        if not expected:

            error_message = (
                "LOGIN_PASSWORD is not configured."
            )

        elif secrets.compare_digest(
            entered,
            expected
        ):

            session.clear()

            session["mail_console_auth"] = True

            return redirect(
                url_for("dashboard")
            )

        else:

            error_message = "Incorrect password."

    return render_template(
        "login.html",
        error=error_message
    )


@server.route("/logout")
def logout_page():

    session.clear()

    return redirect(
        url_for("login_page")
    )


@server.route("/")
def dashboard():

    if not logged_in():
        return redirect(
            url_for("login_page")
        )

    return render_template(
        "index.html",
        site_key=os.getenv(
            "TURNSTILE_SITE_KEY",
            ""
        )
    )


@server.route(
    "/send-batch",
    methods=["POST"]
)
def send_batch():

    if not logged_in():

        return jsonify({
            "ok": False,
            "message": "Login required."
        }), 401

    payload = request.get_json(
        silent=True
    ) or {}

    sender_name = str(
        payload.get(
            "sender_name",
            ""
        )
    ).strip()

    gmail = clean_email(
        payload.get(
            "gmail",
            ""
        )
    )

    app_password = str(
        payload.get(
            "app_password",
            ""
        )
    ).strip()

    subject = str(
        payload.get(
            "subject",
            ""
        )
    ).strip()

    message_body = str(
        payload.get(
            "message_body",
            ""
        )
    )

    html_mode = bool(
        payload.get(
            "html_mode",
            False
        )
    )

    recipients_input = payload.get(
        "recipients",
        []
    )

    turnstile = str(
        payload.get(
            "turnstile",
            ""
        )
    ).strip()

    if not sender_name:
        return jsonify({
            "ok": False,
            "message": "Sender Name is required."
        }), 400

    if not email_ok(gmail):
        return jsonify({
            "ok": False,
            "message": "Enter a valid Gmail address."
        }), 400

    if not app_password:
        return jsonify({
            "ok": False,
            "message": "App Password is required."
        }), 400

    if not subject:
        return jsonify({
            "ok": False,
            "message": "Subject is required."
        }), 400

    if not message_body.strip():
        return jsonify({
            "ok": False,
            "message": "Message Body is empty."
        }), 400

    if not isinstance(
        recipients_input,
        list
    ):
        return jsonify({
            "ok": False,
            "message": "Invalid recipients."
        }), 400

    recipients = []

    for raw in recipients_input:

        address = clean_email(raw)

        if not email_ok(address):
            continue

        if address not in recipients:
            recipients.append(address)

    recipients = recipients[:LIMIT]

    if not recipients:

        return jsonify({
            "ok": False,
            "message": "No valid recipients."
        }), 400

    remote_ip = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr
    )

    verified, verification_error = verify_cloudflare(
        turnstile,
        remote_ip
    )

    if not verified:

        return jsonify({
            "ok": False,
            "message": verification_error
        }), 403

    @stream_with_context
    def event_stream():

        total = len(recipients)
        sent = 0
        failed = 0

        def emit(event_type, **extra):

            packet = {
                "type": event_type,
                "total": total,
                "sent": sent,
                "failed": failed,
                "remaining": total - sent - failed
            }

            packet.update(extra)

            return (
                json.dumps(
                    packet,
                    ensure_ascii=False
                )
                + "\n"
            )

        yield emit("started")

        smtp_context = ssl.create_default_context()

        try:

            with smtplib.SMTP_SSL(
                "smtp.gmail.com",
                465,
                context=smtp_context,
                timeout=20
            ) as smtp:

                smtp.login(
                    gmail,
                    app_password
                )

                for destination in recipients:

                    try:

                        # ALWAYS ON
                        final_subject = spin_text(
                            subject
                        )

                        final_message = spin_text(
                            message_body
                        )

                        mime_type = (
                            "html"
                            if html_mode
                            else "plain"
                        )

                        email_message = MIMEText(
                            final_message,
                            mime_type,
                            "utf-8"
                        )

                        email_message["Subject"] = (
                            final_subject
                        )

                        email_message["From"] = (
                            formataddr(
                                (
                                    sender_name,
                                    gmail
                                )
                            )
                        )

                        email_message["To"] = destination

                        smtp.sendmail(
                            gmail,
                            [destination],
                            email_message.as_string()
                        )

                        sent += 1

                        yield emit(
                            "recipient",
                            email=destination,
                            result="sent"
                        )

                    except Exception as error:

                        failed += 1

                        yield emit(
                            "recipient",
                            email=destination,
                            result="failed",
                            error=str(error)
                        )

        except smtplib.SMTPAuthenticationError:

            yield emit(
                "fatal",
                message=(
                    "Gmail authentication failed. "
                    "Check Gmail and App Password."
                )
            )

            return

        except smtplib.SMTPException as error:

            yield emit(
                "fatal",
                message=f"SMTP error: {error}"
            )

            return

        except Exception as error:

            yield emit(
                "fatal",
                message=f"Server error: {error}"
            )

            return

        yield emit(
            "finished",
            message="sending compleate Babu❤️"
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
            "no"
        }
    )


@server.route("/health")
def health_check():

    return jsonify({
        "status": "ok",
        "mailer": "gmail-smtp",
        "spintax": "always-on"
    })


app = server


if __name__ == "__main__":

    server.run(
        host="0.0.0.0",
        port=5000
    )

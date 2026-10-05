import os
import re
import ssl
import json
import time
import random
import smtplib
import secrets
import urllib.parse
import urllib.request

from pathlib import Path
from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    session,
    jsonify,
    Response,
    stream_with_context
)

from email.mime.text import MIMEText
from email.utils import formataddr


BASE = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE / "templates"),
    static_folder=str(BASE / "static")
)

app.secret_key = os.getenv(
    "SESSION_SECRET",
    "change-this-session-secret"
)


MAX_RECIPIENTS = 25

# -------------------------------------------------------
# MAIL SPEED
# -------------------------------------------------------
#
# 0    = no extra application delay
# 0.25 = small pacing gap
# 0.50 = moderate pacing
# 1.00 = one second between messages
#
# This does NOT guarantee delivery time because Gmail
# controls actual delivery/processing.
# -------------------------------------------------------

MAIL_GAP_SECONDS = float(
    os.getenv(
        "MAIL_GAP_SECONDS",
        "0"
    )
)


EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)

SPINTAX_RE = re.compile(
    r"\{([^{}]+)\}"
)


def valid_email(value):

    value = str(
        value or ""
    ).strip().lower()

    return bool(
        EMAIL_RE.fullmatch(value)
    )


def is_logged():

    return (
        session.get(
            "secure_mail_login"
        ) is True
    )


# -------------------------------------------------------
# PERMANENT SPINTAX
# -------------------------------------------------------

def render_spintax(text):

    text = str(
        text or ""
    )

    def replace_group(match):

        options = [
            x.strip()
            for x in
            match.group(1).split("|")
            if x.strip()
        ]

        if len(options) < 2:
            return match.group(0)

        return random.choice(
            options
        )

    # Several passes make nested/simple groups
    # more reliable without requiring a toggle.

    for _ in range(6):

        new_text = SPINTAX_RE.sub(
            replace_group,
            text
        )

        if new_text == text:
            break

        text = new_text

    return text


# -------------------------------------------------------
# TURNSTILE
# -------------------------------------------------------

def check_turnstile(token, remote_ip):

    secret = os.getenv(
        "TURNSTILE_SECRET_KEY",
        ""
    ).strip()

    if not secret:
        return False, "Turnstile secret is missing."

    if not token:
        return False, "Complete Spam Protection."

    values = {
        "secret": secret,
        "response": token
    }

    if remote_ip:
        values["remoteip"] = remote_ip

    body = urllib.parse.urlencode(
        values
    ).encode()

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=body,
        headers={
            "Content-Type":
            "application/x-www-form-urlencoded"
        },
        method="POST"
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=10
        ) as response:

            result = json.loads(
                response.read().decode()
            )

        if result.get("success"):
            return True, ""

        return False, "Cloudflare verification failed."

    except Exception:

        return False, "Cloudflare verification error."


# -------------------------------------------------------
# LOGIN
# -------------------------------------------------------

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if is_logged():

        return redirect(
            url_for("home")
        )

    error = ""

    if request.method == "POST":

        entered = str(
            request.form.get(
                "password",
                ""
            )
        )

        configured = os.getenv(
            "LOGIN_PASSWORD",
            ""
        )

        if not configured:

            error = (
                "LOGIN_PASSWORD is not configured."
            )

        elif secrets.compare_digest(
            entered,
            configured
        ):

            session.clear()

            session["secure_mail_login"] = True

            return redirect(
                url_for("home")
            )

        else:

            error = "Incorrect password."

    return render_template(
        "login.html",
        error=error
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# -------------------------------------------------------
# DASHBOARD
# -------------------------------------------------------

@app.route("/")
def home():

    if not is_logged():

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html",
        site_key=os.getenv(
            "TURNSTILE_SITE_KEY",
            ""
        )
    )


# -------------------------------------------------------
# MAIL ENGINE
# -------------------------------------------------------

def create_message(
    sender_name,
    gmail,
    recipient,
    subject,
    body,
    html_mode
):

    # Spintax is ALWAYS enabled.
    final_subject = render_spintax(
        subject
    )

    final_body = render_spintax(
        body
    )

    subtype = (
        "html"
        if html_mode
        else "plain"
    )

    message = MIMEText(
        final_body,
        subtype,
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

    return message


def send_one(
    smtp,
    sender,
    recipient,
    subject,
    body,
    html_mode
):

    message = create_message(
        sender_name=sender["name"],
        gmail=sender["email"],
        recipient=recipient,
        subject=subject,
        body=body,
        html_mode=html_mode
    )

    smtp.send_message(
        message,
        from_addr=sender["email"],
        to_addrs=[recipient]
    )


# -------------------------------------------------------
# BATCH ENDPOINT
# -------------------------------------------------------

@app.route(
    "/send-batch",
    methods=["POST"]
)
def send_batch():

    if not is_logged():

        return jsonify({
            "ok": False,
            "message": "Authentication required."
        }), 401


    data = request.get_json(
        silent=True
    ) or {}


    sender_name = str(
        data.get(
            "sender_name",
            ""
        )
    ).strip()


    gmail = str(
        data.get(
            "gmail",
            ""
        )
    ).strip().lower()


    app_password = str(
        data.get(
            "app_password",
            ""
        )
    ).strip()


    subject = str(
        data.get(
            "subject",
            ""
        )
    ).strip()


    body = str(
        data.get(
            "message_body",
            ""
        )
    )


    html_mode = bool(
        data.get(
            "html_mode",
            False
        )
    )


    raw_recipients = data.get(
        "recipients",
        []
    )


    captcha = str(
        data.get(
            "turnstile",
            ""
        )
    ).strip()


    # ---------------------------------------------------
    # VALIDATION
    # ---------------------------------------------------

    if not sender_name:

        return jsonify({
            "ok": False,
            "message": "Sender Name is required."
        }), 400


    if not valid_email(gmail):

        return jsonify({
            "ok": False,
            "message": "Invalid Gmail address."
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


    if not body.strip():

        return jsonify({
            "ok": False,
            "message": "Message Body is blank."
        }), 400


    if not isinstance(
        raw_recipients,
        list
    ):

        return jsonify({
            "ok": False,
            "message": "Invalid recipients."
        }), 400


    recipients = []

    for value in raw_recipients:

        email = str(
            value
        ).strip().lower()

        if not valid_email(email):
            continue

        if email not in recipients:

            recipients.append(
                email
            )


    recipients = recipients[
        :MAX_RECIPIENTS
    ]


    if not recipients:

        return jsonify({
            "ok": False,
            "message": "No valid recipients."
        }), 400


    remote_ip = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr
    )


    verified, verify_message = check_turnstile(
        captcha,
        remote_ip
    )


    if not verified:

        return jsonify({
            "ok": False,
            "message": verify_message
        }), 403


    # ---------------------------------------------------
    # STREAMING MAIL PROCESS
    # ---------------------------------------------------

    @stream_with_context
    def mail_stream():

        total = len(
            recipients
        )

        sent = 0
        failed = 0


        def packet(
            event,
            **values
        ):

            result = {
                "event": event,
                "total": total,
                "sent": sent,
                "failed": failed,
                "remaining":
                    total - sent - failed
            }

            result.update(values)

            return (
                json.dumps(
                    result,
                    ensure_ascii=False
                )
                + "\n"
            )


        yield packet(
            "begin"
        )


        context = ssl.create_default_context()


        sender_info = {
            "name": sender_name,
            "email": gmail
        }


        try:

            # ------------------------------------------------
            # ONE SMTP CONNECTION
            # ------------------------------------------------

            smtp = smtplib.SMTP_SSL(
                "smtp.gmail.com",
                465,
                context=context,
                timeout=20
            )


            try:

                smtp.ehlo()


                smtp.login(
                    gmail,
                    app_password
                )


                # --------------------------------------------
                # SEQUENTIAL SEND
                # --------------------------------------------

                for recipient in recipients:

                    try:

                        send_one(
                            smtp=smtp,
                            sender=sender_info,
                            recipient=recipient,
                            subject=subject,
                            body=body,
                            html_mode=html_mode
                        )


                        sent += 1


                        yield packet(
                            "update",
                            email=recipient,
                            result="sent"
                        )


                    except Exception as error:

                        failed += 1


                        yield packet(
                            "update",
                            email=recipient,
                            result="failed",
                            error=str(error)
                        )


                    # ----------------------------------------
                    # OPTIONAL PACING
                    # ----------------------------------------

                    if (
                        MAIL_GAP_SECONDS > 0
                        and sent + failed < total
                    ):

                        time.sleep(
                            MAIL_GAP_SECONDS
                        )


            finally:

                try:
                    smtp.quit()
                except Exception:
                    pass


        except smtplib.SMTPAuthenticationError:

            yield packet(
                "fatal",
                message=(
                    "Gmail login failed. "
                    "Check the Gmail address and "
                    "Google App Password."
                )
            )

            return


        except smtplib.SMTPException as error:

            yield packet(
                "fatal",
                message=f"SMTP error: {error}"
            )

            return


        except Exception as error:

            yield packet(
                "fatal",
                message=f"Mail server error: {error}"
            )

            return


        yield packet(
            "complete",
            message="sending compleate Babu❤️"
        )


    return Response(
        mail_stream(),
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


@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "smtp": "gmail",
        "smtp_port": 465,
        "spintax": True,
        "max_recipients": MAX_RECIPIENTS
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

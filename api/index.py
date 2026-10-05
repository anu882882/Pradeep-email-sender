from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    session,
    Response,
    stream_with_context
)

from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

import os
import re
import ssl
import json
import random
import smtplib
import secrets
import urllib.request
import urllib.parse
import html


BASE_DIR = Path(__file__).resolve().parent.parent


app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static"
)


app.secret_key = os.environ.get(
    "SESSION_SECRET",
    ""
)


MAX_RECIPIENTS = 25

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 20


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
except ValueError:
    MAIL_GAP_SECONDS = 0.0


EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


SPINTAX_RE = re.compile(
    r"\{([^{}]+)\}"
)


TURNSTILE_SECRET_KEY = os.environ.get(
    "TURNSTILE_SECRET_KEY",
    ""
)


# ==========================================
# EMAIL VALIDATION
# ==========================================

def valid_email(value):
    return bool(
        EMAIL_RE.fullmatch(
            str(value or "").strip()
        )
    )


# ==========================================
# LOGIN
# ==========================================

def authenticated():
    return (
        session.get(
            "authenticated"
        ) is True
    )


# ==========================================
# SPINTAX
# ==========================================

def expand_spintax(text):
    text = str(text or "")

    def replace(match):
        choices = [
            item.strip()
            for item in match.group(1).split("|")
            if item.strip()
        ]

        if len(choices) < 2:
            return match.group(0)

        return random.choice(choices)

    for _ in range(10):

        updated = SPINTAX_RE.sub(
            replace,
            text
        )

        if updated == text:
            break

        text = updated

    return text


# ==========================================
# RECIPIENT CLEANUP
# ==========================================

def clean_recipients(raw):

    if not isinstance(raw, list):
        return []

    output = []
    seen = set()

    for item in raw:

        email = str(
            item or ""
        ).strip().lower()

        if not valid_email(email):
            continue

        if email in seen:
            continue

        seen.add(email)
        output.append(email)

    return output[:MAX_RECIPIENTS]


# ==========================================
# SIMPLE EMAIL HTML
# ==========================================

def text_to_simple_html(text):

    escaped = html.escape(
        str(text or "")
    )

    escaped = escaped.replace(
        "\r\n",
        "\n"
    ).replace(
        "\r",
        "\n"
    )

    escaped = escaped.replace(
        "\n",
        "<br>\n"
    )

    return f"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
</head>
<body style="
margin:0;
padding:0;
background:#ffffff;
color:#202124;
font-family:Arial,Helvetica,sans-serif;
font-size:15px;
line-height:1.55;
">
<div style="
margin:0;
padding:0;
">
{escaped}
</div>
</body>
</html>
"""


# ==========================================
# CLOUDFLARE TURNSTILE
# ==========================================

def verify_turnstile(
    token,
    remote_ip=None
):

    if not TURNSTILE_SECRET_KEY:

        return False, (
            "Turnstile is not configured."
        )

    if not token:

        return False, (
            "Please complete the security verification."
        )

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(
        payload
    ).encode("utf-8")

    request_obj = urllib.request.Request(
        "https://challenges.cloudflare.com/"
        "turnstile/v0/siteverify",
        data=encoded,
        headers={
            "Content-Type":
                "application/x-www-form-urlencoded"
        },
        method="POST"
    )

    try:

        with urllib.request.urlopen(
            request_obj,
            timeout=10
        ) as response:

            result = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )

        if result.get("success") is True:

            return True, None

        return False, (
            "Security verification failed."
        )

    except Exception:

        return False, (
            "Unable to verify security challenge."
        )


# ==========================================
# LOGIN
# ==========================================

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

        configured = os.environ.get(
            "LOGIN_PASSWORD",
            ""
        )

        if not configured:

            error = (
                "LOGIN_PASSWORD is not configured."
            )

        elif secrets.compare_digest(
            password,
            configured
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


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    if not authenticated():

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get(
            "TURNSTILE_SITE_KEY",
            ""
        )
    )


# ==========================================
# SEND BATCH
# ==========================================

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
            "body",
            ""
        )
    )


    recipients = clean_recipients(
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


    # --------------------------------------
    # REQUIRED FIELDS
    # --------------------------------------

    if not sender_name:

        return jsonify({
            "success": False,
            "message":
                "Sender Name is required."
        }), 400


    if not valid_email(gmail):

        return jsonify({
            "success": False,
            "message":
                "Enter a valid Gmail address."
        }), 400


    if not app_password:

        return jsonify({
            "success": False,
            "message":
                "Google App Password is required."
        }), 400


    if not subject:

        return jsonify({
            "success": False,
            "message":
                "Email Subject is required."
        }), 400


    if not body.strip():

        return jsonify({
            "success": False,
            "message":
                "Message Body is required."
        }), 400


    if not recipients:

        return jsonify({
            "success": False,
            "message":
                "No valid recipients found."
        }), 400


    # --------------------------------------
    # TURNSTILE
    # --------------------------------------

    remote_ip = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr
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


    # --------------------------------------
    # STREAMING SENDER
    # --------------------------------------

    @stream_with_context
    def generate():

        total = len(recipients)

        sent = 0

        failed = 0

        smtp = None


        def emit(
            event,
            **extra
        ):

            payload = {

                "event":
                    event,

                "total":
                    total,

                "sent":
                    sent,

                "failed":
                    failed,

                "remaining":
                    total - sent - failed

            }

            payload.update(extra)

            return (
                json.dumps(
                    payload,
                    ensure_ascii=False
                )
                + "\n"
            )


        yield emit(
            "started"
        )


        try:

            # ----------------------------------
            # ONE SMTP CONNECTION
            # ----------------------------------

            context = (
                ssl.create_default_context()
            )


            smtp = smtplib.SMTP_SSL(
                SMTP_HOST,
                SMTP_PORT,
                context=context,
                timeout=SMTP_TIMEOUT
            )


            smtp.ehlo()


            smtp.login(
                gmail,
                app_password
            )


            yield emit(
                "connected"
            )


            # ----------------------------------
            # SEND ONE BY ONE
            # ----------------------------------

            for recipient in recipients:

                try:

                    # New Spintax variation
                    # for every recipient.

                    final_subject = (
                        expand_spintax(
                            subject
                        )
                    )


                    final_body = (
                        expand_spintax(
                            body
                        )
                    )


                    plain_text = (
                        final_body
                    )


                    html_body = (
                        text_to_simple_html(
                            final_body
                        )
                    )


                    # Simple multipart email.

                    message = MIMEMultipart(
                        "alternative"
                    )


                    message["Subject"] = (
                        final_subject
                    )


                    message["From"] = (
                        formataddr(
                            (
                                sender_name,
                                gmail
                            )
                        )
                    )


                    message["To"] = (
                        recipient
                    )


                    message.attach(
                        MIMEText(
                            plain_text,
                            "plain",
                            "utf-8"
                        )
                    )


                    message.attach(
                        MIMEText(
                            html_body,
                            "html",
                            "utf-8"
                        )
                    )


                    smtp.sendmail(
                        gmail,
                        [recipient],
                        message.as_string()
                    )


                    sent += 1


                    yield emit(
                        "sent",
                        email=recipient
                    )


                except Exception as exc:

                    failed += 1


                    yield emit(
                        "failed",
                        email=recipient,
                        error=str(exc)
                    )


        except smtplib.SMTPAuthenticationError:

            yield emit(
                "error",
                message=(
                    "Gmail authentication failed. "
                    "Check the Gmail address and "
                    "App Password."
                )
            )

            return


        except smtplib.SMTPException as exc:

            yield emit(
                "error",
                message=f"SMTP error: {exc}"
            )

            return


        except Exception as exc:

            yield emit(
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


        yield emit(
            "complete",
            message="sending compleate Babu❤️"
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
                "no"
        }
    )


# ==========================================
# HEALTH
# ==========================================

@app.route("/health")
def health():

    return jsonify({

        "status":
            "ok",

        "mailer":
            "Gmail SMTP SSL",

        "spintax":
            "always-on",

        "email_format":
            "plain-text + simple-html",

        "max_recipients":
            MAX_RECIPIENTS

    })


# ==========================================
# LOCAL RUN
# ==========================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

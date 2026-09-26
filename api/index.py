import os
import re
import ssl
import smtplib
import time
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for
)

from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr


# =========================================================
# PROJECT PATHS
# =========================================================

API_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(API_DIR)

TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")


# =========================================================
# FLASK APP
# =========================================================

app = Flask(
    __name__,
    template_folder=TEMPLATES_DIR,
    static_folder=STATIC_DIR,
    static_url_path="/static"
)


# =========================================================
# SECURITY
# =========================================================

APP_LOGIN_PASSWORD = os.environ.get(
    "APP_LOGIN_PASSWORD",
    ""
)

SESSION_SECRET = os.environ.get(
    "SESSION_SECRET",
    ""
)

if not SESSION_SECRET:
    SESSION_SECRET = "temporary-session-secret-change-me"


app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_NAME="secure_mail_session"
)


# =========================================================
# SMTP
# =========================================================

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465


# =========================================================
# SENDING LIMITS
# =========================================================

MAX_RECIPIENTS = 25
SEND_DELAY_SECONDS = 1.0


# =========================================================
# EMAIL VALIDATION
# =========================================================

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def is_valid_email(email):
    return (
        EMAIL_PATTERN.fullmatch(
            str(email).strip()
        )
        is not None
    )


# =========================================================
# RECIPIENT PARSER
# =========================================================

def parse_recipients(raw_value):

    if not raw_value:
        return []

    normalized = (
        str(raw_value)
        .replace(",", "\n")
        .replace(";", "\n")
        .replace("\r", "\n")
    )

    recipients = []
    seen = set()

    for line in normalized.split("\n"):

        for item in line.split():

            email = item.strip().lower()

            if not email:
                continue

            if email in seen:
                continue

            seen.add(email)
            recipients.append(email)

    return recipients


# =========================================================
# LOGIN PROTECTION
# =========================================================

def login_required(view):

    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if not session.get("logged_in"):

            if request.path.startswith("/api/"):

                return jsonify({
                    "success": False,
                    "error": "Login required."
                }), 401

            return redirect(
                url_for("login")
            )

        return view(
            *args,
            **kwargs
        )

    return wrapped_view


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if session.get("logged_in"):

        return redirect(
            url_for("home")
        )


    if request.method == "POST":

        password = str(
            request.form.get(
                "password",
                ""
            )
        )


        if not APP_LOGIN_PASSWORD:

            return render_template(
                "login.html",
                error=(
                    "Login password is not configured."
                )
            )


        if password != APP_LOGIN_PASSWORD:

            return render_template(
                "login.html",
                error="Incorrect password."
            )


        session.clear()

        session["logged_in"] = True

        return redirect(
            url_for("home")
        )


    return render_template(
        "login.html"
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
@login_required
def home():

    return render_template(
        "index.html"
    )


# =========================================================
# HEALTH
# =========================================================

@app.route("/api/health")
@app.route("/health")
def health():

    return jsonify({
        "ok": True,
        "service": "Secure Mail Console"
    })


# =========================================================
# PROTECTION STATUS
# =========================================================

@app.route(
    "/api/protection",
    methods=["GET"]
)
@login_required
def protection():

    return jsonify({

        "active": True,

        "max_recipients":
            MAX_RECIPIENTS,

        "duplicate_filter":
            True,

        "invalid_email_filter":
            True,

        "controlled_rate":
            True,

        "smtp_error_protection":
            True,

        "fake_captcha":
            False,

        "access_key_required":
            False

    })


# =========================================================
# SEND EMAILS
# =========================================================

@app.route(
    "/api/send",
    methods=["POST"]
)
@login_required
def send_emails():

    data = request.get_json(
        silent=True
    )


    if not data:

        return jsonify({
            "success": False,
            "error": "Invalid request."
        }), 400


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
    ).strip()


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


    message = str(
        data.get(
            "message",
            ""
        )
    )


    raw_recipients = str(
        data.get(
            "recipients",
            ""
        )
    )


    # =====================================================
    # VALIDATION
    # =====================================================

    if not sender_name:

        return jsonify({
            "success": False,
            "error": "Please enter sender name."
        }), 400


    if not gmail:

        return jsonify({
            "success": False,
            "error": "Please enter Gmail address."
        }), 400


    if not is_valid_email(gmail):

        return jsonify({
            "success": False,
            "error": "Invalid Gmail address."
        }), 400


    if not app_password:

        return jsonify({
            "success": False,
            "error": "Please enter Gmail App Password."
        }), 400


    if not subject:

        return jsonify({
            "success": False,
            "error": "Please enter email subject."
        }), 400


    if not message.strip():

        return jsonify({
            "success": False,
            "error": "Please enter message body."
        }), 400


    # =====================================================
    # RECIPIENTS
    # =====================================================

    recipients = parse_recipients(
        raw_recipients
    )


    if not recipients:

        return jsonify({
            "success": False,
            "error": "No recipients found."
        }), 400


    # =====================================================
    # MAX 25
    # =====================================================

    if len(recipients) > MAX_RECIPIENTS:

        return jsonify({
            "success": False,
            "error": (
                "Maximum 25 recipients "
                "are allowed per send."
            )
        }), 400


    # =====================================================
    # INVALID EMAILS
    # =====================================================

    invalid = [
        email
        for email in recipients
        if not is_valid_email(email)
    ]


    if invalid:

        return jsonify({

            "success": False,

            "error":
                "Invalid email address(es).",

            "invalid":
                invalid

        }), 400


    # =====================================================
    # SMTP SEND
    # =====================================================

    sent = []
    failed = []


    ssl_context = ssl.create_default_context()


    try:

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=ssl_context,
            timeout=25
        ) as server:

            # Gmail authentication
            server.login(
                gmail,
                app_password
            )


            for index, recipient in enumerate(
                recipients
            ):

                try:

                    # {name} personalization
                    personalized_message = (
                        message.replace(
                            "{name}",
                            recipient.split("@")[0]
                        )
                    )


                    mail = MIMEText(
                        personalized_message,
                        "plain",
                        "utf-8"
                    )


                    mail["Subject"] = Header(
                        subject,
                        "utf-8"
                    )


                    mail["From"] = formataddr(
                        (
                            sender_name,
                            gmail
                        )
                    )


                    mail["To"] = recipient


                    server.sendmail(
                        gmail,
                        [recipient],
                        mail.as_string()
                    )


                    sent.append(
                        recipient
                    )


                    # Controlled sending interval
                    if (
                        index
                        < len(recipients) - 1
                    ):

                        time.sleep(
                            SEND_DELAY_SECONDS
                        )


                except Exception as exc:

                    failed.append({

                        "email":
                            recipient,

                        "error":
                            str(exc)

                    })


                    # Stop on SMTP errors
                    if isinstance(
                        exc,
                        smtplib.SMTPException
                    ):

                        break


    except smtplib.SMTPAuthenticationError:

        return jsonify({

            "success": False,

            "error": (
                "Gmail authentication failed. "
                "Use a valid Gmail App Password."
            )

        }), 401


    except smtplib.SMTPConnectError:

        return jsonify({

            "success": False,

            "error":
                "Could not connect to Gmail SMTP."

        }), 502


    except smtplib.SMTPException as exc:

        return jsonify({

            "success": False,

            "error":
                f"SMTP error: {str(exc)}"

        }), 502


    except Exception as exc:

        return jsonify({

            "success": False,

            "error":
                str(exc)

        }), 500


    # =====================================================
    # RESULT
    # =====================================================

    total = len(recipients)

    sent_count = len(sent)

    failed_count = len(failed)

    remaining = (
        total
        - sent_count
        - failed_count
    )


    return jsonify({

        "success":
            sent_count > 0,

        "total":
            total,

        "sent":
            sent_count,

        "failed":
            failed_count,

        "remaining":
            remaining,

        "sent_emails":
            sent,

        "failed_emails":
            failed

    })


# =========================================================
# RUN LOCALLY
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=False
    )

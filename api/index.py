import os
import re
import ssl
import smtplib
import time

from functools import wraps
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr, formatdate, make_msgid

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for
)


# =========================================================
# PATHS
# =========================================================

ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


app = Flask(
    __name__,
    template_folder=os.path.join(
        ROOT,
        "templates"
    ),
    static_folder=os.path.join(
        ROOT,
        "static"
    )
)


# =========================================================
# SECURITY
# =========================================================

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    "change-this-secret"
)


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax"
)


LOGIN_PASSWORD = os.environ.get(
    "APP_LOGIN_PASSWORD",
    ""
)


# =========================================================
# GMAIL SMTP
# =========================================================

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465


# =========================================================
# SEND LIMITS
# =========================================================

MAX_RECIPIENTS = 25

# Controlled pace.
# This is for responsible delivery,
# not for bypassing spam filters.
SEND_DELAY_SECONDS = 1.0


# =========================================================
# EMAIL VALIDATION
# =========================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(email):

    return bool(
        EMAIL_RE.fullmatch(
            str(email).strip()
        )
    )


# =========================================================
# RECIPIENT PARSER
# =========================================================

def parse_recipients(raw):

    raw = str(
        raw or ""
    )

    raw = (
        raw
        .replace(",", "\n")
        .replace(";", "\n")
        .replace("\r", "\n")
    )

    recipients = []
    seen = set()

    for line in raw.split("\n"):

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
    def wrapped(*args, **kwargs):

        if not session.get(
            "logged_in"
        ):

            if request.path.startswith(
                "/api/"
            ):

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

    return wrapped


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if session.get(
        "logged_in"
    ):

        return redirect(
            url_for("home")
        )


    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )


        if not LOGIN_PASSWORD:

            return render_template(
                "login.html",
                error=(
                    "APP_LOGIN_PASSWORD "
                    "is not configured."
                )
            )


        if password != LOGIN_PASSWORD:

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

@app.route(
    "/logout"
)
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

@app.route("/health")
@app.route("/api/health")
def health():

    return jsonify({
        "ok": True,
        "service": "Secure Mail Console"
    })


# =========================================================
# PROTECTION STATUS
# =========================================================

@app.route(
    "/api/protection"
)
@login_required
def protection():

    return jsonify({

        "active": True,

        "tls": True,

        "persistent_smtp": True,

        "rfc5322_headers": True,

        "duplicate_filter": True,

        "invalid_email_filter": True,

        "controlled_rate": True,

        "max_recipients":
            MAX_RECIPIENTS,

        "spam_bypass": False

    })


# =========================================================
# BUILD EMAIL
# =========================================================

def build_message(
    sender_name,
    sender_email,
    recipient,
    subject,
    body,
    unsubscribe_url=""
):

    personalized_body = body.replace(
        "{name}",
        recipient.split(
            "@",
            1
        )[0]
    )


    message = MIMEText(
        personalized_body,
        "plain",
        "utf-8"
    )


    # Standard email headers

    message["Date"] = formatdate(
        localtime=True
    )


    message["Message-ID"] = make_msgid()


    message["Subject"] = Header(
        subject,
        "utf-8"
    )


    # Authenticated Gmail account
    # remains the actual From address.

    message["From"] = formataddr(
        (
            sender_name,
            sender_email
        )
    )


    message["To"] = recipient


    message["Reply-To"] = sender_email


    # Only use this when the URL is
    # a real unsubscribe endpoint.

    if unsubscribe_url:

        message["List-Unsubscribe"] = (
            f"<{unsubscribe_url}>"
        )

        message["List-Unsubscribe-Post"] = (
            "List-Unsubscribe=One-Click"
        )


    return message


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


    unsubscribe_url = str(
        data.get(
            "unsubscribe_url",
            ""
        )
    ).strip()


    # =====================================================
    # VALIDATION
    # =====================================================

    if not sender_name:

        return jsonify({
            "success": False,
            "error":
                "Sender name required."
        }), 400


    if not valid_email(gmail):

        return jsonify({
            "success": False,
            "error":
                "Valid sender email required."
        }), 400


    if not app_password:

        return jsonify({
            "success": False,
            "error":
                "Gmail App Password required."
        }), 400


    if not subject:

        return jsonify({
            "success": False,
            "error":
                "Subject required."
        }), 400


    if not message.strip():

        return jsonify({
            "success": False,
            "error":
                "Message required."
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
            "error":
                "Add recipients."
        }), 400


    if len(recipients) > MAX_RECIPIENTS:

        return jsonify({
            "success": False,
            "error":
                f"Maximum "
                f"{MAX_RECIPIENTS} "
                f"recipients per send."
        }), 400


    invalid = [
        email
        for email in recipients
        if not valid_email(email)
    ]


    if invalid:

        return jsonify({

            "success": False,

            "error":
                "Invalid recipient "
                "email address.",

            "invalid":
                invalid

        }), 400


    # =====================================================
    # SMTP CONNECTION
    # =====================================================

    sent = []

    failed = []

    ssl_context = (
        ssl.create_default_context()
    )


    try:

        # One SMTP connection for the
        # complete sending job.

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=ssl_context,
            timeout=30
        ) as smtp:


            # Gmail authentication

            smtp.login(
                gmail,
                app_password
            )


            # =================================================
            # SEND RECIPIENTS
            # =================================================

            for index, recipient in enumerate(
                recipients
            ):

                try:

                    mail = build_message(
                        sender_name,
                        gmail,
                        recipient,
                        subject,
                        message,
                        unsubscribe_url
                    )


                    refused = smtp.sendmail(
                        gmail,
                        [recipient],
                        mail.as_string()
                    )


                    if refused:

                        failed.append({

                            "email":
                                recipient,

                            "error":
                                "SMTP rejected recipient."

                        })

                    else:

                        sent.append(
                            recipient
                        )


                except smtplib.SMTPException as exc:

                    failed.append({

                        "email":
                            recipient,

                        "error":
                            str(exc)

                    })

                    # Do not continuously retry
                    # an SMTP-level failure.

                    break


                except Exception as exc:

                    failed.append({

                        "email":
                            recipient,

                        "error":
                            str(exc)

                    })


                # Controlled pace between
                # individual messages.

                if (
                    index <
                    len(recipients) - 1
                ):

                    time.sleep(
                        SEND_DELAY_SECONDS
                    )


    # =====================================================
    # SMTP ERRORS
    # =====================================================

    except smtplib.SMTPAuthenticationError:

        return jsonify({

            "success": False,

            "error":
                "Gmail authentication failed. "
                "Check the App Password."

        }), 401


    except smtplib.SMTPConnectError:

        return jsonify({

            "success": False,

            "error":
                "Could not connect "
                "to Gmail SMTP."

        }), 502


    except smtplib.SMTPException as exc:

        return jsonify({

            "success": False,

            "error":
                f"SMTP error: {exc}"

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

    total = len(
        recipients
    )

    sent_count = len(
        sent
    )

    failed_count = len(
        failed
    )

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
            failed,

        "accepted_means":
            "SMTP accepted; "
            "Inbox placement is not verified."

    })


# =========================================================
# LOCAL SERVER
# =========================================================

if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=int(
            os.environ.get(
                "PORT",
                "5000"
            )
        ),

        debug=False
    )

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import smtplib
import ssl
import re
import os
import json
import urllib.request
import urllib.parse
import secrets
from email.mime.text import MIMEText
from email.utils import formataddr
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static"
)

app.secret_key = os.environ.get("SESSION_SECRET", "")

MAX_RECIPIENTS = 25

TURNSTILE_SECRET_KEY = os.environ.get(
    "TURNSTILE_SECRET_KEY",
    ""
)

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    return bool(
        EMAIL_RE.fullmatch(value.strip())
    )


def authenticated():
    return session.get("authenticated") is True


def verify_turnstile(token, remote_ip=None):

    if not TURNSTILE_SECRET_KEY:
        return False, "TURNSTILE_SECRET_KEY is not configured."

    if not token:
        return False, "Cloudflare verification is required."

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(
        payload
    ).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
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
                response.read().decode("utf-8")
            )

        if result.get("success") is True:
            return True, None

        return False, "Cloudflare verification failed."

    except Exception:
        return False, "Unable to verify Cloudflare."


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

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

        configured_password = os.environ.get(
            "LOGIN_PASSWORD",
            ""
        )

        if not configured_password:

            error = "LOGIN_PASSWORD is not configured."

        elif secrets.compare_digest(
            password,
            configured_password
        ):

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


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# --------------------------------------------------
# HOME
# --------------------------------------------------

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


# --------------------------------------------------
# GMAIL SMTP BATCH
# --------------------------------------------------

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

    body = str(
        data.get(
            "body",
            ""
        )
    )

    is_html = bool(
        data.get(
            "is_html",
            False
        )
    )

    recipients = data.get(
        "recipients",
        []
    )

    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    ).strip()


    # -----------------------------
    # VALIDATION
    # -----------------------------

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
            "message": "Subject is required."
        }), 400


    if not body.strip():

        return jsonify({
            "success": False,
            "message": "Message body is required."
        }), 400


    if not isinstance(
        recipients,
        list
    ):

        return jsonify({
            "success": False,
            "message": "Invalid recipient list."
        }), 400


    clean_recipients = []

    for item in recipients:

        email = str(
            item
        ).strip().lower()

        if not valid_email(email):
            continue

        if email not in clean_recipients:
            clean_recipients.append(email)


    clean_recipients = clean_recipients[
        :MAX_RECIPIENTS
    ]


    if not clean_recipients:

        return jsonify({
            "success": False,
            "message": "No valid recipients found."
        }), 400


    # -----------------------------
    # TURNSTILE
    # -----------------------------

    verified, verify_error = verify_turnstile(
        turnstile_token,
        request.headers.get(
            "X-Forwarded-For",
            request.remote_addr
        )
    )


    if not verified:

        return jsonify({
            "success": False,
            "message": verify_error
        }), 403


    sent = []
    failed = []


    # -----------------------------
    # ONE SMTP CONNECTION
    # -----------------------------

    context = ssl.create_default_context()


    try:

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=context,
            timeout=30
        ) as server:

            # Login once.
            server.login(
                gmail,
                app_password
            )


            # Send recipients sequentially
            # using the same SMTP connection.

            for recipient in clean_recipients:

                try:

                    content_type = (
                        "html"
                        if is_html
                        else "plain"
                    )


                    message = MIMEText(
                        body,
                        content_type,
                        "utf-8"
                    )


                    message["Subject"] = subject

                    message["From"] = formataddr(
                        (
                            sender_name,
                            gmail
                        )
                    )

                    message["To"] = recipient


                    server.sendmail(
                        gmail,
                        [recipient],
                        message.as_string()
                    )


                    sent.append(
                        recipient
                    )


                except Exception as exc:

                    failed.append({
                        "email": recipient,
                        "error": str(exc)
                    })


    except smtplib.SMTPAuthenticationError:

        return jsonify({
            "success": False,
            "message": (
                "Gmail authentication failed. "
                "Check Gmail address and Google App Password."
            )
        }), 401


    except smtplib.SMTPException as exc:

        return jsonify({
            "success": False,
            "message": (
                f"SMTP connection error: {str(exc)}"
            ),
            "sent": sent,
            "failed": failed,
            "sent_count": len(sent),
            "failed_count": len(failed),
            "remaining": (
                len(clean_recipients)
                - len(sent)
                - len(failed)
            )
        }), 500


    except Exception as exc:

        return jsonify({
            "success": False,
            "message": (
                f"Server error: {str(exc)}"
            ),
            "sent": sent,
            "failed": failed,
            "sent_count": len(sent),
            "failed_count": len(failed),
            "remaining": (
                len(clean_recipients)
                - len(sent)
                - len(failed)
            )
        }), 500


    # -----------------------------
    # RESULT
    # -----------------------------

    return jsonify({

        "success": True,

        "message": (
            f"Batch completed: "
            f"{len(sent)} sent, "
            f"{len(failed)} failed."
        ),

        "total":
            len(clean_recipients),

        "sent":
            sent,

        "failed":
            failed,

        "sent_count":
            len(sent),

        "failed_count":
            len(failed),

        "remaining":
            0

    })


# --------------------------------------------------
# HEALTH
# --------------------------------------------------

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "Secure Mail Console",
        "mailer": "Gmail SMTP"
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

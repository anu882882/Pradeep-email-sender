import os
import re
import ssl
import smtplib
import time

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify
)
from email.mime.text import MIMEText
from email.utils import formataddr


app = Flask(__name__)

# =========================================================
# LOGIN SETTINGS
# =========================================================

# Requested login password
# Vercel Environment Variable can override this value.
APP_LOGIN_PASSWORD = os.environ.get(
    "APP_LOGIN_PASSWORD",
    "Love882@#"
)

# Use a strong SESSION_SECRET in Vercel.
SESSION_SECRET = os.environ.get(
    "SESSION_SECRET",
    "change-this-session-secret-before-production"
)

app.secret_key = SESSION_SECRET

# Cookie settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# HTTPS on Vercel
if os.environ.get("VERCEL"):
    app.config["SESSION_COOKIE_SECURE"] = True
else:
    app.config["SESSION_COOKIE_SECURE"] = False


# =========================================================
# EMAIL SETTINGS
# =========================================================

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

MAX_RECIPIENTS = 25

# Delay between emails
SEND_DELAY_SECONDS = 1.0

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


# =========================================================
# HELPERS
# =========================================================

def is_valid_email(email):
    return EMAIL_PATTERN.fullmatch(email) is not None


def parse_recipients(raw_value):
    """
    Accept:
      email1@gmail.com
      email2@gmail.com, email3@gmail.com
      email4@gmail.com;email5@gmail.com

    Returns unique emails in first-seen order.
    """

    if not raw_value:
        return []

    normalized = re.sub(
        r"[,;\s]+",
        "\n",
        raw_value
    )

    recipients = []
    seen = set()

    for item in normalized.splitlines():

        email = item.strip().lower()

        if not email:
            continue

        if email not in seen:
            seen.add(email)
            recipients.append(email)

    return recipients


def login_required():
    return session.get("logged_in") is True


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if login_required():
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        if password == APP_LOGIN_PASSWORD:

            session.clear()
            session["logged_in"] = True

            return redirect(url_for("home"))

        error = "Incorrect password."

    return render_template(
        "login.html",
        error=error
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if not login_required():
        return redirect(url_for("login"))

    return render_template("index.html")


# =========================================================
# PROTECTION STATUS
# =========================================================

@app.route("/api/protection")
def protection():

    if not login_required():
        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    return jsonify({
        "ok": True,
        "active": True,
        "max_recipients": MAX_RECIPIENTS,
        "duplicate_filter": True,
        "invalid_email_filter": True,
        "controlled_rate": True,
        "smtp_error_protection": True,
        "fake_captcha": False,
        "access_key": False
    })


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/api/health")
def health():

    return jsonify({
        "ok": True,
        "service": "Secure Mail Console"
    })


# =========================================================
# SEND EMAIL
# =========================================================

@app.route("/api/send", methods=["POST"])
def send_email():

    if not login_required():
        return jsonify({
            "ok": False,
            "error": "Session expired. Please login again."
        }), 401

    data = request.get_json(silent=True)

    if not data:
        data = request.form

    sender_name = str(
        data.get("sender_name", "")
    ).strip()

    gmail = str(
        data.get("gmail", "")
    ).strip().lower()

    app_password = str(
        data.get("app_password", "")
    ).strip()

    subject = str(
        data.get("subject", "")
    ).strip()

    message = str(
        data.get("message", "")
    )

    recipients_raw = data.get(
        "recipients",
        ""
    )

    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not sender_name:
        return jsonify({
            "ok": False,
            "error": "Sender name is required."
        }), 400

    if not gmail:
        return jsonify({
            "ok": False,
            "error": "Gmail address is required."
        }), 400

    if not is_valid_email(gmail):
        return jsonify({
            "ok": False,
            "error": "Enter a valid Gmail address."
        }), 400

    if not app_password:
        return jsonify({
            "ok": False,
            "error": "Gmail App Password is required."
        }), 400

    if not subject:
        return jsonify({
            "ok": False,
            "error": "Subject is required."
        }), 400

    if not message.strip():
        return jsonify({
            "ok": False,
            "error": "Message body is required."
        }), 400

    # -----------------------------------------------------
    # RECIPIENTS
    # -----------------------------------------------------

    recipients = parse_recipients(
        recipients_raw
    )

    if not recipients:
        return jsonify({
            "ok": False,
            "error": "Enter at least one recipient."
        }), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "ok": False,
            "error": (
                f"Maximum {MAX_RECIPIENTS} "
                "recipients are allowed per send."
            )
        }), 400

    invalid = [
        email
        for email in recipients
        if not is_valid_email(email)
    ]

    if invalid:
        return jsonify({
            "ok": False,
            "error": "Invalid email address detected.",
            "invalid": invalid
        }), 400

    # -----------------------------------------------------
    # SMTP CONNECTION
    # -----------------------------------------------------

    sent = []
    failed = []

    try:

        ssl_context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=ssl_context,
            timeout=30
        ) as server:

            # Gmail authentication
            server.login(
                gmail,
                app_password
            )

            # -------------------------------------------------
            # SEND ONE EMAIL AT A TIME
            # -------------------------------------------------

            for index, recipient in enumerate(recipients):

                # Simple personalization:
                # john@gmail.com -> John
                local_part = recipient.split("@")[0]

                name = local_part.replace(
                    ".",
                    " "
                ).replace(
                    "_",
                    " "
                ).replace(
                    "-",
                    " "
                ).strip()

                if name:
                    name = name.title()

                personalized_message = message.replace(
                    "{name}",
                    name
                )

                msg = MIMEText(
                    personalized_message,
                    "plain",
                    "utf-8"
                )

                msg["Subject"] = subject

                msg["From"] = formataddr((
                    sender_name,
                    gmail
                ))

                msg["To"] = recipient

                try:

                    server.sendmail(
                        gmail,
                        [recipient],
                        msg.as_string()
                    )

                    sent.append(recipient)

                except Exception as send_error:

                    failed.append({
                        "email": recipient,
                        "error": str(send_error)
                    })

                    # Stop if SMTP starts rejecting requests
                    break

                # Controlled delay
                if index < len(recipients) - 1:
                    time.sleep(
                        SEND_DELAY_SECONDS
                    )

    except smtplib.SMTPAuthenticationError:

        return jsonify({
            "ok": False,
            "error": (
                "Gmail authentication failed. "
                "Use your Gmail App Password, "
                "not your normal Gmail password."
            )
        }), 401

    except smtplib.SMTPException as error:

        return jsonify({
            "ok": False,
            "error": f"SMTP error: {str(error)}"
        }), 502

    except TimeoutError:

        return jsonify({
            "ok": False,
            "error": "SMTP connection timed out."
        }), 504

    except Exception as error:

        return jsonify({
            "ok": False,
            "error": f"Server error: {str(error)}"
        }), 500

    # -----------------------------------------------------
    # RESULT
    # -----------------------------------------------------

    remaining = len(recipients) - len(sent) - len(failed)

    return jsonify({
        "ok": True,
        "total": len(recipients),
        "sent": len(sent),
        "failed": len(failed),
        "remaining": max(0, remaining),
        "sent_to": sent,
        "failed_items": failed
    })


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )

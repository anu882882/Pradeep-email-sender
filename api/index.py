import os
import re
import ssl
import smtplib

from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr

from flask import Flask, render_template, request, jsonify


BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)


# =========================================================
# SETTINGS
# =========================================================

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

# Maximum recipients per send
MAX_RECIPIENTS = 25


EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


# =========================================================
# EMAIL VALIDATION
# =========================================================

def is_valid_email(email):
    return (
        EMAIL_PATTERN.fullmatch(
            email.strip()
        ) is not None
    )


# =========================================================
# RECIPIENT PARSER
# =========================================================

def parse_recipients(raw_value):

    if not raw_value:
        return []

    normalized = (
        raw_value
        .replace(",", "\n")
        .replace(";", "\n")
        .replace("\r", "\n")
    )

    recipients = []
    seen = set()

    for line in normalized.split("\n"):

        parts = line.split()

        for part in parts:

            email = part.strip().lower()

            if not email:
                continue

            if email not in seen:

                seen.add(email)
                recipients.append(email)

    return recipients


# =========================================================
# NAME FROM EMAIL
# =========================================================

def display_name_from_email(email):

    local_part = email.split("@", 1)[0]

    local_part = re.sub(
        r"[._-]+",
        " ",
        local_part
    )

    local_part = re.sub(
        r"\d+",
        " ",
        local_part
    )

    local_part = " ".join(
        local_part.split()
    ).strip()

    if not local_part:
        return "there"

    return local_part.title()


# =========================================================
# PERSONALIZATION
# =========================================================

def personalize_message(message, recipient):

    name = display_name_from_email(
        recipient
    )

    return message.replace(
        "{name}",
        name
    )


# =========================================================
# HOME
# =========================================================

@app.route("/", methods=["GET"])
def home():

    return render_template(
        "index.html"
    )


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "ok",
        "service": "Secure Mail Console"
    })


# =========================================================
# SEND EMAILS
# =========================================================

@app.route("/api/send", methods=["POST"])
def send_emails():

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({
            "success": False,
            "error": "Invalid request."
        }), 400


    # -----------------------------------------------------
    # FORM DATA
    # -----------------------------------------------------

    sender_name = str(
        data.get("sender_name", "")
    ).strip()

    gmail = str(
        data.get("gmail", "")
    ).strip()

    app_password = str(
        data.get("app_password", "")
    ).strip()

    subject = str(
        data.get("subject", "")
    ).strip()

    message = str(
        data.get("message", "")
    )

    raw_recipients = str(
        data.get("recipients", "")
    )


    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not sender_name:

        return jsonify({
            "success": False,
            "error": "Please enter sender name."
        }), 400


    if not gmail:

        return jsonify({
            "success": False,
            "error": "Please enter your Gmail address."
        }), 400


    if not is_valid_email(gmail):

        return jsonify({
            "success": False,
            "error": "Please enter a valid Gmail address."
        }), 400


    if not app_password:

        return jsonify({
            "success": False,
            "error": "Please enter your Gmail App Password."
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


    # -----------------------------------------------------
    # RECIPIENTS
    # -----------------------------------------------------

    recipients = parse_recipients(
        raw_recipients
    )


    if not recipients:

        return jsonify({
            "success": False,
            "error": "Please enter at least one recipient."
        }), 400


    # -----------------------------------------------------
    # MAXIMUM 25 RECIPIENTS
    # -----------------------------------------------------

    if len(recipients) > MAX_RECIPIENTS:

        return jsonify({
            "success": False,
            "error": (
                "Maximum 25 recipients "
                "are allowed per send."
            )
        }), 400


    # -----------------------------------------------------
    # INVALID EMAILS
    # -----------------------------------------------------

    invalid = [
        email
        for email in recipients
        if not is_valid_email(email)
    ]


    if invalid:

        return jsonify({
            "success": False,
            "error": "Invalid email address(es).",
            "invalid": invalid
        }), 400


    # -----------------------------------------------------
    # SMTP
    # -----------------------------------------------------

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

            server.login(
                gmail,
                app_password
            )


            # ---------------------------------------------
            # SEND ONE BY ONE
            # ---------------------------------------------

            for recipient in recipients:

                try:

                    personalized_message = (
                        personalize_message(
                            message,
                            recipient
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


                except Exception as exc:

                    failed.append({
                        "email": recipient,
                        "error": str(exc)
                    })


    except smtplib.SMTPAuthenticationError:

        return jsonify({
            "success": False,
            "error": (
                "Gmail authentication failed. "
                "Use a Gmail App Password instead "
                "of your normal Gmail password."
            )
        }), 401


    except smtplib.SMTPConnectError:

        return jsonify({
            "success": False,
            "error": (
                "Could not connect to Gmail SMTP."
            )
        }), 502


    except smtplib.SMTPException as exc:

        return jsonify({
            "success": False,
            "error": f"SMTP error: {str(exc)}"
        }), 502


    except Exception as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


    # -----------------------------------------------------
    # RESULT
    # -----------------------------------------------------

    total = len(recipients)
    sent_count = len(sent)
    failed_count = len(failed)

    remaining = (
        total
        - sent_count
        - failed_count
    )


    return jsonify({

        "success": sent_count > 0,

        "total": total,

        "sent": sent_count,

        "failed": failed_count,

        "remaining": remaining,

        "sent_emails": sent,

        "failed_emails": failed

    })


# =========================================================
# LOCAL DEVELOPMENT
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
        debug=True
    )

import os
import re
import ssl
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr

from flask import Flask, render_template, request, jsonify


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)


# ---------------------------------------------------------
# SETTINGS
# ---------------------------------------------------------

MAX_RECIPIENTS = 5
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def is_valid_email(email):
    return EMAIL_PATTERN.fullmatch(email.strip()) is not None


def parse_recipients(raw_value):
    """
    Accept:
      email1@gmail.com
      email2@gmail.com,email3@gmail.com
      email4@gmail.com;email5@gmail.com
    """

    if not raw_value:
        return []

    normalized = (
        raw_value
        .replace(",", "\n")
        .replace(";", "\n")
        .replace("\r", "\n")
    )

    results = []
    seen = set()

    for line in normalized.split("\n"):
        email = line.strip().lower()

        if not email:
            continue

        # Also handle accidental spaces
        pieces = email.split()

        for piece in pieces:
            if piece not in seen:
                seen.add(piece)
                results.append(piece)

    return results


def display_name_from_email(email):
    """
    Example:
    john.smith@gmail.com
    -> John Smith
    """

    local = email.split("@", 1)[0]

    local = re.sub(r"[._-]+", " ", local)
    local = re.sub(r"\d+", " ", local)

    local = " ".join(local.split()).strip()

    if not local:
        return "there"

    return local.title()


def render_personalized_text(text, recipient):
    """
    Supports:

    {name}

    Example:
    Hello {name},

    becomes:

    Hello John,
    """

    name = display_name_from_email(recipient)

    return text.replace("{name}", name)


def check_access_key():
    """
    Protect the public Vercel endpoint.

    Set APP_ACCESS_KEY in Vercel Environment Variables.
    """

    configured_key = os.environ.get("APP_ACCESS_KEY", "").strip()

    # If no key is configured, allow access.
    # You can change this to return False if you want
    # access key to be mandatory.
    if not configured_key:
        return True

    supplied_key = (
        request.headers.get("X-Access-Key")
        or request.form.get("access_key")
        or ""
    ).strip()

    return supplied_key == configured_key


# ---------------------------------------------------------
# PAGES
# ---------------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "Secure Mail Console"
    })


# ---------------------------------------------------------
# SEND EMAILS
# ---------------------------------------------------------

@app.route("/api/send", methods=["POST"])
def send_emails():

    # -----------------------------------------------------
    # ACCESS KEY
    # -----------------------------------------------------

    if not check_access_key():
        return jsonify({
            "success": False,
            "error": "Invalid access key."
        }), 401


    # -----------------------------------------------------
    # JSON
    # -----------------------------------------------------

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "error": "Invalid request."
        }), 400


    sender_name = str(data.get("sender_name", "")).strip()
    gmail = str(data.get("gmail", "")).strip()
    app_password = str(data.get("app_password", "")).strip()
    subject = str(data.get("subject", "")).strip()
    message = str(data.get("message", ""))

    raw_recipients = str(data.get("recipients", ""))


    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not sender_name:
        return jsonify({
            "success": False,
            "error": "Please enter sender name."
        }), 400


    if not gmail or not is_valid_email(gmail):
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


    recipients = parse_recipients(raw_recipients)


    if not recipients:
        return jsonify({
            "success": False,
            "error": "Please enter at least one recipient."
        }), 400


    # -----------------------------------------------------
    # LIMIT
    # -----------------------------------------------------

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "success": False,
            "error": (
                f"Maximum {MAX_RECIPIENTS} recipients are allowed "
                "per send."
            )
        }), 400


    invalid = [
        email for email in recipients
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

    context = ssl.create_default_context()

    try:

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=25
        ) as server:

            server.login(gmail, app_password)

            for recipient in recipients:

                try:

                    personalized_message = render_personalized_text(
                        message,
                        recipient
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
                        (sender_name, gmail)
                    )

                    mail["To"] = recipient

                    server.sendmail(
                        gmail,
                        [recipient],
                        mail.as_string()
                    )

                    sent.append(recipient)

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
                "Use your Gmail App Password, not your normal "
                "Gmail password."
            )
        }), 401


    except smtplib.SMTPConnectError:

        return jsonify({
            "success": False,
            "error": "Could not connect to Gmail SMTP."
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


    return jsonify({
        "success": len(sent) > 0,
        "total": len(recipients),
        "sent": len(sent),
        "failed": len(failed),
        "remaining": len(recipients) - len(sent) - len(failed),
        "sent_emails": sent,
        "failed_emails": failed
    })


# ---------------------------------------------------------
# VERCEL ENTRY
# ---------------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=True
    )

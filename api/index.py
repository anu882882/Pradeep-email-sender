
import os
import re
import ssl
import smtplib
import html
import logging

from concurrent.futures import ThreadPoolExecutor
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from email.header import Header

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
)

# --------------------------------------------------
# APP CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()

if os.environ.get("VERCEL") and not SESSION_SECRET:
    raise RuntimeError(
        "SESSION_SECRET is missing. Add it in Vercel Environment Variables."
    )

app.secret_key = SESSION_SECRET or "local-development-secret-change-before-deploy"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("COOKIE_SECURE", "true").lower() == "true"
    ),
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
)

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()

MAX_RECIPIENTS = 25
BATCH_SIZE = 5
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 30

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

EMAIL_PATTERN = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$",
    re.IGNORECASE,
)

ALLOWED_FONTS = {
    "Arial": "Arial, Helvetica, sans-serif",
    "Arial Black": "Arial Black, Arial, sans-serif",
    "Calibri": "Calibri, Arial, sans-serif",
    "Cambria": "Cambria, Georgia, serif",
    "Courier New": "'Courier New', monospace",
    "Georgia": "Georgia, serif",
    "Helvetica": "Helvetica, Arial, sans-serif",
    "Tahoma": "Tahoma, sans-serif",
    "Times New Roman": "'Times New Roman', serif",
    "Trebuchet MS": "'Trebuchet MS', sans-serif",
    "Verdana": "Verdana, sans-serif",
    "Garamond": "Garamond, serif",
    "Palatino": "'Palatino Linotype', Palatino, serif",
    "Impact": "Impact, sans-serif",
    "Lucida Console": "'Lucida Console', monospace",
}


# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def is_valid_email(address):
    address = (address or "").strip()
    return bool(EMAIL_PATTERN.fullmatch(address))


def parse_recipients(raw_value):
    """
    Accepts newline/comma/semicolon separated addresses.
    Also accepts: Display Name <person@example.com>
    """
    if isinstance(raw_value, list):
        raw_items = raw_value
    else:
        raw_items = re.split(r"[\n,;]+", str(raw_value or ""))

    recipients = []
    seen = set()

    for item in raw_items:
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            address = str(item.get("email", "")).strip()
        else:
            item = str(item).strip()
            if not item:
                continue

            name, address = "", item

            if "<" in item and ">" in item:
                left, right = item.rsplit("<", 1)
                name = left.strip().strip('"')
                address = right.split(">", 1)[0].strip()

        address = address.strip().lower()

        if not is_valid_email(address):
            continue

        if address in seen:
            continue

        seen.add(address)
        recipients.append({
            "name": name,
            "email": address,
        })

    return recipients


def personalize_text(text, recipient, is_html=False):
    name = recipient.get("name") or recipient["email"].split("@")[0]
    email_address = recipient["email"]

    if is_html:
        name = html.escape(name)
        email_address = html.escape(email_address)

    return (
        str(text)
        .replace("{{name}}", name)
        .replace("{{email}}", email_address)
    )


def build_message(
    sender_name,
    sender_email,
    recipient,
    subject,
    body,
    is_html,
    font_family,
):
    message_body = personalize_text(body, recipient, is_html)

    if is_html:
        safe_font = ALLOWED_FONTS.get(font_family, ALLOWED_FONTS["Arial"])
        message_body = (
            '<div style="font-family:'
            + safe_font
            + ';">'
            + message_body
            + "</div>"
        )

    message = MIMEText(
        message_body,
        "html" if is_html else "plain",
        "utf-8",
    )

    message["Subject"] = str(Header(subject, "utf-8"))
    message["From"] = formataddr((sender_name, sender_email))
    message["To"] = recipient["email"]
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    return message


def send_one_email(
    sender_name,
    sender_email,
    app_password,
    recipient,
    subject,
    body,
    is_html,
    font_family,
):
    try:
        message = build_message(
            sender_name,
            sender_email,
            recipient,
            subject,
            body,
            is_html,
            font_family,
        )

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=SMTP_TIMEOUT,
        ) as smtp:
            smtp.login(sender_email, app_password)
            smtp.send_message(
                message,
                from_addr=sender_email,
                to_addrs=[recipient["email"]],
            )

        return {
            "success": True,
            "email": recipient["email"],
            "message": f"Accepted by Gmail: {recipient['email']}",
        }

    except smtplib.SMTPAuthenticationError:
        return {
            "success": False,
            "email": recipient["email"],
            "message": (
                f"Gmail authentication failed for {recipient['email']}. "
                "Check your Gmail address and App Password."
            ),
        }

    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        logger.warning("SMTP error for %s: %s", recipient["email"], exc)
        return {
            "success": False,
            "email": recipient["email"],
            "message": f"Sending failed for {recipient['email']}: {str(exc)}",
        }

    except Exception:
        logger.exception("Unexpected email error")
        return {
            "success": False,
            "email": recipient["email"],
            "message": f"Unexpected error while sending to {recipient['email']}.",
        }


def login_required():
    return bool(session.get("logged_in"))


def error_response(message, status=400):
    return jsonify({"success": False, "error": message}), status


# --------------------------------------------------
# ROUTES
# --------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    if not login_required():
        return redirect(url_for("login"))

    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if login_required():
            return redirect(url_for("index"))
        return render_template("login.html")

    if not LOGIN_PASSWORD:
        return render_template(
            "login.html",
            error="LOGIN_PASSWORD is not configured on the server.",
        ), 500

    entered_password = request.form.get("password", "")

    if entered_password and entered_password == LOGIN_PASSWORD:
        session.clear()
        session["logged_in"] = True
        session.permanent = True
        return redirect(url_for("index"))

    return render_template(
        "login.html",
        error="Incorrect password. Please try again.",
    ), 401


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/send", methods=["POST"])
def send():
    if not login_required():
        return error_response(
            "Your login session has expired. Please log in again.",
            401,
        )

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        data = request.form.to_dict()

    sender_name = str(
        data.get("sender_name", data.get("name", ""))
    ).strip()

    sender_email = str(
        data.get("sender_email", data.get("gmail", ""))
    ).strip().lower()

    app_password = str(
        data.get("app_password", data.get("password", ""))
    ).replace(" ", "").strip()

    subject = str(data.get("subject", "")).strip()
    body = str(
        data.get("body", data.get("message_body", ""))
    )

    raw_recipients = data.get(
        "recipients",
        data.get("recipient_emails", data.get("emails", "")),
    )

    is_html = str(
        data.get("is_html", data.get("html", False))
    ).lower() in ("true", "1", "yes", "on")

    consent = str(
        data.get("consent", data.get("recipient_consent", False))
    ).lower() in ("true", "1", "yes", "on")

    font_family = str(data.get("font_family", "Arial")).strip()
    if font_family not in ALLOWED_FONTS:
        font_family = "Arial"

    if not all((sender_name, sender_email, app_password, subject, body.strip())):
        return error_response("Please complete all required fields.")

    if not is_valid_email(sender_email):
        return error_response("Please enter a valid sender email address.")

    if not sender_email.endswith("@gmail.com"):
        return error_response("Please use a Gmail address for SMTP sending.")

    if not consent:
        return error_response(
            "Please confirm that all recipients agreed to receive your email."
        )

    recipients = parse_recipients(raw_recipients)

    if not recipients:
        return error_response("No valid recipient email addresses were found.")

    if len(recipients) > MAX_RECIPIENTS:
        return error_response(
            f"Maximum {MAX_RECIPIENTS} unique recipients are allowed."
        )

    results = []

    # Send in groups of five. Each group finishes before the next starts.
    for start in range(0, len(recipients), BATCH_SIZE):
        batch = recipients[start:start + BATCH_SIZE]

        with ThreadPoolExecutor(max_workers=BATCH_SIZE) as executor:
            futures = [
                executor.submit(
                    send_one_email,
                    sender_name,
                    sender_email,
                    app_password,
                    recipient,
                    subject,
                    body,
                    is_html,
                    font_family,
                )
                for recipient in batch
            ]

            for future in futures:
                try:
                    results.append(future.result())
                except Exception:
                    logger.exception("Batch worker failed")
                    results.append({
                        "success": False,
                        "email": "",
                        "message": "A sending worker failed unexpectedly.",
                    })

    sent_count = sum(1 for item in results if item["success"])
    failed_count = len(results) - sent_count

    return jsonify({
        "success": failed_count == 0,
        "total": len(recipients),
        "sent": sent_count,
        "failed": failed_count,
        "results": results,
        "message": (
            f"Completed: {sent_count} accepted by Gmail, "
            f"{failed_count} failed."
        ),
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# Vercel uses this Flask application object.

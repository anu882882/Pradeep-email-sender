
import os
import re
import ssl
import time
import html
import secrets
import random
import smtplib
from datetime import datetime
from zoneinfo import ZoneInfo
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from email.header import Header
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)


# --------------------------------------------------
# APP CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

app.secret_key = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)

app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))

MAIL_GAP_SECONDS = max(
    0.0,
    min(float(os.environ.get("MAIL_GAP_SECONDS", "1")), 10.0)
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

IST = ZoneInfo("Asia/Kolkata")


# --------------------------------------------------
# LOGIN CHECK
# --------------------------------------------------

def logged_in():
    return session.get("logged_in") is True


# --------------------------------------------------
# SPINTAX PROCESSOR
# --------------------------------------------------

def process_spintax(text):
    if not text:
        return ""

    pattern = re.compile(r"\{([^{}]+)\}")

    while True:
        match = pattern.search(text)

        if not match:
            break

        choices = match.group(1).split("|")
        selected = secrets.choice(choices)

        text = (
            text[:match.start()]
            + selected
            + text[match.end():]
        )

    return text


# --------------------------------------------------
# HTML TO TEXT CONVERTER
# --------------------------------------------------

from html.parser import HTMLParser


class HTMLTextExtractor(HTMLParser):

    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        value = data.strip()

        if value:
            self.parts.append(value)

    def get_text(self):
        return "\n".join(self.parts)


def get_plain_text(body, html_mode):
    if not html_mode:
        return body

    parser = HTMLTextExtractor()

    try:
        parser.feed(body)
        return parser.get_text()
    except Exception:
        return body


# --------------------------------------------------
# SMTP CONNECTION
# --------------------------------------------------

def open_smtp_connection(sender_email, app_password):

    if SMTP_PORT == 465:
        server = smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=25,
            context=ssl.create_default_context()
        )
    else:
        server = smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT,
            timeout=25
        )

        server.ehlo()
        server.starttls(context=ssl.create_default_context())
        server.ehlo()

    server.login(sender_email, app_password)

    return server


# --------------------------------------------------
# ORIGINAL EMAIL DETAILS FOR REPLY
# --------------------------------------------------

def create_reply_details(
    sender_email,
    recipient_email,
    sender_name,
    subject,
    original_body,
    html_mode,
    sent_time,
    message_id
):

    formatted_date = sent_time.strftime("%d %b %Y")
    formatted_time = sent_time.strftime("%I:%M:%S %p IST")

    original_text = get_plain_text(original_body, html_mode)

    details = (
        "\n\n"
        "----------------------------------------\n"
        "ORIGINAL EMAIL DETAILS\n"
        "----------------------------------------\n"
        f"From: {sender_name} <{sender_email}>\n"
        f"To: {recipient_email}\n"
        f"Date: {formatted_date}\n"
        f"Time: {formatted_time}\n"
        f"Subject: {subject}\n"
        f"Message-ID: {message_id}\n"
        "\n"
        "ORIGINAL MESSAGE:\n"
        "----------------------------------------\n"
        f"{original_text}\n"
        "----------------------------------------\n"
        "\n"
        "YOUR REPLY:\n"
    )

    return details


# --------------------------------------------------
# CREATE EMAIL WITH REPLY BUTTONS
# --------------------------------------------------

def create_message(
    sender_email,
    recipient_email,
    sender_name,
    subject,
    body,
    html_mode
):

    sent_time = datetime.now(IST)

    # A unique ID for this individual email
    message_id = make_msgid()

    # Process Spintax separately for each recipient
    final_subject = process_spintax(subject)
    final_body = process_spintax(body)

    reply_details = create_reply_details(
        sender_email=sender_email,
        recipient_email=recipient_email,
        sender_name=sender_name,
        subject=final_subject,
        original_body=final_body,
        html_mode=html_mode,
        sent_time=sent_time,
        message_id=message_id
    )

    reply_options = [
        "Yes, please do.",
        "Yes, of course you can.",
        "Yes, that would be fine."
    ]

    # Plain text version
    plain_original = get_plain_text(final_body, html_mode)

    plain_message = plain_original

    plain_message += "\n\n"
    plain_message += "----------------------------------------\n"
    plain_message += "QUICK REPLY OPTIONS\n"
    plain_message += "----------------------------------------\n"

    for option in reply_options:
        plain_message += f"\n{option}"

    plain_message += (
        "\n\n"
        "Click a reply option in the HTML version "
        "to prepare your response.\n"
    )

    # HTML original message
    if html_mode:
        original_html = final_body
    else:
        original_html = (
            "<div style='white-space:pre-wrap;'>"
            + html.escape(final_body)
            + "</div>"
        )

    # Create HTML reply buttons
    buttons_html = ""

    for option in reply_options:

        reply_subject = "Re: " + final_subject

        mailto_body = option + reply_details

        mailto_link = (
            "mailto:"
            + recipient_email
            + "?subject="
            + __import__("urllib.parse", fromlist=["quote"]).quote(
                reply_subject
            )
            + "&body="
            + __import__("urllib.parse", fromlist=["quote"]).quote(
                mailto_body
            )
        )

        buttons_html += f"""
        <a href="{html.escape(mailto_link, quote=True)}"
           style="
             display:inline-block;
             margin:5px 5px 5px 0;
             padding:10px 16px;
             background:#ffffff;
             border:1px solid #cbd5e1;
             border-radius:7px;
             color:#2563eb;
             font-family:Arial,sans-serif;
             font-size:13px;
             text-decoration:none;
           ">
           {html.escape(option)}
        </a>
        """

    html_message = f"""
    <html>
    <body style="
        margin:0;
        padding:20px;
        color:#1f2937;
        font-family:Arial,sans-serif;
        font-size:14px;
        line-height:1.6;
    ">

        <div>
            {original_html}
        </div>

        <div style="
            margin-top:25px;
            padding-top:18px;
            border-top:1px solid #e5e7eb;
        ">

            <p style="font-weight:bold;margin-bottom:12px;">
                Quick reply
            </p>

            {buttons_html}

            <p style="
                color:#64748b;
                font-size:12px;
                margin-top:12px;
            ">
                Select an option to prepare your reply with
                the original email details included.
            </p>

        </div>

    </body>
    </html>
    """

    # Build email
    message = EmailMessage()

    message["From"] = formataddr((sender_name, sender_email))
    message["To"] = recipient_email
    message["Subject"] = str(Header(final_subject, "utf-8"))
    message["Date"] = sent_time.strftime("%a, %d %b %Y %H:%M:%S %z")
    message["Message-ID"] = message_id

    message.set_content(plain_message)
    message.add_alternative(html_message, subtype="html")

    return message, sent_time, final_subject


# --------------------------------------------------
# SEND BATCH USING ONE SMTP CONNECTION
# --------------------------------------------------

def send_batch_with_smtp(
    recipients,
    sender_email,
    app_password,
    sender_name,
    subject,
    body,
    html_mode
):

    results = []

    server = None

    try:
        server = open_smtp_connection(
            sender_email,
            app_password
        )

        for index, recipient in enumerate(recipients):

            try:

                message, sent_time, final_subject = create_message(
                    sender_email=sender_email,
                    recipient_email=recipient,
                    sender_name=sender_name,
                    subject=subject,
                    body=body,
                    html_mode=html_mode
                )

                server.send_message(message)

                results.append({
                    "email": recipient,
                    "status": "sent",
                    "detail": "Accepted by SMTP",
                    "date": sent_time.strftime("%d %b %Y"),
                    "time": sent_time.strftime("%I:%M:%S %p IST"),
                    "subject": final_subject
                })

            except smtplib.SMTPRecipientsRefused as error:

                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": str(error)
                })

            except (
                smtplib.SMTPException,
                OSError,
                TimeoutError
            ) as error:

                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": str(error)
                })

                # Connection may be unusable after an SMTP error.
                # Stop this batch rather than pretending later sends worked.
                for remaining in recipients[index + 1:]:
                    results.append({
                        "email": remaining,
                        "status": "failed",
                        "detail": "Batch stopped after SMTP connection error."
                    })

                break

            if index < len(recipients) - 1 and MAIL_GAP_SECONDS:
                time.sleep(MAIL_GAP_SECONDS)

    except Exception as error:

        results = [
            {
                "email": recipient,
                "status": "failed",
                "detail": str(error)
            }
            for recipient in recipients
        ]

    finally:

        if server is not None:
            try:
                server.quit()
            except Exception:
                pass

    return results


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "smtp_host": SMTP_HOST,
        "smtp_port": SMTP_PORT
    })


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        password = request.form.get("password", "")

        if LOGIN_PASSWORD and secrets.compare_digest(
            password,
            LOGIN_PASSWORD
        ):

            session.clear()
            session["logged_in"] = True

            return redirect(url_for("index"))

        return render_template(
            "login.html",
            error="Incorrect password. Please try again."
        )

    return render_template("login.html")


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# --------------------------------------------------
# MAIN PAGE
# --------------------------------------------------

@app.route("/")
def index():

    if not logged_in():
        return redirect(url_for("login"))

    return render_template("index.html")


# --------------------------------------------------
# SEND EMAIL BATCH
# --------------------------------------------------

@app.route("/send-batch", methods=["POST"])
def send_batch():

    if not logged_in():
        return jsonify({
            "error": "Session expired. Please sign in again."
        }), 401

    data = request.get_json(silent=True) or {}

    recipients_input = data.get("recipients", [])

    if isinstance(recipients_input, str):
        recipients_input = re.split(
            r"[\n,;\t]+",
            recipients_input
        )

    if not isinstance(recipients_input, list):
        return jsonify({
            "error": "Invalid recipients format."
        }), 400

    sender_email = str(data.get("senderEmail", "")).strip()
    app_password = str(data.get("appPassword", "")).strip()
    sender_name = str(data.get("senderName", "")).strip()
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))

    html_mode = bool(data.get("htmlMode", False))
    consent_confirmed = bool(data.get("consentConfirmed", False))

    if not consent_confirmed:
        return jsonify({
            "error": "Please confirm that recipients have given permission."
        }), 400

    if not sender_email or not EMAIL_RE.match(sender_email):
        return jsonify({
            "error": "Enter a valid sender Gmail address."
        }), 400

    if not app_password:
        return jsonify({
            "error": "Enter your Gmail App Password."
        }), 400

    if not subject:
        return jsonify({
            "error": "Email subject is required."
        }), 400

    if not body.strip():
        return jsonify({
            "error": "Email message is required."
        }), 400

    if not sender_name:
        sender_name = sender_email

    # Validate and deduplicate recipients
    recipients = []
    seen = set()

    for item in recipients_input:

        email_address = str(item).strip()

        if (
            email_address
            and EMAIL_RE.match(email_address)
            and email_address.lower() not in seen
        ):

            recipients.append(email_address)
            seen.add(email_address.lower())

    if not recipients:
        return jsonify({
            "error": "No valid recipient email addresses found."
        }), 400

    # Frontend sends batches of five
    if len(recipients) > 5:
        return jsonify({
            "error": "Maximum 10 recipients are allowed per batch."
        }), 400

    results = send_batch_with_smtp(
        recipients=recipients,
        sender_email=sender_email,
        app_password=app_password,
        sender_name=sender_name,
        subject=subject,
        body=body,
        html_mode=html_mode
    )

    sent_count = sum(
        1 for item in results
        if item["status"] == "sent"
    )

    failed_count = len(results) - sent_count

    return jsonify({
        "success": True,
        "total": len(results),
        "sent": sent_count,
        "failed": failed_count,
        "results": results
    })


# --------------------------------------------------
# VERCEL APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )

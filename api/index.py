import os
import re
import ssl
import time
import logging
import secrets
import smtplib

from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import local

from email.message import EmailMessage
from email.utils import formataddr
from html.parser import HTMLParser

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify
)


# =========================================================
# LOGGING
# =========================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =========================================================
# APP
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET"
)

app.config.update(
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
)


# =========================================================
# ENVIRONMENT VARIABLES
# =========================================================

LOGIN_PASSWORD = os.environ.get(
    "LOGIN_PASSWORD",
    ""
)

SMTP_HOST = os.environ.get(
    "SMTP_HOST",
    "smtp.gmail.com"
)

SMTP_PORT = int(
    os.environ.get("SMTP_PORT", "587")
)

# Fast mode: no delay between emails.
MAIL_GAP_SECONDS = 0

SMTP_TIMEOUT = 20

# Allow 25 recipients in one request.
MAX_RECIPIENTS = 25

# 5 parallel SMTP connections.
MAX_SMTP_WORKERS = 5

EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


# =========================================================
# LOGIN CHECK
# =========================================================

def logged_in():
    return session.get("logged_in") is True


# =========================================================
# SPINTAX
# =========================================================

def process_spintax(text):

    if not isinstance(text, str):
        return text

    def parse_segment(value):

        output = []
        options = []
        current = []
        depth = 0
        i = 0

        while i < len(value):

            char = value[i]

            if char == "{":

                if depth == 0:
                    current = []
                    options = []
                else:
                    current.append(char)

                depth += 1

            elif char == "}" and depth > 0:

                depth -= 1

                if depth == 0:

                    options.append(
                        "".join(current)
                    )

                    if len(options) > 1:

                        selected = secrets.choice(
                            options
                        )

                        output.append(
                            parse_segment(selected)
                        )

                    else:

                        output.append(
                            "{" + options[0] + "}"
                        )

                    current = []
                    options = []

                else:
                    current.append(char)

            elif char == "|" and depth == 1:

                options.append(
                    "".join(current)
                )

                current = []

            elif depth > 0:

                current.append(char)

            else:

                output.append(char)

            i += 1

        if depth > 0:

            output.append("{")
            output.append("".join(current))

        return "".join(output)

    return parse_segment(text)


# =========================================================
# HTML TEXT EXTRACTOR
# =========================================================

class HTMLTextExtractor(HTMLParser):

    def __init__(self):

        super().__init__()

        self.parts = []

    def handle_data(self, data):

        self.parts.append(data)

    def get_text(self):

        return " ".join(
            self.parts
        ).strip()


# =========================================================
# CREATE EMAIL MESSAGE
# =========================================================

def create_message(
    recipient,
    subject,
    body,
    sender_name,
    sender_email,
    html_mode=False
):

    message = EmailMessage()

    message["From"] = formataddr(
        (
            sender_name or sender_email,
            sender_email
        )
    )

    message["To"] = recipient

    message["Subject"] = subject

    if html_mode:

        extractor = HTMLTextExtractor()

        extractor.feed(body)

        plain_text = (
            extractor.get_text()
            or "Please view this email in an HTML-compatible email client."
        )

        message.set_content(plain_text)

        message.add_alternative(
            body,
            subtype="html"
        )

    else:

        message.set_content(body)

    return message


# =========================================================
# SMTP CONNECTION
# =========================================================

def open_smtp_connection(
    sender_email,
    app_password
):

    context = ssl.create_default_context()

    if SMTP_PORT == 465:

        server = smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=SMTP_TIMEOUT,
            context=context
        )

    else:

        server = smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT,
            timeout=SMTP_TIMEOUT
        )

        server.ehlo()

        server.starttls(
            context=context
        )

        server.ehlo()

    try:

        server.login(
            sender_email,
            app_password
        )

        server.noop()

        return server

    except Exception:

        try:
            server.quit()
        except Exception:
            pass

        raise


# =========================================================
# SMTP ERROR MESSAGE
# =========================================================

def smtp_error_message(exc):

    if isinstance(
        exc,
        smtplib.SMTPAuthenticationError
    ):

        return (
            "Gmail login failed. Check Gmail address "
            "and Google App Password."
        )

    if isinstance(
        exc,
        smtplib.SMTPRecipientsRefused
    ):

        return (
            "Recipient address rejected by Gmail SMTP."
        )

    if isinstance(
        exc,
        smtplib.SMTPDataError
    ):

        return (
            f"Gmail rejected the message. "
            f"SMTP code: {exc.smtp_code}"
        )

    if isinstance(
        exc,
        smtplib.SMTPConnectError
    ):

        return (
            f"Could not connect to Gmail SMTP. "
            f"Code: {exc.smtp_code}"
        )

    if isinstance(
        exc,
        (TimeoutError, OSError)
    ):

        return (
            f"SMTP network or timeout error: "
            f"{str(exc)[:180]}"
        )

    if isinstance(
        exc,
        smtplib.SMTPException
    ):

        return (
            f"SMTP error: {str(exc)[:180]}"
        )

    return (
        f"Unexpected sending error: {str(exc)[:180]}"
    )


# =========================================================
# SEND BATCH WITH SMTP — PARALLEL VERSION
# =========================================================

def send_batch_with_smtp(
    recipients,
    subject,
    body,
    sender_name,
    sender_email,
    app_password,
    html_mode
):

    results = []

    thread_data = local()

    def send_one(recipient):

        try:
            # Each worker thread gets its own SMTP connection.
            if not hasattr(thread_data, "server"):

                thread_data.server = open_smtp_connection(
                    sender_email,
                    app_password
                )

            server = thread_data.server

            personalized_subject = process_spintax(subject)

            personalized_body = process_spintax(body)

            message = create_message(
                recipient,
                personalized_subject,
                personalized_body,
                sender_name,
                sender_email,
                html_mode
            )

            refused = server.send_message(message)

            if refused:

                return {
                    "email": recipient,
                    "status": "failed",
                    "detail": (
                        "Recipient rejected by SMTP server."
                    )
                }

            return {
                "email": recipient,
                "status": "sent",
                "detail": (
                    "Accepted by SMTP server."
                )
            }

        except smtplib.SMTPAuthenticationError as exc:

            return {
                "email": recipient,
                "status": "failed",
                "detail": smtp_error_message(exc)
            }

        except smtplib.SMTPRecipientsRefused:

            return {
                "email": recipient,
                "status": "failed",
                "detail": (
                    "Recipient address rejected by Gmail."
                )
            }

        except smtplib.SMTPDataError as exc:

            return {
                "email": recipient,
                "status": "failed",
                "detail": (
                    f"Message rejected. "
                    f"SMTP code: {exc.smtp_code}"
                )
            }

        except (
            smtplib.SMTPException,
            OSError,
            TimeoutError
        ) as exc:

            return {
                "email": recipient,
                "status": "failed",
                "detail": smtp_error_message(exc)
            }

        except Exception as exc:

            return {
                "email": recipient,
                "status": "failed",
                "detail": (
                    f"Unexpected error: {str(exc)[:180]}"
                )
            }

    # Send all recipients concurrently using 5 workers.
    with ThreadPoolExecutor(
        max_workers=MAX_SMTP_WORKERS
    ) as executor:

        future_map = {
            executor.submit(send_one, recipient): recipient
            for recipient in recipients
        }

        for future in as_completed(future_map):

            results.append(future.result())

    return results


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "Gmail SMTP",
        "smtp_host": SMTP_HOST,
        "smtp_port": SMTP_PORT,
        "mail_gap_seconds": MAIL_GAP_SECONDS,
        "max_recipients": MAX_RECIPIENTS,
        "max_smtp_workers": MAX_SMTP_WORKERS
    })


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    error = None

    if request.method == "POST":

        if not LOGIN_PASSWORD:

            error = (
                "Set LOGIN_PASSWORD in Vercel "
                "Environment Variables first."
            )

        elif secrets.compare_digest(
            request.form.get("password", ""),
            LOGIN_PASSWORD
        ):

            session.clear()

            session["logged_in"] = True

            session.permanent = True

            return redirect(
                url_for("index")
            )

        else:

            error = "Incorrect password."

    return render_template(
        "login.html",
        error=error
    )


# =========================================================
# LOGOUT
# =========================================================

@app.get("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# HOME
# =========================================================

@app.get("/")
def index():

    if not logged_in():

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html"
    )


# =========================================================
# SEND BATCH
# =========================================================

@app.post("/send-batch")
def send_batch():

    if not logged_in():

        return jsonify({
            "error": "Please sign in again."
        }), 401

    try:

        data = request.get_json(
            silent=True
        )

        if not isinstance(data, dict):

            return jsonify({
                "error": (
                    "Invalid request. "
                    "Expected JSON data."
                )
            }), 400

        recipients = data.get(
            "recipients",
            []
        )

        sender_email = str(
            data.get("senderEmail", "")
        ).strip()

        app_password = str(
            data.get("appPassword", "")
        ).replace(" ", "")

        sender_name = str(
            data.get("senderName", "")
        ).strip()[:100]

        subject = str(
            data.get("subject", "")
        ).strip()

        body = str(
            data.get("body", "")
        )

        html_mode = (
            data.get("htmlMode") is True
        )

        # -------------------------------------------------
        # CONSENT VALIDATION
        # -------------------------------------------------

        if data.get("consentConfirmed") is not True:

            return jsonify({
                "error": (
                    "Confirm recipient permission first."
                )
            }), 400

        # -------------------------------------------------
        # EMAIL VALIDATION
        # -------------------------------------------------

        if not EMAIL_RE.fullmatch(sender_email):

            return jsonify({
                "error": (
                    "Enter a valid Gmail address."
                )
            }), 400

        if not sender_email.lower().endswith(
            "@gmail.com"
        ):

            return jsonify({
                "error": (
                    "Use a Gmail address for Gmail SMTP."
                )
            }), 400

        if not app_password:

            return jsonify({
                "error": (
                    "Enter your Google App Password."
                )
            }), 400

        # -------------------------------------------------
        # RECIPIENT VALIDATION
        # -------------------------------------------------

        if not isinstance(recipients, list):

            return jsonify({
                "error": (
                    "Recipients must be a list."
                )
            }), 400

        recipients = list(dict.fromkeys(
            item.strip()
            for item in recipients
            if isinstance(item, str)
            and EMAIL_RE.fullmatch(item.strip())
        ))

        if not recipients:

            return jsonify({
                "error": (
                    "No valid recipient addresses found."
                )
            }), 400

        if len(recipients) > MAX_RECIPIENTS:

            return jsonify({
                "error": (
                    f"Maximum {MAX_RECIPIENTS} "
                    "recipients per request."
                )
            }), 400

        # -------------------------------------------------
        # MESSAGE VALIDATION
        # -------------------------------------------------

        if not subject or not body.strip():

            return jsonify({
                "error": (
                    "Subject and message are required."
                )
            }), 400

        if len(subject) > 200:

            return jsonify({
                "error": (
                    "Subject is too long."
                )
            }), 400

        if len(body) > 50000:

            return jsonify({
                "error": (
                    "Message body is too long."
                )
            }), 400

        # -------------------------------------------------
        # SEND
        # -------------------------------------------------

        results = send_batch_with_smtp(
            recipients,
            subject,
            body,
            sender_name,
            sender_email,
            app_password,
            html_mode
        )

        sent = sum(
            item["status"] == "sent"
            for item in results
        )

        failed = len(results) - sent

        logger.info(
            "Batch completed: total=%s sent=%s failed=%s",
            len(results),
            sent,
            failed
        )

        return jsonify({
            "total": len(results),
            "sent": sent,
            "failed": failed,
            "results": results
        })

    except Exception:

        logger.exception(
            "Unhandled error in /send-batch"
        )

        return jsonify({
            "error": (
                "Server error while processing "
                "the batch. Check Vercel Runtime Logs."
            )
        }), 500


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )

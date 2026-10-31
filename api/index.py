
import os
import re
import ssl
import time
import logging
import secrets
import smtplib
from email.message import EmailMessage
from email.utils import formataddr
from html.parser import HTMLParser

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET"
)

app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))

MAIL_GAP_SECONDS = max(
    0.0,
    min(float(os.environ.get("MAIL_GAP_SECONDS", "1")), 10.0)
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def logged_in():
    return session.get("logged_in") is True


def process_spintax(text):
    """
    Supports:
    {Hello|Hi|Hey}
    {professional|attractive|well designed}
    Nested choices such as:
    {{Hello|Hi}|Hey}

    One random option is selected for each recipient.
    """

    if not isinstance(text, str):
        return text

    def parse_segment(value):
        output = []
        options = []
        current = []
        depth = 0
        found_open = False
        i = 0

        while i < len(value):
            char = value[i]

            if char == "{":
                if depth == 0:
                    found_open = True
                    current = []
                    options = []
                else:
                    current.append(char)
                depth += 1

            elif char == "}" and depth > 0:
                depth -= 1

                if depth == 0:
                    options.append("".join(current))

                    if len(options) > 1:
                        selected = secrets.choice(options)
                        output.append(parse_segment(selected))
                    else:
                        output.append("{" + options[0] + "}")

                    found_open = False
                    current = []
                    options = []
                else:
                    current.append(char)

            elif char == "|" and depth == 1:
                options.append("".join(current))
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


class HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)

    def get_text(self):
        return " ".join(self.parts).strip()


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
        (sender_name or sender_email, sender_email)
    )
    message["To"] = recipient
    message["Subject"] = subject

    if html_mode:
        extractor = HTMLTextExtractor()
        extractor.feed(body)
        plain_text = extractor.get_text() or "Please view this email in an HTML-compatible email client."

        message.set_content(plain_text)
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    return message


def open_smtp_connection(sender_email, app_password):
    context = ssl.create_default_context()

    if SMTP_PORT == 465:
        server = smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=15,
            context=context
        )
    else:
        server = smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT,
            timeout=15
        )
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()

    server.login(sender_email, app_password)
    return server


def smtp_error_message(exc):
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "Gmail login failed. Check Gmail address and Google App Password."

    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "Recipient address rejected by Gmail SMTP."

    if isinstance(exc, smtplib.SMTPDataError):
        return f"Gmail rejected the message. SMTP code: {exc.smtp_code}"

    if isinstance(exc, smtplib.SMTPConnectError):
        return f"Could not connect to Gmail SMTP. Code: {exc.smtp_code}"

    if isinstance(exc, (TimeoutError, OSError)):
        return f"SMTP network or timeout error: {str(exc)[:180]}"

    if isinstance(exc, smtplib.SMTPException):
        return f"SMTP error: {str(exc)[:180]}"

    return f"Unexpected sending error: {str(exc)[:180]}"


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
    server = None

    # Reuse one authenticated SMTP connection for this batch.
    for attempt in range(2):
        try:
            server = open_smtp_connection(sender_email, app_password)
            break
        except smtplib.SMTPAuthenticationError as exc:
            logger.warning("SMTP authentication failed: %s", exc)
            error = smtp_error_message(exc)
            return [
                {"email": address, "status": "failed", "detail": error}
                for address in recipients
            ]
        except Exception as exc:
            logger.exception("SMTP connection attempt %s failed", attempt + 1)
            if attempt == 0:
                time.sleep(1)
            else:
                error = smtp_error_message(exc)
                return [
                    {"email": address, "status": "failed", "detail": error}
                    for address in recipients
                ]

    try:
        for index, recipient in enumerate(recipients):
            # Generate a fresh variation for every recipient.
            personalized_subject = process_spintax(subject)
            personalized_body = process_spintax(body)

            try:
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
                    results.append({
                        "email": recipient,
                        "status": "failed",
                        "detail": "Recipient rejected by SMTP server."
                    })
                else:
                    results.append({
                        "email": recipient,
                        "status": "sent",
                        "detail": "Accepted by Gmail SMTP."
                    })

            except smtplib.SMTPRecipientsRefused:
                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": "Recipient address rejected by Gmail."
                })

            except smtplib.SMTPDataError as exc:
                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": f"Message rejected. SMTP code: {exc.smtp_code}"
                })

            except (smtplib.SMTPException, OSError, TimeoutError) as exc:
                logger.exception("SMTP sending failed for recipient")
                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": smtp_error_message(exc)
                })

                # A connection-level failure can affect later recipients.
                for remaining in recipients[index + 1:]:
                    results.append({
                        "email": remaining,
                        "status": "failed",
                        "detail": "Batch stopped because the SMTP connection failed."
                    })
                break

            if index < len(recipients) - 1 and MAIL_GAP_SECONDS:
                time.sleep(MAIL_GAP_SECONDS)

    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass

    return results


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        if not LOGIN_PASSWORD:
            error = "Set LOGIN_PASSWORD in Vercel Environment Variables first."

        elif request.form.get("password", "") == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("index"))

        else:
            error = "Incorrect password."

    return render_template("login.html", error=error)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    if not logged_in():
        return redirect(url_for("login"))

    return render_template("index.html")


@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify({"error": "Please sign in again."}), 401

    try:
        data = request.get_json(silent=True) or {}

        recipients = data.get("recipients", [])
        sender_email = str(data.get("senderEmail", "")).strip()
        app_password = str(data.get("appPassword", "")).replace(" ", "")
        sender_name = str(data.get("senderName", "")).strip()[:100]
        subject = str(data.get("subject", "")).strip()
        body = str(data.get("body", ""))
        html_mode = data.get("htmlMode") is True

        if data.get("consentConfirmed") is not True:
            return jsonify({
                "error": "Confirm recipient permission first."
            }), 400

        if not EMAIL_RE.fullmatch(sender_email):
            return jsonify({
                "error": "Enter a valid Gmail address."
            }), 400

        if not sender_email.lower().endswith("@gmail.com"):
            return jsonify({
                "error": "Use a Gmail address for Gmail SMTP."
            }), 400

        if not app_password:
            return jsonify({
                "error": "Enter your Google App Password."
            }), 400

        if not isinstance(recipients, list):
            return jsonify({
                "error": "Recipients must be a list."
            }), 400

        recipients = list(dict.fromkeys(
            item.strip()
            for item in recipients
            if isinstance(item, str)
            and EMAIL_RE.fullmatch(item.strip())
        ))

        if not recipients:
            return jsonify({
                "error": "No valid recipient addresses found."
            }), 400

        if len(recipients) > 5:
            return jsonify({
                "error": "Maximum 5 recipients per request."
            }), 400

        if not subject or not body.strip():
            return jsonify({
                "error": "Subject and message are required."
            }), 400

        if len(subject) > 200:
            return jsonify({
                "error": "Subject is too long."
            }), 400

        if len(body) > 50000:
            return jsonify({
                "error": "Message body is too long."
            }), 400

        results = send_batch_with_smtp(
            recipients,
            subject,
            body,
            sender_name,
            sender_email,
            app_password,
            html_mode
        )

        sent = sum(item["status"] == "sent" for item in results)
        failed = len(results) - sent

        logger.info(
            "Batch completed: total=%s sent=%s failed=%s",
            len(results), sent, failed
        )

        return jsonify({
            "total": len(results),
            "sent": sent,
            "failed": failed,
            "results": results
        })

    except Exception:
        logger.exception("Unhandled error in /send-batch")
        return jsonify({
            "error": "Server error while processing the batch. Check Vercel Runtime Logs."
        }), 500


if __name__ == "__main__":
    app.run()

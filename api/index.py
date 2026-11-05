import logging
import os
import re
import secrets
import smtplib
import ssl
import time

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from html.parser import HTMLParser

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import RequestEntityTooLarge


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

if not SESSION_SECRET:
    raise RuntimeError("Set SESSION_SECRET before starting the application.")

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

app.secret_key = SESSION_SECRET

app.config.update(
    MAX_CONTENT_LENGTH=1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get(
        "COOKIE_SECURE", "true"
    ).lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_TIMEOUT = 10

MAX_RECIPIENTS = 25
MAX_SMTP_WORKERS = max(
    1, min(int(os.environ.get("MAX_SMTP_WORKERS", "5")), 5)
)

EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")


def logged_in():
    return session.get("logged_in") is True


def csrf_token():
    token = session.get("csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token

    return token


app.jinja_env.globals["csrf_token"] = csrf_token


def csrf_valid(value):
    expected = session.get("csrf_token")

    return (
        isinstance(value, str)
        and isinstance(expected, str)
        and secrets.compare_digest(value, expected)
    )


def process_spintax(text):
    pattern = re.compile(r"\{([^{}]*\|[^{}]*)\}")

    for _ in range(20):
        updated = pattern.sub(
            lambda match: secrets.choice(match.group(1).split("|")),
            text,
        )

        if updated == text:
            break

        text = updated

    return text


class HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.hidden_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.hidden_depth += 1

        if tag in ("br", "p", "div", "li", "tr"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.hidden_depth:
            self.hidden_depth -= 1

        if tag in ("p", "div", "li", "tr"):
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.hidden_depth:
            self.parts.append(data)

    def get_text(self):
        return "".join(self.parts).strip()


def create_message(
    recipient,
    subject,
    body,
    sender_name,
    sender_email,
    html_mode,
):
    message = EmailMessage()
    message["From"] = formataddr(
        (sender_name or sender_email, sender_email)
    )
    message["To"] = recipient
    message["Subject"] = process_spintax(subject)
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid()

    content = process_spintax(body)

    if html_mode:
        extractor = HTMLTextExtractor()
        extractor.feed(content)

        message.set_content(
            extractor.get_text()
            or "Please view this message in an HTML-compatible email client."
        )
        message.add_alternative(content, subtype="html")
    else:
        message.set_content(content)

    return message


def close_smtp(server):
    if server is None:
        return

    try:
        server.quit()
    except Exception:
        try:
            server.close()
        except Exception:
            pass


def open_smtp_connection(sender_email, app_password):
    server = None
    context = ssl.create_default_context()

    try:
        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(
                SMTP_HOST,
                SMTP_PORT,
                timeout=SMTP_TIMEOUT,
                context=context,
            )
        elif SMTP_PORT == 587:
            server = smtplib.SMTP(
                SMTP_HOST,
                SMTP_PORT,
                timeout=SMTP_TIMEOUT,
            )
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
        else:
            raise ValueError("SMTP_PORT must be 465 or 587.")

        server.login(sender_email, app_password)
        return server

    except Exception:
        close_smtp(server)
        raise


def smtp_error_message(exc):
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "Gmail login failed. Check the Gmail address and App Password."

    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "Recipient rejected by SMTP."

    if isinstance(exc, smtplib.SMTPResponseException):
        return f"SMTP rejected the request. Code: {exc.smtp_code}."

    if isinstance(exc, (OSError, TimeoutError)):
        return "SMTP network connection failed or timed out."

    return "SMTP operation failed. Check server logs."


def result_item(recipient, status, detail):
    return {
        "email": recipient,
        "status": status,
        "detail": detail,
    }


def send_worker(
    recipients,
    subject,
    body,
    sender_name,
    sender_email,
    app_password,
    html_mode,
):
    results = []
    server = None

    try:
        try:
            server = open_smtp_connection(sender_email, app_password)
        except Exception as exc:
            logger.warning(
                "SMTP connection failed: %s",
                type(exc).__name__,
            )

            return [
                result_item(address, "failed", smtp_error_message(exc))
                for address in recipients
            ]

        for index, recipient in enumerate(recipients):
            try:
                message = create_message(
                    recipient,
                    subject,
                    body,
                    sender_name,
                    sender_email,
                    html_mode,
                )
            except Exception:
                results.append(
                    result_item(
                        recipient,
                        "failed",
                        "Could not create the email message.",
                    )
                )
                continue

            try:
                refused = server.send_message(message)

                if refused:
                    results.append(
                        result_item(
                            recipient,
                            "failed",
                            "Recipient rejected by SMTP.",
                        )
                    )
                else:
                    results.append(
                        result_item(
                            recipient,
                            "sent",
                            "Accepted by Gmail SMTP; inbox delivery is not confirmed.",
                        )
                    )

            except smtplib.SMTPRecipientsRefused as exc:
                results.append(
                    result_item(
                        recipient,
                        "failed",
                        smtp_error_message(exc),
                    )
                )

            except smtplib.SMTPResponseException as exc:
                results.append(
                    result_item(
                        recipient,
                        "failed",
                        smtp_error_message(exc),
                    )
                )

                results.extend(
                    result_item(
                        address,
                        "not_sent",
                        "Worker stopped after an SMTP error. No automatic retry.",
                    )
                    for address in recipients[index + 1:]
                )
                break

            except (smtplib.SMTPException, OSError, TimeoutError):
                results.append(
                    result_item(
                        recipient,
                        "unknown",
                        "Connection failed during sending. Delivery may have occurred; verify before retrying.",
                    )
                )

                results.extend(
                    result_item(
                        address,
                        "not_sent",
                        "Not attempted because the SMTP connection failed.",
                    )
                    for address in recipients[index + 1:]
                )
                break

    finally:
        close_smtp(server)

    return results


def send_batch_with_smtp(
    recipients,
    subject,
    body,
    sender_name,
    sender_email,
    app_password,
    html_mode,
):
    worker_count = min(MAX_SMTP_WORKERS, len(recipients))
    groups = [
        recipients[index::worker_count]
        for index in range(worker_count)
    ]

    results = []

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(
                send_worker,
                group,
                subject,
                body,
                sender_name,
                sender_email,
                app_password,
                html_mode,
            )
            for group in groups
        ]

        for future in futures:
            results.extend(future.result())

    order = {
        recipient: index
        for index, recipient in enumerate(recipients)
    }

    return sorted(results, key=lambda item: order[item["email"]])


@app.get("/health")
def health():
    return jsonify(
        status="ok",
        max_recipients=MAX_RECIPIENTS,
        max_smtp_workers=MAX_SMTP_WORKERS,
        mail_gap_seconds=0,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        if not csrf_valid(request.form.get("csrf_token")):
            error = "Session expired. Reload the page and try again."

        elif not LOGIN_PASSWORD:
            error = "Set LOGIN_PASSWORD in the server environment."

        elif secrets.compare_digest(
            request.form.get("password", "").encode("utf-8"),
            LOGIN_PASSWORD.encode("utf-8"),
        ):
            session.clear()
            session["logged_in"] = True
            session.permanent = True
            csrf_token()
            return redirect(url_for("index"))

        else:
            error = "Incorrect password."

    return render_template("login.html", error=error)


@app.post("/logout")
def logout():
    if not csrf_valid(request.form.get("csrf_token")):
        return "Invalid session token. Reload and try again.", 400

    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    if not logged_in():
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        max_recipients=MAX_RECIPIENTS,
    )


@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify(error="Please sign in again."), 401

    if not csrf_valid(request.headers.get("X-CSRF-Token")):
        return jsonify(error="Session expired. Reload the page."), 400

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify(error="Expected a JSON object."), 400

    if data.get("consentConfirmed") is not True:
        return jsonify(error="Confirm recipient permission first."), 400

    text_fields = (
        "senderEmail",
        "appPassword",
        "senderName",
        "subject",
        "body",
    )

    if any(
        not isinstance(data.get(field, ""), str)
        for field in text_fields
    ):
        return jsonify(error="Invalid message fields."), 400

    sender_email = data.get("senderEmail", "").strip()
    app_password = re.sub(r"\s+", "", data.get("appPassword", ""))
    sender_name = data.get("senderName", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "")
    html_mode = data.get("htmlMode") is True
    raw_recipients = data.get("recipients")

    if (
        not EMAIL_RE.fullmatch(sender_email)
        or not sender_email.lower().endswith("@gmail.com")
    ):
        return jsonify(error="Enter a valid @gmail.com address."), 400

    if not app_password:
        return jsonify(error="Enter your Google App Password."), 400

    if (
        len(sender_name) > 100
        or any(char in sender_name + subject for char in "\r\n")
    ):
        return jsonify(error="Invalid sender name or subject."), 400

    if not subject or len(subject) > 200:
        return jsonify(error="Subject must contain 1–200 characters."), 400

    if not body.strip() or len(body) > 50000:
        return jsonify(error="Message must contain 1–50,000 characters."), 400

    if (
        not isinstance(raw_recipients, list)
        or not 1 <= len(raw_recipients) <= MAX_RECIPIENTS
    ):
        return jsonify(
            error=f"Provide between 1 and {MAX_RECIPIENTS} recipients."
        ), 400

    if any(
        not isinstance(address, str)
        or not EMAIL_RE.fullmatch(address.strip())
        for address in raw_recipients
    ):
        return jsonify(error="One or more recipient addresses are invalid."), 400

    recipients = list(
        dict.fromkeys(address.strip() for address in raw_recipients)
    )

    started = time.perf_counter()

    try:
        results = send_batch_with_smtp(
            recipients,
            subject,
            body,
            sender_name,
            sender_email,
            app_password,
            html_mode,
        )

        counts = {
            status: sum(item["status"] == status for item in results)
            for status in ("sent", "failed", "unknown", "not_sent")
        }

        return jsonify(
            total=len(results),
            results=results,
            elapsed_seconds=round(time.perf_counter() - started, 2),
            **counts,
        )

    except Exception:
        logger.exception("Unexpected batch processing error")

        return jsonify(
            error=(
                "Unexpected server error. Some messages may have been sent. "
                "Check logs and received messages before retrying."
            )
        ), 500


@app.errorhandler(RequestEntityTooLarge)
def payload_too_large(exc):
    return jsonify(error="Request exceeds the 1 MB limit."), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

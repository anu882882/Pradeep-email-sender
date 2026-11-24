
import os
import re
import ssl
import smtplib
import secrets
import time

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
)

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate, make_msgid


# =========================================================
# APP CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

handler = app

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET is not configured.")

if not LOGIN_PASSWORD:
    raise RuntimeError("LOGIN_PASSWORD is not configured.")

app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


# =========================================================
# EMAIL SETTINGS
# =========================================================

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

SEND_DELAY_SECONDS = 0.2


# =========================================================
# EMAIL VALIDATION
# =========================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    if not isinstance(value, str):
        return False

    value = value.strip()

    if not value or len(value) > 254:
        return False

    return bool(EMAIL_RE.fullmatch(value))


def normalize_email(value):
    return str(value or "").strip().lower()


def authenticated():
    return session.get("authenticated") is True


def clean_header(value, max_length=998):
    value = str(value or "")
    value = value.replace("\r", " ")
    value = value.replace("\n", " ")
    return value.strip()[:max_length]


# =========================================================
# PERSONALIZATION
# =========================================================

def personalize_template(template, recipient):

    result = str(template or "")

    values = {
        "{{hi}}": str(recipient.get("hi", "") or ""),
        "{{hello}}": str(recipient.get("hello", "") or ""),
        "{{thanks}}": str(recipient.get("thanks", "") or ""),
        "{{name}}": str(recipient.get("name", "") or ""),
        "{{email}}": str(recipient.get("email", "") or ""),
        "{{ref_code}}": str(recipient.get("ref_code", "") or ""),
    }

    for placeholder, value in values.items():
        result = result.replace(placeholder, value)

    return result


# =========================================================
# HTML TO PLAIN TEXT
# =========================================================

def html_to_plain_text(html):

    text = str(html or "")

    text = re.sub(
        r"<br\s*/?>",
        "\n",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"</p\s*>",
        "\n\n",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"</div\s*>",
        "\n",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"<[^>]+>",
        "",
        text,
    )

    replacements = {
        "&nbsp;": " ",
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&#39;": "'",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    return text.strip()


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if authenticated():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template(
            "login.html",
            error=None,
        )

    password = str(
        request.form.get("password", "")
    )

    if not secrets.compare_digest(
        password,
        LOGIN_PASSWORD,
    ):
        return render_template(
            "login.html",
            error="Incorrect password.",
        ), 401

    session.clear()
    session.permanent = True
    session["authenticated"] = True

    return redirect(url_for("home"))


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout", methods=["GET", "POST"])
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if not authenticated():
        return redirect(url_for("login"))

    return render_template("index.html")


# =========================================================
# NORMALIZE RECIPIENT
# =========================================================

def normalize_recipient(item):

    if isinstance(item, str):
        return {
            "email": normalize_email(item),
            "name": "",
            "hi": "",
            "hello": "",
            "thanks": "",
            "ref_code": "",
        }

    if not isinstance(item, dict):
        return None

    email = normalize_email(item.get("email", ""))

    def safe_value(key, limit):
        value = str(item.get(key, "") or "")
        value = value.replace("\r", " ")
        value = value.replace("\n", " ")
        return value.strip()[:limit]

    return {
        "email": email,
        "name": safe_value("name", 200),
        "hi": safe_value("hi", 100),
        "hello": safe_value("hello", 100),
        "thanks": safe_value("thanks", 100),
        "ref_code": safe_value("ref_code", 200),
    }


# =========================================================
# BUILD EMAIL MESSAGE
# =========================================================

def build_message(
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):

    gmail = gmail.strip().lower()
    recipient = recipient.strip()

    sender_name = clean_header(sender_name, 200)
    subject = clean_header(subject, 998)

    body = str(body or "").replace("\x00", "")

    if is_html:

        message = MIMEMultipart("alternative")

        plain_body = html_to_plain_text(body)

        message.attach(
            MIMEText(
                plain_body,
                "plain",
                "utf-8",
            )
        )

        message.attach(
            MIMEText(
                body,
                "html",
                "utf-8",
            )
        )

    else:

        message = MIMEText(
            body,
            "plain",
            "utf-8",
        )

    message["Subject"] = subject

    message["From"] = formataddr(
        (
            sender_name,
            gmail,
        )
    )

    message["To"] = recipient
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    return message


# =========================================================
# SMTP CONNECTION
# =========================================================

def create_smtp_connection(gmail, app_password):

    clean_password = re.sub(
        r"\s+",
        "",
        str(app_password or ""),
    )

    context = ssl.create_default_context()

    server = smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT,
    )

    try:
        server.ehlo()
        server.login(gmail, clean_password)
        return server

    except Exception:
        try:
            server.quit()
        except Exception:
            pass

        raise


# =========================================================
# SEND ONE EMAIL
# =========================================================

def send_one_email(
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    recipient_data,
):

    recipient = recipient_data["email"]

    personalized_subject = personalize_template(
        subject,
        recipient_data,
    )

    personalized_body = personalize_template(
        body,
        recipient_data,
    )

    if SEND_DELAY_SECONDS > 0:
        time.sleep(SEND_DELAY_SECONDS)

    message = build_message(
        gmail=gmail,
        sender_name=sender_name,
        subject=personalized_subject,
        body=personalized_body,
        is_html=is_html,
        recipient=recipient,
    )

    smtp_server = None

    try:

        smtp_server = create_smtp_connection(
            gmail,
            app_password,
        )

        refused = smtp_server.sendmail(
            gmail,
            [recipient],
            message.as_string(),
        )

        if refused:
            return {
                "email": recipient,
                "result": "failed",
                "error": "SMTP refused recipient.",
            }

        return {
            "email": recipient,
            "result": "sent",
        }

    except smtplib.SMTPAuthenticationError:

        return {
            "email": recipient,
            "result": "failed",
            "error": "Gmail authentication failed. Check your Gmail App Password.",
        }

    except smtplib.SMTPRecipientsRefused:

        return {
            "email": recipient,
            "result": "failed",
            "error": "Recipient was refused by the mail server.",
        }

    except (smtplib.SMTPException, OSError, TimeoutError) as error:

        return {
            "email": recipient,
            "result": "failed",
            "error": str(error)[:300],
        }

    except Exception as error:

        return {
            "email": recipient,
            "result": "failed",
            "error": str(error)[:300],
        }

    finally:

        if smtp_server is not None:
            try:
                smtp_server.quit()
            except Exception:
                pass


# =========================================================
# SEND EMAILS
# =========================================================

@app.route("/send", methods=["POST"])
def send():

    if not authenticated():

        return jsonify({
            "success": False,
            "message": "Authentication required.",
            "login_required": True,
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return jsonify({
            "success": False,
            "message": "Invalid JSON request.",
        }), 400

    sender_name = clean_header(
        data.get("sender_name", ""),
        200,
    )

    gmail = clean_header(
        data.get("gmail", ""),
        254,
    ).lower()

    app_password = str(
        data.get("app_password", "")
    ).strip()

    subject = clean_header(
        data.get("subject", ""),
        998,
    )

    body = str(
        data.get("body", "")
    )

    is_html = data.get("is_html") is True

    recipients = data.get("recipients", [])

    consent = (
        data.get("consent") is True
        or data.get("recipient_consent") is True
    )

    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not sender_name:

        return jsonify({
            "success": False,
            "message": "Sender Name is required.",
        }), 400

    if not valid_email(gmail):

        return jsonify({
            "success": False,
            "message": "Enter a valid Gmail address.",
        }), 400

    if not gmail.endswith("@gmail.com"):

        return jsonify({
            "success": False,
            "message": "Please use a Gmail address with Gmail SMTP.",
        }), 400

    if not app_password:

        return jsonify({
            "success": False,
            "message": "Google App Password is required.",
        }), 400

    if not subject:

        return jsonify({
            "success": False,
            "message": "Email subject is required.",
        }), 400

    if not body.strip():

        return jsonify({
            "success": False,
            "message": "Message body is required.",
        }), 400

    if len(body) > 100_000:

        return jsonify({
            "success": False,
            "message": "Message body is too large.",
        }), 400

    if not isinstance(recipients, list):

        return jsonify({
            "success": False,
            "message": "Invalid recipient list.",
        }), 400

    if not consent:

        return jsonify({
            "success": False,
            "message": "Please confirm that these recipients have agreed to receive your emails.",
        }), 400

    # -----------------------------------------------------
    # CLEAN RECIPIENTS
    # -----------------------------------------------------

    clean_recipients = []
    seen = set()

    for item in recipients:

        recipient = normalize_recipient(item)

        if not recipient:
            continue

        email = recipient["email"]

        if not valid_email(email):
            continue

        if email in seen:
            continue

        seen.add(email)
        clean_recipients.append(recipient)

    clean_recipients = clean_recipients[:MAX_RECIPIENTS]

    if not clean_recipients:

        return jsonify({
            "success": False,
            "message": "No valid recipients found.",
        }), 400

    # -----------------------------------------------------
    # SEND EMAILS
    # -----------------------------------------------------

    results = []

    worker_count = min(
        MAX_PARALLEL_SENDS,
        len(clean_recipients),
    )

    try:

        with ThreadPoolExecutor(
            max_workers=worker_count
        ) as executor:

            future_map = {}

            for recipient_data in clean_recipients:

                future = executor.submit(
                    send_one_email,
                    gmail,
                    app_password,
                    sender_name,
                    subject,
                    body,
                    is_html,
                    recipient_data,
                )

                future_map[future] = recipient_data

            for future in as_completed(future_map):

                recipient_data = future_map[future]

                try:
                    result = future.result()

                except Exception as error:

                    result = {
                        "email": recipient_data["email"],
                        "result": "failed",
                        "error": str(error)[:300],
                    }

                results.append(result)

    except Exception as error:

        return jsonify({
            "success": False,
            "message": "Sending process failed: " + str(error)[:300],
            "results": results,
        }), 500

    # -----------------------------------------------------
    # FINAL RESPONSE
    # -----------------------------------------------------

    sent_count = sum(
        1 for item in results
        if item.get("result") == "sent"
    )

    failed_count = sum(
        1 for item in results
        if item.get("result") == "failed"
    )

    return jsonify({
        "success": failed_count == 0,
        "message": "Sending process completed.",
        "total": len(results),
        "sent": sent_count,
        "failed": failed_count,
        "results": results,
    })


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "ok",
        "app": "Bulk Email Sender",
    })


# =========================================================
# VERCEL HANDLER
# =========================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )

import os
import re
import ssl
import smtplib
import secrets
import time
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect
)

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

app.secret_key = os.getenv(
    "SESSION_SECRET",
    "change-this-secret"
)

LOGIN = os.getenv(
    "APP_LOGIN_PASSWORD",
    "Baby882@#"
)

TURNSTILE_SECRET = os.getenv(
    "TURNSTILE_SECRET_KEY",
    ""
)

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)

COOLDOWN = 5


def valid_email(value):
    return bool(
        EMAIL_PATTERN.fullmatch(
            str(value).strip()
        )
    )


def auth_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if session.get("login"):
            return function(*args, **kwargs)

        return redirect("/login")

    return wrapper


def parse_recipients(value):

    items = re.split(
        r"[\s,;]+",
        str(value or "")
    )

    result = []

    seen = set()

    for item in items:

        email = item.strip().lower()

        if not email:
            continue

        if email in seen:
            continue

        seen.add(email)

        result.append(email)

    return result


def safe_message(subject, message):

    combined = (
        str(subject) +
        " " +
        str(message)
    )

    if re.search(
        r"<\s*(script|iframe|object|embed)\b",
        combined,
        re.I
    ):
        return False, "Unsafe HTML detected."

    if re.search(
        r"javascript\s*:",
        combined,
        re.I
    ):
        return False, "Unsafe content detected."

    links = re.findall(
        r"https?://",
        combined,
        re.I
    )

    if len(links) > 5:
        return False, "Too many links in message."

    if re.search(
        r"(.)\1{10,}",
        combined
    ):
        return False, "Repeated characters detected."

    return True, "OK"


def resolve_spintax(text):

    pattern = re.compile(
        r"\{([^{}]+)\}"
    )

    def replace(match):

        options = [
            x.strip()
            for x in match.group(1).split("|")
            if x.strip()
        ]

        if not options:
            return ""

        return options[
            secrets.randbelow(
                len(options)
            )
        ]

    previous = None

    while previous != text:

        previous = text

        text = pattern.sub(
            replace,
            text
        )

    return text


def escape_html(text):

    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def make_html_message(text):

    text = escape_html(text)

    text = text.replace(
        "\r\n",
        "\n"
    )

    text = text.replace(
        "\r",
        "\n"
    )

    lines = text.split("\n")

    return "<br>".join(lines)


@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        if password == LOGIN:

            session["login"] = True

            session["last_send"] = 0

            return redirect("/")

        return render_template(
            "login.html",
            error="Wrong password."
        )

    return render_template(
        "login.html"
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


@app.route("/")
@auth_required
def home():

    return render_template(
        "index.html",
        turnstile_site_key=os.getenv(
            "TURNSTILE_SITE_KEY",
            ""
        )
    )


@app.route(
    "/api/send-batch",
    methods=["POST"]
)
@auth_required
def send_batch():

    now = time.time()

    last_send = session.get(
        "last_send",
        0
    )

    if now - last_send < COOLDOWN:

        return jsonify(
            error=(
                f"Please wait "
                f"{COOLDOWN} seconds."
            )
        ), 429

    data = request.get_json(
        silent=True
    ) or {}

    sender = str(
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
    ).strip().lower()

    app_password = "".join(
        str(
            data.get(
                "app_password",
                ""
            )
        ).split()
    )

    subject = str(
        data.get(
            "subject",
            ""
        )
    ).strip()

    message = str(
        data.get(
            "message",
            ""
        )
    )

    recipients = parse_recipients(
        data.get(
            "recipients",
            []
        )
    )

    if not sender:
        return jsonify(
            error="Sender name required."
        ), 400

    if not valid_email(gmail):
        return jsonify(
            error="Valid Gmail address required."
        ), 400

    if not app_password:
        return jsonify(
            error="Gmail App Password required."
        ), 400

    if not subject:
        return jsonify(
            error="Subject required."
        ), 400

    if not message.strip():
        return jsonify(
            error="Message required."
        ), 400

    if not recipients:
        return jsonify(
            error="No recipients."
        ), 400

    if len(recipients) > 5:
        return jsonify(
            error="Only 5 recipients per batch."
        ), 400

    invalid = [
        email
        for email in recipients
        if not valid_email(email)
    ]

    if invalid:

        return jsonify(
            error="Invalid recipient email.",
            invalid=invalid
        ), 400

    safe, reason = safe_message(
        subject,
        message
    )

    if not safe:

        return jsonify(
            error=reason
        ), 400

    sent = []

    failed = []

    try:

        context = (
            ssl.create_default_context()
        )

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=context,
            timeout=30
        ) as smtp:

            smtp.login(
                gmail,
                app_password
            )

            session["last_send"] = time.time()

            for recipient in recipients:

                try:

                    personalized = (
                        resolve_spintax(
                            message
                        )
                    )

                    personalized = (
                        personalized.replace(
                            "{name}",
                            recipient.split("@")[0]
                        )
                    )

                    plain_text = personalized

                    html_text = (
                        make_html_message(
                            personalized
                        )
                    )

                    mail = MIMEMultipart(
                        "alternative"
                    )

                    mail["Subject"] = (
                        resolve_spintax(
                            subject
                        )
                    )

                    mail["From"] = (
                        f"{sender} <{gmail}>"
                    )

                    mail["To"] = recipient

                    mail.attach(
                        MIMEText(
                            plain_text,
                            "plain",
                            "utf-8"
                        )
                    )

                    mail.attach(
                        MIMEText(
                            html_text,
                            "html",
                            "utf-8"
                        )
                    )

                    refused = smtp.sendmail(
                        gmail,
                        [recipient],
                        mail.as_string()
                    )

                    if refused:

                        failed.append(
                            recipient
                        )

                    else:

                        sent.append(
                            recipient
                        )

                except Exception as error:

                    failed.append(
                        recipient
                    )

        return jsonify(
            success=True,
            sent=sent,
            failed=failed,
            sender=gmail
        )

    except smtplib.SMTPAuthenticationError:

        return jsonify(
            error="Gmail authentication failed."
        ), 401

    except Exception as error:

        return jsonify(
            error=str(error)
        ), 500


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                5000
            )
        )
    )

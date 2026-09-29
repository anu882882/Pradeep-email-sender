import os
import re
import ssl
import smtplib
import secrets
import time

from flask import Flask, render_template, request, jsonify, session, redirect
from functools import wraps
from email.mime.text import MIMEText


app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

app.secret_key = os.getenv(
    "SESSION_SECRET",
    "RakshakSecureSession_2026_9xP7mQ4vL8"
)

LOGIN = os.getenv("APP_LOGIN_PASSWORD", "Baby882@#")

SEND_DELAY = float(os.getenv("SEND_DELAY", "1.5"))

ER = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# Display / monitoring information only.
# These addresses are NOT used as SMTP source IPs.
COUNTRY_IP_POOL = [
    {
        "name": "United States",
        "code": "US",
        "flag": "🇺🇸",
        "ip": "198.51.100.42",
        "city": "New York"
    },
    {
        "name": "United Kingdom",
        "code": "GB",
        "flag": "🇬🇧",
        "ip": "185.199.110.153",
        "city": "London"
    },
    {
        "name": "Germany",
        "code": "DE",
        "flag": "🇩🇪",
        "ip": "194.109.6.92",
        "city": "Frankfurt"
    },
    {
        "name": "India",
        "code": "IN",
        "flag": "🇮🇳",
        "ip": "103.21.244.18",
        "city": "Mumbai"
    },
    {
        "name": "Singapore",
        "code": "SG",
        "flag": "🇸🇬",
        "ip": "104.244.42.1",
        "city": "Singapore"
    },
    {
        "name": "Japan",
        "code": "JP",
        "flag": "🇯🇵",
        "ip": "133.242.18.2",
        "city": "Tokyo"
    },
    {
        "name": "Canada",
        "code": "CA",
        "flag": "🇨🇦",
        "ip": "192.206.151.131",
        "city": "Toronto"
    },
    {
        "name": "Australia",
        "code": "AU",
        "flag": "🇦🇺",
        "ip": "139.130.4.5",
        "city": "Sydney"
    },
    {
        "name": "France",
        "code": "FR",
        "flag": "🇫🇷",
        "ip": "195.154.122.3",
        "city": "Paris"
    },
    {
        "name": "Netherlands",
        "code": "NL",
        "flag": "🇳🇱",
        "ip": "188.166.0.4",
        "city": "Amsterdam"
    }
]


def valid(value):
    return bool(ER.fullmatch(str(value).strip()))


def auth(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("login"):
            return redirect("/login")

        return function(*args, **kwargs)

    return wrapper


def recipients(value):
    items = re.split(r"[\s,;]+", str(value))

    return list(
        dict.fromkeys(
            item.strip().lower()
            for item in items
            if item.strip()
        )
    )


def make_reference():
    return "#REF-" + secrets.token_hex(4).upper()


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        password = request.form.get("password", "")

        if secrets.compare_digest(password, LOGIN):
            session["login"] = True
            return redirect("/")

        return render_template(
            "login.html",
            error="Wrong password."
        )

    return render_template("login.html")


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


@app.route("/")
@auth
def home():

    return render_template(
        "index.html",
        country_pool=COUNTRY_IP_POOL
    )


@app.route("/api/pool")
@auth
def pool():

    return jsonify(
        success=True,
        countries=COUNTRY_IP_POOL
    )


@app.route("/api/send", methods=["POST"])
@auth
def send():

    data = request.get_json() or {}

    sender = str(
        data.get("sender_name", "")
    ).strip()

    gmail = str(
        data.get("gmail", "")
    ).strip().lower()

    password = "".join(
        str(data.get("app_password", "")).split()
    )

    subject = str(
        data.get("subject", "")
    ).strip()

    message = str(
        data.get("message", "")
    )

    to = recipients(
        data.get("recipients", "")
    )

    if not sender:
        return jsonify(
            error="Sender name required."
        ), 400

    if not valid(gmail):
        return jsonify(
            error="Valid Gmail address required."
        ), 400

    if not password:
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

    if not to:
        return jsonify(
            error="Add recipients first."
        ), 400

    if len(to) > 25:
        return jsonify(
            error="Maximum 25 recipients."
        ), 400

    invalid = [
        email for email in to
        if not valid(email)
    ]

    if invalid:
        return jsonify(
            error="Invalid recipient email.",
            invalid=invalid
        ), 400

    sent = []
    failed = []

    try:

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=context,
            timeout=30
        ) as smtp:

            smtp.login(
                gmail,
                password
            )

            for index, email in enumerate(to):

                reference = make_reference()

                try:

                    name = email.split("@")[0]

                    text = message.replace(
                        "{name}",
                        name
                    )

                    text = (
                        text.rstrip()
                        + f"\n\nReference: {reference}"
                    )

                    mail = MIMEText(
                        text,
                        "plain",
                        "utf-8"
                    )

                    mail["Subject"] = subject
                    mail["From"] = (
                        f"{sender} <{gmail}>"
                    )
                    mail["To"] = email

                    refused = smtp.sendmail(
                        gmail,
                        [email],
                        mail.as_string()
                    )

                    if refused:

                        failed.append({
                            "email": email,
                            "ref": reference,
                            "error": "Recipient refused."
                        })

                    else:

                        sent.append({
                            "email": email,
                            "ref": reference
                        })

                except Exception as error:

                    failed.append({
                        "email": email,
                        "ref": reference,
                        "error": str(error)
                    })

                # Controlled sending interval.
                if index < len(to) - 1:
                    time.sleep(
                        max(0, SEND_DELAY)
                    )

        return jsonify(
            success=True,
            total=len(to),
            sent=len(sent),
            failed=len(failed),
            sent_emails=sent,
            failed_emails=failed
        )

    except smtplib.SMTPAuthenticationError:

        return jsonify(
            error="Gmail authentication failed. Check the Gmail address and App Password."
        ), 401

    except smtplib.SMTPException as error:

        return jsonify(
            error=f"SMTP error: {error}"
        ), 500

    except Exception as error:

        return jsonify(
            error=str(error)
        ), 500


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv("PORT", "5000")
        )
    )

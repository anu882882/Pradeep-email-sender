import os
import re
import ssl
import smtplib
import secrets
import json
import urllib.request
import urllib.parse

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

TURNSTILE_SITEKEY = os.getenv(
    "TURNSTILE_SITE_KEY",
    ""
)

ER = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def valid(value):
    return bool(
        ER.fullmatch(
            str(value).strip()
        )
    )


def auth(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("login"):
            return redirect("/login")

        return function(*args, **kwargs)

    return wrapper


def recipients(value):

    parts = re.split(
        r"[\s,;]+",
        str(value)
    )

    return list(
        dict.fromkeys(
            item.strip().lower()
            for item in parts
            if item.strip()
        )
    )


def make_reference():

    return (
        "#REF-"
        + secrets.token_hex(4).upper()
    )


def verify_turnstile(token, remote_ip=None):

    if not TURNSTILE_SECRET:
        return {
            "success": False,
            "error-codes": [
                "turnstile-secret-not-configured"
            ]
        }

    if not token:
        return {
            "success": False,
            "error-codes": [
                "missing-input-response"
            ]
        }

    data = {
        "secret": TURNSTILE_SECRET,
        "response": token
    }

    if remote_ip:
        data["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(
        data
    ).encode()

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        method="POST"
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=10
        ) as response:

            return json.loads(
                response.read().decode()
            )

    except Exception:

        return {
            "success": False,
            "error-codes": [
                "turnstile-validation-error"
            ]
        }


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        if secrets.compare_digest(
            password,
            LOGIN
        ):

            session["login"] = True

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
@auth
def home():

    return render_template(
        "index.html",
        turnstile_sitekey=TURNSTILE_SITEKEY
    )


@app.route("/api/smtp-check", methods=["POST"])
@auth
def smtp_check():

    data = request.get_json() or {}

    gmail = str(
        data.get("gmail", "")
    ).strip().lower()

    password = "".join(
        str(
            data.get(
                "app_password",
                ""
            )
        ).split()
    )

    if not valid(gmail):

        return jsonify(
            success=False,
            error="Enter a valid Gmail address."
        ), 400

    if not password:

        return jsonify(
            success=False,
            error="Enter your Gmail App Password."
        ), 400

    try:

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=context,
            timeout=20
        ) as smtp:

            smtp.login(
                gmail,
                password
            )

        return jsonify(
            success=True,
            status="SMTP connection verified.",
            server="smtp.gmail.com",
            port=465
        )

    except smtplib.SMTPAuthenticationError:

        return jsonify(
            success=False,
            error="Gmail authentication failed. Check the App Password."
        ), 401

    except Exception as error:

        return jsonify(
            success=False,
            error=f"SMTP connection failed: {error}"
        ), 500


@app.route("/api/send", methods=["POST"])
@auth
def send():

    data = request.get_json() or {}

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

    password = "".join(
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

    to = recipients(
        data.get(
            "recipients",
            ""
        )
    )

    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    ).strip()


    # -------------------------
    # Turnstile verification
    # -------------------------

    remote_ip = request.headers.get(
        "CF-Connecting-IP"
    )

    if not remote_ip:

        remote_ip = request.remote_addr

    verification = verify_turnstile(
        turnstile_token,
        remote_ip
    )

    if not verification.get("success"):

        return jsonify(
            error="Spam Protection verification failed.",
            verification="failed"
        ), 403


    # -------------------------
    # Basic validation
    # -------------------------

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
        email
        for email in to
        if not valid(email)
    ]

    if invalid:

        return jsonify(
            error="Invalid recipient email.",
            invalid=invalid
        ), 400


    sent = []
    failed = []


    # -------------------------
    # Gmail SMTP
    # -------------------------

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


            for email in to:

                reference = make_reference()

                try:

                    name = email.split(
                        "@"
                    )[0]

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
                            "error": "SMTP recipient refused."
                        })

                    else:

                        sent.append({
                            "email": email,
                            "ref": reference,
                            "smtp": "accepted"
                        })


                except Exception as error:

                    failed.append({
                        "email": email,
                        "ref": reference,
                        "error": str(error)
                    })


        return jsonify(
            success=True,
            total=len(to),
            sent=len(sent),
            failed=len(failed),
            turnstile="verified",
            smtp="connected",
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
            os.getenv(
                "PORT",
                "5000"
            )
        )
    )

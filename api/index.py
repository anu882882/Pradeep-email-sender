import os
import re
import ssl
import smtplib
import secrets

from functools import wraps
from email.mime.text import MIMEText
from flask import Flask, render_template, request, jsonify, session, redirect


BASE = os.getcwd()

app = Flask(
    __name__,
    template_folder=os.path.join(BASE, "templates"),
    static_folder=os.path.join(BASE, "static")
)

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    "change-this-secret"
)

LOGIN_PASSWORD = os.environ.get(
    "APP_LOGIN_PASSWORD",
    ""
)

EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def valid_email(email):
    return bool(
        EMAIL_RE.fullmatch(email.strip())
    )


def clean_password(value):
    return "".join(
        str(value).split()
    )


def make_ref():
    return "#REF-" + secrets.token_hex(2).upper()


def protected(view):

    @wraps(view)
    def wrapper(*args, **kwargs):

        if not session.get("logged_in"):

            if request.path.startswith("/api/"):
                return jsonify(
                    error="Login required."
                ), 401

            return redirect("/login")

        return view(*args, **kwargs)

    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        if request.form.get("password", "") == LOGIN_PASSWORD:

            session["logged_in"] = True

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
@protected
def home():

    return render_template("index.html")


@app.route("/api/send", methods=["POST"])
@protected
def send():

    data = request.get_json(
        silent=True
    ) or {}

    sender_name = str(
        data.get("sender_name", "")
    ).strip()

    gmail = str(
        data.get("gmail", "")
    ).strip().lower()

    app_password = clean_password(
        data.get("app_password", "")
    )

    subject = str(
        data.get("subject", "")
    ).strip()

    message = str(
        data.get("message", "")
    )

    raw = str(
        data.get("recipients", "")
    )

    recipients = re.split(
        r"[\s,;]+",
        raw.strip()
    )

    recipients = [
        x.lower()
        for x in recipients
        if x
    ]

    recipients = list(
        dict.fromkeys(recipients)
    )

    if not sender_name:
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
            error="Add at least one recipient."
        ), 400

    if len(recipients) > 25:
        return jsonify(
            error="Maximum 25 recipients."
        ), 400

    invalid = [
        x for x in recipients
        if not valid_email(x)
    ]

    if invalid:
        return jsonify(
            error="Invalid recipient email.",
            invalid=invalid
        ), 400

    sent = []
    failed = []

    try:

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=ssl.create_default_context(),
            timeout=30
        ) as smtp:

            smtp.login(
                gmail,
                app_password
            )

            for recipient in recipients:

                try:

                    recipient_name = (
                        recipient.split("@")[0]
                    )

                    ref = make_ref()

                    text = message.replace(
                        "{name}",
                        recipient_name
                    )

                    text = text.replace(
                        "{ref}",
                        ref
                    )

                    mail = MIMEText(
                        text,
                        "plain",
                        "utf-8"
                    )

                    mail["Subject"] = subject

                    mail["From"] = (
                        sender_name
                        + " <"
                        + gmail
                        + ">"
                    )

                    mail["To"] = recipient

                    smtp.sendmail(
                        gmail,
                        [recipient],
                        mail.as_string()
                    )

                    sent.append({
                        "email": recipient,
                        "ref": ref
                    })

                except Exception as error:

                    failed.append({
                        "email": recipient,
                        "error": str(error)
                    })

        return jsonify(
            success=bool(sent),
            total=len(recipients),
            sent=len(sent),
            failed=len(failed),
            remaining=0,
            sent_emails=sent,
            failed_emails=failed
        )

    except smtplib.SMTPAuthenticationError:

        return jsonify(
            error="Gmail authentication failed. Check your App Password."
        ), 401

    except Exception as error:

        return jsonify(
            error=str(error)
        ), 500


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get("PORT", "5000")
        )
    )

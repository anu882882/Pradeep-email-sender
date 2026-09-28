import os
import re
import ssl
import smtplib

from flask import Flask, render_template, request, jsonify, session, redirect
from functools import wraps
from email.mime.text import MIMEText

app = Flask(__name__, template_folder="../templates", static_folder="../static")

app.secret_key = os.environ.get("SESSION_SECRET", "change-this-secret")
LOGIN_PASSWORD = os.environ.get("APP_LOGIN_PASSWORD", "")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid_email(x):
    return bool(EMAIL_RE.fullmatch(str(x).strip()))


def protected(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper


def recipients(raw):
    items = re.split(r"[\s,;]+", str(raw).strip())
    return list(dict.fromkeys(
        x.lower() for x in items if x
    ))


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

    data = request.get_json(silent=True) or {}

    sender = str(data.get("sender_name", "")).strip()
    gmail = str(data.get("gmail", "")).strip().lower()
    password = "".join(str(data.get("app_password", "")).split())
    subject = str(data.get("subject", "")).strip()
    message = str(data.get("message", ""))
    to = recipients(data.get("recipients", ""))

    if not sender:
        return jsonify(error="Sender name required."), 400

    if not valid_email(gmail):
        return jsonify(error="Valid Gmail address required."), 400

    if not password:
        return jsonify(error="Gmail App Password required."), 400

    if not subject:
        return jsonify(error="Subject required."), 400

    if not message.strip():
        return jsonify(error="Message required."), 400

    if not to:
        return jsonify(error="Add recipients first."), 400

    if len(to) > 25:
        return jsonify(error="Maximum 25 recipients."), 400

    bad = [x for x in to if not valid_email(x)]

    if bad:
        return jsonify(
            error="Invalid recipient email.",
            invalid=bad
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

            smtp.login(gmail, password)

            for email in to:

                try:

                    text = message.replace(
                        "{name}",
                        email.split("@")[0]
                    )

                    mail = MIMEText(
                        text,
                        "plain",
                        "utf-8"
                    )

                    mail["Subject"] = subject
                    mail["From"] = f"{sender} <{gmail}>"
                    mail["To"] = email

                    refused = smtp.sendmail(
                        gmail,
                        [email],
                        mail.as_string()
                    )

                    if refused:
                        failed.append({
                            "email": email
                        })
                    else:
                        sent.append({
                            "email": email
                        })

                except Exception as e:

                    failed.append({
                        "email": email,
                        "error": str(e)
                    })

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
            error="Gmail authentication failed."
        ), 401

    except Exception as e:

        return jsonify(
            error=str(e)
        ), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )

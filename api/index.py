import os
import ssl
import smtplib
import re
import secrets

from functools import wraps
from email.mime.text import MIMEText
from flask import Flask, render_template, request, jsonify, session, redirect

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=ROOT + "/templates",
    static_folder=ROOT + "/static"
)

app.secret_key = os.getenv(
    "SESSION_SECRET",
    "change-me"
)

LOGIN_PASS = os.getenv(
    "APP_LOGIN_PASSWORD",
    ""
)

EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def valid_email(email):
    return bool(
        EMAIL_RE.fullmatch(
            email.strip()
        )
    )


def clean_password(password):
    return "".join(
        str(password).split()
    )


def make_ref():
    return "#REF-" + secrets.token_hex(2).upper()


def login_required(function):

    @wraps(function)
    def check(*args, **kwargs):

        if not session.get("login"):

            if request.path.startswith("/api/"):
                return jsonify(
                    error="Login required"
                ), 401

            return redirect("/login")

        return function(*args, **kwargs)

    return check


# =========================
# LOGIN
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        if request.form.get("password") == LOGIN_PASS:

            session["login"] = True

            return redirect("/")

        return render_template(
            "login.html",
            error="Wrong password"
        )

    return render_template(
        "login.html"
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# =========================
# HOME
# =========================

@app.route("/")
@login_required
def home():

    return render_template(
        "index.html"
    )


# =========================
# PROTECTION STATUS
# =========================

@app.route("/api/protection")
@login_required
def protection():

    return jsonify(
        active=True,
        duplicate_filter=True,
        invalid_email_filter=True,
        controlled_sending=True
    )


# =========================
# SEND EMAIL
# =========================

@app.route("/api/send", methods=["POST"])
@login_required
def send():

    data = request.get_json() or {}

    name = str(
        data.get("sender_name", "")
    ).strip()

    gmail = str(
        data.get("gmail", "")
    ).strip().lower()

    password = clean_password(
        data.get("app_password", "")
    )

    subject = str(
        data.get("subject", "")
    ).strip()

    body = str(
        data.get("message", "")
    )

    raw_recipients = str(
        data.get("recipients", "")
    )

    recipients = re.split(
        r"[\s,;]+",
        raw_recipients.strip()
    )

    recipients = [
        x.lower()
        for x in recipients
        if x
    ]

    # Remove duplicates
    recipients = list(
        dict.fromkeys(recipients)
    )

    # -------------------------
    # Validation
    # -------------------------

    if not name:

        return jsonify(
            error="Sender name required."
        ), 400

    if not valid_email(gmail):

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

    if not body.strip():

        return jsonify(
            error="Message required."
        ), 400

    if not recipients:

        return jsonify(
            error="Add recipients."
        ), 400

    if len(recipients) > 25:

        return jsonify(
            error="Maximum 25 recipients."
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

    sent = []
    failed = []

    # =========================
    # SMTP CONNECTION
    # =========================

    try:

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=context,
            timeout=30
        ) as smtp:

            # Gmail authentication
            smtp.login(
                gmail,
                password
            )

            # =========================
            # SEND TO EACH RECIPIENT
            # =========================

            for recipient in recipients:

                try:

                    recipient_name = (
                        recipient
                        .split("@")[0]
                    )

                    # Unique reference for
                    # every individual email
                    ref = make_ref()

                    # Personalize message
                    text = body.replace(
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
                        f"{name} <{gmail}>"
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

            remaining=(
                len(recipients)
                - len(sent)
                - len(failed)
            ),

            sent_emails=sent,

            failed_emails=failed
        )

    except smtplib.SMTPAuthenticationError:

        return jsonify(
            error=(
                "Gmail authentication failed. "
                "Check your Gmail App Password."
            )
        ), 401

    except smtplib.SMTPConnectError:

        return jsonify(
            error=(
                "Could not connect to Gmail SMTP."
            )
        ), 502

    except Exception as error:

        return jsonify(
            error=str(error)
        ), 500


# =========================
# LOCAL RUN
# =========================

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

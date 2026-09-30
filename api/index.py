import os
import re
import ssl
import smtplib
import urllib.request
import urllib.parse
import json
import time
import secrets

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect
)

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
    "change-login-password"
)

TURNSTILE_SITE_KEY = os.getenv(
    "TURNSTILE_SITE_KEY",
    ""
)

TURNSTILE_SECRET_KEY = os.getenv(
    "TURNSTILE_SECRET_KEY",
    ""
)

COOLDOWN = 10
MAX_RECIPIENTS = 25


EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def valid_email(email):
    return bool(
        EMAIL_PATTERN.fullmatch(
            str(email).strip()
        )
    )


def auth_required(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        if session.get("login"):
            return func(*args, **kwargs)

        return redirect("/login")

    return wrapper


def parse_recipients(value):

    return list(
        dict.fromkeys(
            item.strip().lower()
            for item in re.split(
                r"[\s,;]+",
                str(value)
            )
            if item.strip()
        )
    )


# ==========================================
# SPINTAX
# ==========================================

SPINTAX_PATTERN = re.compile(
    r"\{([^{}]+)\}"
)


def spintax(text):

    def replace(match):

        choices = [
            item.strip()
            for item in match.group(1).split("|")
            if item.strip()
        ]

        if not choices:
            return match.group(0)

        return secrets.choice(choices)

    current = str(text)

    for _ in range(20):

        if not SPINTAX_PATTERN.search(current):
            break

        current = SPINTAX_PATTERN.sub(
            replace,
            current
        )

    return current


# ==========================================
# MESSAGE SAFETY
# ==========================================

def safe_message(subject, message):

    text = subject + " " + message

    if re.search(
        r"<\s*(script|iframe|object|embed)\b",
        text,
        re.I
    ):
        return False, "Unsafe HTML detected."

    if re.search(
        r"javascript\s*:",
        text,
        re.I
    ):
        return False, "Unsafe content detected."

    if len(
        re.findall(
            r"https?://",
            text,
            re.I
        )
    ) > 5:
        return False, "Too many links in message."

    if re.search(
        r"(.)\1{10,}",
        text
    ):
        return False, "Repeated characters detected."

    return True, "OK"


# ==========================================
# CLOUDFLARE TURNSTILE
# ==========================================

def verify_turnstile(token, remote_ip):

    if not TURNSTILE_SECRET_KEY:

        return (
            False,
            "Turnstile secret key is not configured."
        )

    if not token:

        return (
            False,
            "Please complete the Cloudflare verification."
        )

    payload = urllib.parse.urlencode({

        "secret":
            TURNSTILE_SECRET_KEY,

        "response":
            token,

        "remoteip":
            remote_ip or ""

    }).encode()

    try:

        req = urllib.request.Request(

            "https://challenges.cloudflare.com/"
            "turnstile/v0/siteverify",

            data=payload,

            headers={
                "Content-Type":
                "application/x-www-form-urlencoded"
            },

            method="POST"
        )

        with urllib.request.urlopen(
            req,
            timeout=10
        ) as response:

            result = json.loads(
                response
                .read()
                .decode("utf-8")
            )

        if result.get("success"):

            return True, "OK"

        return (
            False,
            "Cloudflare verification failed."
        )

    except Exception:

        return (
            False,
            "Cloudflare verification could not be completed."
        )


# ==========================================
# LOGIN
# ==========================================

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

        if secrets.compare_digest(
            password,
            LOGIN
        ):

            session.clear()

            session["login"] = 1
            session["last_send"] = 0

            return redirect("/")

        return render_template(
            "login.html",
            error="Wrong password.",
            turnstile_site_key=TURNSTILE_SITE_KEY
        )

    return render_template(
        "login.html",
        error=None,
        turnstile_site_key=TURNSTILE_SITE_KEY
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ==========================================
# HOME
# ==========================================

@app.route("/")
@auth_required
def home():

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY
    )


# ==========================================
# SEND EMAIL
# ==========================================

@app.route(
    "/api/send",
    methods=["POST"]
)
@auth_required
def send():

    now = time.time()

    last_send = session.get(
        "last_send",
        0
    )

    if now - last_send < COOLDOWN:

        wait = int(
            COOLDOWN -
            (now - last_send)
        ) + 1

        return jsonify(
            error=
            f"Please wait {wait} seconds before sending again."
        ), 429


    data = request.get_json() or {}


    # --------------------------------------
    # CLOUDFLARE
    # --------------------------------------

    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    ).strip()


    verified, reason = verify_turnstile(

        turnstile_token,

        request.headers.get(
            "CF-Connecting-IP",
            request.remote_addr
        )

    )


    if not verified:

        return jsonify(
            error=reason
        ), 403


    # --------------------------------------
    # INPUTS
    # --------------------------------------

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


    recipients = parse_recipients(
        data.get(
            "recipients",
            ""
        )
    )


    # --------------------------------------
    # VALIDATION
    # --------------------------------------

    if not sender:

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


    if not message.strip():

        return jsonify(
            error="Message required."
        ), 400


    if not recipients:

        return jsonify(
            error="Add recipients first."
        ), 400


    if len(recipients) > MAX_RECIPIENTS:

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

            error=
            "Invalid recipient email.",

            invalid=invalid

        ), 400


    # --------------------------------------
    # MESSAGE SAFETY
    # --------------------------------------

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


            session["last_send"] = time.time()


            for email in recipients:

                try:

                    # --------------------------
                    # SPINTAX
                    # --------------------------

                    personalized_subject = spintax(
                        subject
                    )


                    personalized_message = spintax(
                        message
                    )


                    # --------------------------
                    # {name}
                    # --------------------------

                    personalized_message = (
                        personalized_message
                        .replace(
                            "{name}",
                            email.split("@")[0]
                        )
                    )


                    # --------------------------
                    # EMAIL
                    # --------------------------

                    mail = MIMEText(

                        personalized_message,

                        "plain",

                        "utf-8"

                    )


                    mail["Subject"] = (
                        personalized_subject
                    )


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
                            "email": email
                        })

                    else:

                        sent.append({
                            "email": email
                        })


                except Exception as error:

                    failed.append({

                        "email":
                            email,

                        "error":
                            str(error)

                    })


        return jsonify(

            success=True,

            total=len(recipients),

            sent=len(sent),

            failed=len(failed),

            sent_emails=sent,

            failed_emails=failed

        )


    except smtplib.SMTPAuthenticationError:

        return jsonify(

            error=
            "Gmail authentication failed."

        ), 401


    except Exception as error:

        return jsonify(

            error=str(error)

        ), 500


# ==========================================
# LOCAL
# ==========================================

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

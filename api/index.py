import os
import re
import ssl
import smtplib
import secrets
import json

from functools import wraps
from email.mime.text import MIMEText

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    Response,
    stream_with_context,
)


app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)


# --------------------------------------------------
# Security / Login
# --------------------------------------------------

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    "change-this-secret"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True
)

LOGIN_PASSWORD = os.environ.get(
    "APP_LOGIN_PASSWORD",
    ""
)


# --------------------------------------------------
# Email settings
# --------------------------------------------------

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

MAX_RECIPIENTS = 25

EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def valid_email(value):
    return bool(
        EMAIL_RE.fullmatch(
            str(value).strip()
        )
    )


def clean_app_password(value):
    # Removes spaces accidentally copied into
    # a Gmail App Password.
    return "".join(
        str(value).split()
    )


def make_ref():
    """
    Creates a different reference for every email.

    Example:
    #REF-8A42F1C7
    """

    return (
        "#REF-"
        + secrets.token_hex(4).upper()
    )


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


def parse_recipients(raw):

    items = re.split(
        r"[\s,;]+",
        str(raw).strip()
    )

    result = []
    seen = set()

    for item in items:

        email = item.strip().lower()

        if not email:
            continue

        if email not in seen:

            seen.add(email)
            result.append(email)

    return result


def get_recipient_name(email):

    """
    Uses the part before @ as a simple recipient name.

    example:
    rahul123@gmail.com -> rahul123
    """

    return email.split("@")[0]


# --------------------------------------------------
# Message checks
# --------------------------------------------------

def message_checks(subject, message):

    text = (
        str(subject)
        + " "
        + str(message)
    )

    issues = []

    if len(str(subject)) > 200:

        issues.append(
            "Subject is unusually long."
        )

    if re.search(
        r"(.)\1{7,}",
        text
    ):

        issues.append(
            "Repeated characters detected."
        )

    link_count = len(
        re.findall(
            r"https?://",
            text,
            flags=re.I
        )
    )

    if link_count > 5:

        issues.append(
            "Message contains many links."
        )

    if re.search(
        r"<script|javascript:|<iframe",
        text,
        flags=re.I
    ):

        issues.append(
            "Unsafe HTML content detected."
        )

    return issues


# --------------------------------------------------
# Login
# --------------------------------------------------

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if session.get("logged_in"):

        return redirect("/")

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        if (
            LOGIN_PASSWORD
            and secrets.compare_digest(
                password,
                LOGIN_PASSWORD
            )
        ):

            session.clear()

            session["logged_in"] = True

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


# --------------------------------------------------
# Home
# --------------------------------------------------

@app.route("/")
@protected
def home():

    return render_template(
        "index.html"
    )


# --------------------------------------------------
# Message checking API
# --------------------------------------------------

@app.route(
    "/api/check-message",
    methods=["POST"]
)
@protected
def check_message():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    subject = str(
        data.get(
            "subject",
            ""
        )
    )

    message = str(
        data.get(
            "message",
            ""
        )
    )

    issues = message_checks(
        subject,
        message
    )

    return jsonify(
        safe=not bool(issues),
        issues=issues
    )


# --------------------------------------------------
# SEND EMAILS
# --------------------------------------------------

@app.route(
    "/api/send",
    methods=["POST"]
)
@protected
def send():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    sender_name = str(
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

    app_password = clean_app_password(
        data.get(
            "app_password",
            ""
        )
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


    # --------------------------------------------------
    # Validation
    # --------------------------------------------------

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
            error="Invalid recipient email.",
            invalid=invalid
        ), 400


    issues = message_checks(
        subject,
        message
    )


    if issues:

        return jsonify(
            error="Please review the message before sending.",
            issues=issues
        ), 400


    # --------------------------------------------------
    # Streaming response
    # --------------------------------------------------

    @stream_with_context
    def generate():

        sent_count = 0
        failed_count = 0


        try:

            context = (
                ssl.create_default_context()
            )


            with smtplib.SMTP_SSL(
                SMTP_HOST,
                SMTP_PORT,
                context=context,
                timeout=30
            ) as smtp:


                # --------------------------------------
                # Gmail login
                # --------------------------------------

                try:

                    smtp.login(
                        gmail,
                        app_password
                    )

                except smtplib.SMTPAuthenticationError:

                    yield json.dumps({
                        "type": "error",
                        "error":
                            "Gmail authentication failed. Check your App Password."
                    }) + "\n"

                    return


                # --------------------------------------
                # Send one recipient at a time
                # --------------------------------------

                for recipient in recipients:


                    # IMPORTANT:
                    # A completely new reference is
                    # generated for every recipient.
                    ref = make_ref()


                    recipient_name = (
                        get_recipient_name(
                            recipient
                        )
                    )


                    # ----------------------------------
                    # Replace placeholders
                    # ----------------------------------

                    final_subject = (
                        subject
                        .replace(
                            "{name}",
                            recipient_name
                        )
                        .replace(
                            "{ref}",
                            ref
                        )
                    )


                    final_message = (
                        message
                        .replace(
                            "{name}",
                            recipient_name
                        )
                        .replace(
                            "{ref}",
                            ref
                        )
                    )


                    try:

                        mail = MIMEText(
                            final_message,
                            "plain",
                            "utf-8"
                        )


                        mail["Subject"] = (
                            final_subject
                        )


                        mail["From"] = (
                            sender_name
                            + " <"
                            + gmail
                            + ">"
                        )


                        mail["To"] = recipient


                        refused = smtp.sendmail(
                            gmail,
                            [recipient],
                            mail.as_string()
                        )


                        # ----------------------------------
                        # Failed recipient
                        # ----------------------------------

                        if refused:

                            failed_count += 1

                            yield json.dumps({
                                "type": "failed",

                                "email":
                                    recipient,

                                "ref":
                                    ref,

                                "error":
                                    str(refused),

                                "sent":
                                    sent_count,

                                "failed":
                                    failed_count,

                                "total":
                                    len(recipients)

                            }) + "\n"


                        # ----------------------------------
                        # Successful recipient
                        # ----------------------------------

                        else:

                            sent_count += 1

                            yield json.dumps({
                                "type": "sent",

                                "email":
                                    recipient,

                                "ref":
                                    ref,

                                "sent":
                                    sent_count,

                                "failed":
                                    failed_count,

                                "total":
                                    len(recipients)

                            }) + "\n"


                    except Exception as error:

                        failed_count += 1

                        yield json.dumps({
                            "type": "failed",

                            "email":
                                recipient,

                            "ref":
                                ref,

                            "error":
                                str(error),

                            "sent":
                                sent_count,

                            "failed":
                                failed_count,

                            "total":
                                len(recipients)

                        }) + "\n"


                # --------------------------------------
                # Completed
                # --------------------------------------

                yield json.dumps({

                    "type":
                        "done",

                    "sent":
                        sent_count,

                    "failed":
                        failed_count,

                    "total":
                        len(recipients)

                }) + "\n"


        except Exception as error:

            yield json.dumps({

                "type":
                    "error",

                "error":
                    str(error),

                "sent":
                    sent_count,

                "failed":
                    failed_count

            }) + "\n"


    return Response(

        generate(),

        mimetype=
            "application/x-ndjson",

        headers={
            "Cache-Control":
                "no-cache",

            "X-Accel-Buffering":
                "no"
        }

    )


# --------------------------------------------------
# Local development
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",

        port=int(
            os.environ.get(
                "PORT",
                "5000"
            )
        )
    )

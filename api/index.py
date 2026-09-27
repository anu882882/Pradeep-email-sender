import os
import re
import ssl
import smtplib
import secrets

from functools import wraps
from email.mime.text import MIMEText

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect
)


# =========================================================
# PATHS
# =========================================================

BASE = os.getcwd()

TEMPLATES_DIR = os.path.join(
    BASE,
    "templates"
)

STATIC_DIR = os.path.join(
    BASE,
    "static"
)


# =========================================================
# FLASK
# =========================================================

app = Flask(
    __name__,
    template_folder=TEMPLATES_DIR,
    static_folder=STATIC_DIR
)


# =========================================================
# SESSION
# =========================================================

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    "change-this-secret"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True
)


# =========================================================
# LOGIN PASSWORD
# =========================================================

LOGIN_PASSWORD = os.environ.get(
    "APP_LOGIN_PASSWORD",
    ""
)


# =========================================================
# EMAIL SETTINGS
# =========================================================

SMTP_HOST = "smtp.gmail.com"

SMTP_PORT = 465

MAX_RECIPIENTS = 25


# =========================================================
# EMAIL VALIDATION
# =========================================================

EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def valid_email(value):

    return bool(
        EMAIL_RE.fullmatch(
            str(value).strip()
        )
    )


# =========================================================
# APP PASSWORD CLEANER
# =========================================================

def clean_app_password(value):

    return "".join(
        str(value).split()
    )


# =========================================================
# UNIQUE REFERENCE
# =========================================================

def make_ref():

    return (
        "#REF-"
        + secrets.token_hex(4).upper()
    )


# Example:
# #REF-5395A6CA


# =========================================================
# RECIPIENT NAME
# =========================================================

def get_recipient_name(email):

    return email.split("@")[0]


# =========================================================
# RECIPIENT PARSER
# =========================================================

def parse_recipients(raw):

    items = re.split(
        r"[\s,;]+",
        str(raw).strip()
    )

    result = []

    seen = set()

    for item in items:

        email = (
            item
            .strip()
            .lower()
        )

        if not email:
            continue

        if email not in seen:

            seen.add(email)

            result.append(email)

    return result


# =========================================================
# LOGIN PROTECTION
# =========================================================

def protected(view):

    @wraps(view)
    def wrapper(*args, **kwargs):

        if not session.get(
            "logged_in"
        ):

            if request.path.startswith(
                "/api/"
            ):

                return jsonify(
                    error="Login required."
                ), 401

            return redirect(
                "/login"
            )

        return view(
            *args,
            **kwargs
        )

    return wrapper


# =========================================================
# BASIC MESSAGE CHECK
# =========================================================

def message_checks(
    subject,
    message
):

    text = (
        str(subject)
        + " "
        + str(message)
    )

    issues = []


    # Very long subject

    if len(subject) > 200:

        issues.append(
            "Subject is unusually long."
        )


    # Repeated characters

    if re.search(
        r"(.)\1{7,}",
        text
    ):

        issues.append(
            "Repeated characters detected."
        )


    # Excessive links

    links = re.findall(
        r"https?://",
        text,
        flags=re.I
    )

    if len(links) > 5:

        issues.append(
            "Message contains many links."
        )


    # Unsafe HTML/script

    if re.search(
        r"<script|javascript:|<iframe",
        text,
        flags=re.I
    ):

        issues.append(
            "Unsafe HTML content detected."
        )


    return issues


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if session.get(
        "logged_in"
    ):

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


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        "/login"
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
@protected
def home():

    return render_template(
        "index.html"
    )


# =========================================================
# MESSAGE CHECK API
# =========================================================

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


# =========================================================
# SEND EMAILS
# =========================================================

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


    # -----------------------------------------------------
    # INPUTS
    # -----------------------------------------------------

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


    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

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


    # -----------------------------------------------------
    # INVALID RECIPIENTS
    # -----------------------------------------------------

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


    # -----------------------------------------------------
    # BASIC MESSAGE CHECK
    # -----------------------------------------------------

    issues = message_checks(
        subject,
        message
    )


    if issues:

        return jsonify(
            error="Please review the message before sending.",
            issues=issues
        ), 400


    # -----------------------------------------------------
    # RESULTS
    # -----------------------------------------------------

    sent = []

    failed = []


    # -----------------------------------------------------
    # SMTP CONNECTION
    # -----------------------------------------------------

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


            # -------------------------------------------------
            # GMAIL LOGIN
            # -------------------------------------------------

            try:

                smtp.login(
                    gmail,
                    app_password
                )

            except smtplib.SMTPAuthenticationError:

                return jsonify(
                    error=(
                        "Gmail authentication failed. "
                        "Check your App Password."
                    )
                ), 401


            # -------------------------------------------------
            # SEND EACH RECIPIENT
            # -------------------------------------------------

            for email in recipients:


                # Unique reference for THIS recipient

                ref = make_ref()


                # Recipient name

                name = get_recipient_name(
                    email
                )


                # -------------------------------------------------
                # Replace {name}
                # -------------------------------------------------

                final_message = (
                    message.replace(
                        "{name}",
                        name
                    )
                )


                # -------------------------------------------------
                # Support {ref} if user happens to use it
                # -------------------------------------------------

                used_ref_placeholder = (
                    "{ref}" in final_message
                )


                final_message = (
                    final_message.replace(
                        "{ref}",
                        ref
                    )
                )


                # -------------------------------------------------
                # AUTOMATIC REFERENCE
                #
                # If user did NOT use {ref},
                # automatically append:
                #
                # Reference: #REF-XXXXXXXX
                # -------------------------------------------------

                if not used_ref_placeholder:

                    final_message = (
                        final_message.rstrip()
                        + "\n\n"
                        + "Reference: "
                        + ref
                    )


                # -------------------------------------------------
                # Subject placeholders
                # -------------------------------------------------

                final_subject = (
                    subject
                    .replace(
                        "{name}",
                        name
                    )
                    .replace(
                        "{ref}",
                        ref
                    )
                )


                # -------------------------------------------------
                # MIME EMAIL
                # -------------------------------------------------

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


                mail["To"] = email


                # -------------------------------------------------
                # SEND
                # -------------------------------------------------

                try:

                    refused = smtp.sendmail(
                        gmail,
                        [email],
                        mail.as_string()
                    )


                    if refused:

                        failed.append({

                            "email":
                                email,

                            "ref":
                                ref,

                            "error":
                                str(refused)

                        })


                    else:

                        sent.append({

                            "email":
                                email,

                            "ref":
                                ref

                        })


                except Exception as error:

                    failed.append({

                        "email":
                            email,

                        "ref":
                            ref,

                        "error":
                            str(error)

                    })


        # -----------------------------------------------------
        # FINAL RESPONSE
        # -----------------------------------------------------

        return jsonify(

            success=True,

            total=len(recipients),

            sent=len(sent),

            failed=len(failed),

            remaining=0,

            sent_emails=sent,

            failed_emails=failed

        )


    except Exception as error:

        return jsonify(
            error=str(error)
        ), 500


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

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

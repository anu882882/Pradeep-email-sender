import os
import re
import ssl
import smtplib
import secrets
import json
import time
import urllib.request
import urllib.parse

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
from email.utils import formataddr

from html.parser import HTMLParser


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)


app.secret_key = os.getenv(
    "SESSION_SECRET",
    "change-this-secret"
)


# =========================================================
# ENVIRONMENT SETTINGS
# =========================================================

LOGIN_PASSWORD = os.getenv(
    "APP_LOGIN_PASSWORD",
    "change-login-password"
)


TURNSTILE_SECRET_KEY = os.getenv(
    "TURNSTILE_SECRET_KEY",
    ""
)


MAX_RECIPIENTS = 25


# Conservative interval between messages.
# This does not bypass Gmail sending limits.
MIN_SEND_INTERVAL = 2.0


EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


# =========================================================
# EMAIL VALIDATION
# =========================================================

def is_valid_email(email):
    """
    Basic email address validation.
    """

    if not email:
        return False

    email = email.strip()

    return bool(
        EMAIL_PATTERN.fullmatch(email)
    )


# =========================================================
# RECIPIENT PARSER
# =========================================================

def parse_recipients(value):
    """
    Accepts recipient addresses separated by:

        spaces
        commas
        semicolons
        new lines

    Duplicate addresses are removed.
    Maximum 25 addresses are accepted.
    """

    if not value:
        return []

    parts = re.split(
        r"[\s,;]+",
        str(value)
    )

    result = []

    seen = set()

    for item in parts:

        email = item.strip().lower()

        if not email:
            continue

        if email in seen:
            continue

        seen.add(email)

        result.append(email)

        if len(result) >= MAX_RECIPIENTS:
            break

    return result


# =========================================================
# LOGIN DECORATOR
# =========================================================

def authentication_required(function):
    """
    Only authenticated users can access protected routes.
    """

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("authenticated"):

            return redirect(
                "/login"
            )

        return function(
            *args,
            **kwargs
        )

    return wrapper


# =========================================================
# SPINTAX
# =========================================================

def resolve_spintax(text):
    """
    Supports simple content variation such as:

        {Hello|Hi|Hey}

    This is ordinary content variation and is not intended
    to bypass spam filters.
    """

    if not text:
        return ""

    pattern = re.compile(
        r"\{([^{}|]+(?:\|[^{}|]+)+)\}"
    )

    def replace_match(match):

        choices = match.group(1).split("|")

        return secrets.choice(
            choices
        )

    previous = text

    for _ in range(20):

        current = pattern.sub(
            replace_match,
            previous
        )

        if current == previous:
            break

        previous = current

    return previous


# =========================================================
# SAFE HTML PARSER
# =========================================================

class SafeHTMLParser(HTMLParser):

    ALLOWED_TAGS = {
        "div",
        "p",
        "br",
        "strong",
        "b",
        "em",
        "i",
        "u",
        "span",
        "a",
        "ul",
        "ol",
        "li"
    }


    def __init__(self):

        super().__init__(
            convert_charrefs=True
        )

        self.output = []


    def handle_starttag(
        self,
        tag,
        attrs
    ):

        if tag not in self.ALLOWED_TAGS:
            return

        attributes = []

        for name, value in attrs:

            if tag == "a":

                if name not in {
                    "href",
                    "target",
                    "rel"
                }:
                    continue

                if name == "href":

                    if not value:
                        continue

                    lower_value = (
                        str(value).lower()
                    )

                    if not lower_value.startswith(
                        (
                            "https://",
                            "http://",
                            "mailto:"
                        )
                    ):
                        continue

            elif tag == "span":

                if name != "class":
                    continue

            else:

                continue

            safe_value = str(
                value
            ).replace(
                '"',
                "&quot;"
            )

            attributes.append(
                f' {name}="{safe_value}"'
            )

        self.output.append(
            "<"
            + tag
            + "".join(attributes)
            + ">"
        )


    def handle_endtag(self, tag):

        if tag in self.ALLOWED_TAGS:

            self.output.append(
                f"</{tag}>"
            )


    def handle_data(self, data):

        self.output.append(
            data
        )


# =========================================================
# HTML SANITIZER
# =========================================================

def sanitize_html(value):

    parser = SafeHTMLParser()

    parser.feed(
        value or ""
    )

    parser.close()

    return "".join(
        parser.output
    )


# =========================================================
# HTML TO PLAIN TEXT
# =========================================================

def html_to_plain_text(html):

    if not html:
        return ""

    text = re.sub(
        r"<br\s*/?>",
        "\n",
        html,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r"</p\s*>",
        "\n\n",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r"</div\s*>",
        "\n",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r"</li\s*>",
        "\n",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r"<[^>]+>",
        "",
        text
    )

    return text.strip()


# =========================================================
# CLOUDFLARE TURNSTILE
# =========================================================

def verify_turnstile(token):

    # If no Turnstile secret is configured,
    # Turnstile verification is skipped.

    if not TURNSTILE_SECRET_KEY:

        return True


    if not token:

        return False


    try:

        payload = urllib.parse.urlencode(
            {
                "secret": TURNSTILE_SECRET_KEY,
                "response": token
            }
        ).encode(
            "utf-8"
        )


        request_object = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=payload,
            method="POST"
        )


        with urllib.request.urlopen(
            request_object,
            timeout=10
        ) as response:

            response_data = response.read()

            result = json.loads(
                response_data.decode(
                    "utf-8"
                )
            )


        return bool(
            result.get(
                "success"
            )
        )


    except Exception as error:

        print(
            "TURNSTILE ERROR:",
            repr(error)
        )

        return False


# =========================================================
# LOGIN PAGE
# =========================================================

@app.route(
    "/login",
    methods=[
        "GET",
        "POST"
    ]
)
def login():

    if request.method == "POST":

        submitted_password = str(
            request.form.get(
                "password",
                ""
            )
        )


        if secrets.compare_digest(
            submitted_password,
            str(
                LOGIN_PASSWORD
            )
        ):

            session.clear()

            session[
                "authenticated"
            ] = True

            return redirect(
                "/"
            )


        return render_template(
            "login.html",
            error="Invalid password."
        )


    return render_template(
        "login.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/logout"
)
def logout():

    session.clear()

    return redirect(
        "/login"
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
@authentication_required
def dashboard():

    return render_template(
        "index.html",
        turnstile_site_key=os.getenv(
            "TURNSTILE_SITE_KEY",
            ""
        )
    )


# =========================================================
# SEND EMAIL API
# =========================================================

@app.post(
    "/api/send"
)
@authentication_required
def send_email():

    print(
        "--------------------------------------------------"
    )

    print(
        "NEW EMAIL SEND REQUEST"
    )

    print(
        "--------------------------------------------------"
    )


    # -----------------------------------------------------
    # READ REQUEST
    # -----------------------------------------------------

    data = request.get_json(
        silent=True
    )


    if not isinstance(
        data,
        dict
    ):

        print(
            "REQUEST ERROR: Invalid JSON request."
        )

        return jsonify(
            {
                "error":
                "Invalid request data."
            }
        ), 400


    # -----------------------------------------------------
    # CLOUDFLARE VERIFICATION
    # -----------------------------------------------------

    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    )


    if not verify_turnstile(
        turnstile_token
    ):

        print(
            "TURNSTILE ERROR: Verification failed."
        )

        return jsonify(
            {
                "error":
                "Cloudflare verification failed. "
                "Please complete the verification again."
            }
        ), 403


    # -----------------------------------------------------
    # READ FORM VALUES
    # -----------------------------------------------------

    sender_name = str(
        data.get(
            "sender_name",
            ""
        )
    ).strip()


    gmail_address = str(
        data.get(
            "gmail",
            ""
        )
    ).strip()


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


    original_html = str(
        data.get(
            "message_html",
            ""
        )
    )


    message_html = sanitize_html(
        original_html
    )


    raw_recipients = data.get(
        "recipients",
        []
    )


    # -----------------------------------------------------
    # BASIC VALIDATION
    # -----------------------------------------------------

    if not is_valid_email(
        gmail_address
    ):

        print(
            "VALIDATION ERROR: Invalid Gmail address."
        )

        return jsonify(
            {
                "error":
                "Please enter a valid Gmail address."
            }
        ), 400


    if not app_password:

        print(
            "VALIDATION ERROR: Missing App Password."
        )

        return jsonify(
            {
                "error":
                "Please enter the Gmail App Password."
            }
        ), 400


    if not subject:

        print(
            "VALIDATION ERROR: Missing subject."
        )

        return jsonify(
            {
                "error":
                "Please enter an email subject."
            }
        ), 400


    if not message_html.strip():

        print(
            "VALIDATION ERROR: Missing message."
        )

        return jsonify(
            {
                "error":
                "Please enter the message body."
            }
        ), 400


    # -----------------------------------------------------
    # RECIPIENT PROCESSING
    # -----------------------------------------------------

    if isinstance(
        raw_recipients,
        str
    ):

        recipient_list = parse_recipients(
            raw_recipients
        )

    elif isinstance(
        raw_recipients,
        list
    ):

        recipient_list = parse_recipients(
            " ".join(
                str(item)
                for item in raw_recipients
            )
        )

    else:

        recipient_list = []


    if not recipient_list:

        print(
            "VALIDATION ERROR: No recipients."
        )

        return jsonify(
            {
                "error":
                "No recipients were found."
            }
        ), 400


    print(
        "Recipient count:",
        len(recipient_list)
    )


    # -----------------------------------------------------
    # VALID / INVALID RECIPIENTS
    # -----------------------------------------------------

    valid_recipients = []

    failed = []


    for recipient in recipient_list:

        if is_valid_email(
            recipient
        ):

            valid_recipients.append(
                recipient
            )

        else:

            failed.append(
                {
                    "email": recipient,
                    "error":
                    "Invalid email address."
                }
            )


    if not valid_recipients:

        return jsonify(
            {
                "error":
                "No valid recipient email addresses were found.",
                "failed":
                failed
            }
        ), 400


    # -----------------------------------------------------
    # RESULT ARRAYS
    # -----------------------------------------------------

    sent = []


    smtp = None


    # -----------------------------------------------------
    # SMTP CONNECTION
    # -----------------------------------------------------

    try:

        print(
            "Connecting to smtp.gmail.com:465 ..."
        )


        smtp_context = ssl.create_default_context()


        smtp = smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=smtp_context,
            timeout=30
        )


        print(
            "SMTP connection established."
        )


        print(
            "Logging into Gmail..."
        )


        smtp.login(
            gmail_address,
            app_password
        )


        print(
            "Gmail authentication successful."
        )


        # -------------------------------------------------
        # SEND EMAILS
        # -------------------------------------------------

        last_send_time = 0


        for index, recipient in enumerate(
            valid_recipients,
            start=1
        ):

            print(
                "Processing recipient",
                index,
                "of",
                len(valid_recipients),
                ":",
                recipient
            )


            # Conservative pacing.

            elapsed = (
                time.monotonic()
                - last_send_time
            )


            if (
                last_send_time > 0
                and
                elapsed < MIN_SEND_INTERVAL
            ):

                time.sleep(
                    MIN_SEND_INTERVAL
                    - elapsed
                )


            try:

                first_name = recipient.split(
                    "@",
                    1
                )[0]


                personalized_html = (
                    message_html.replace(
                        "{name}",
                        first_name
                    )
                )


                personalized_html = (
                    resolve_spintax(
                        personalized_html
                    )
                )


                personalized_subject = (
                    resolve_spintax(
                        subject
                    )
                )


                plain_body = (
                    html_to_plain_text(
                        personalized_html
                    )
                )


                # -----------------------------------------
                # BUILD EMAIL
                # -----------------------------------------

                email_message = MIMEMultipart(
                    "alternative"
                )


                if sender_name:

                    email_message["From"] = (
                        formataddr(
                            (
                                sender_name,
                                gmail_address
                            )
                        )
                    )

                else:

                    email_message["From"] = (
                        gmail_address
                    )


                email_message["To"] = recipient


                email_message["Subject"] = (
                    personalized_subject
                )


                email_message.attach(
                    MIMEText(
                        plain_body,
                        "plain",
                        "utf-8"
                    )
                )


                email_message.attach(
                    MIMEText(
                        personalized_html,
                        "html",
                        "utf-8"
                    )
                )


                # -----------------------------------------
                # SMTP SEND
                # -----------------------------------------

                print(
                    "Sending message to:",
                    recipient
                )


                smtp.sendmail(
                    gmail_address,
                    [recipient],
                    email_message.as_string()
                )


                sent.append(
                    recipient
                )


                last_send_time = (
                    time.monotonic()
                )


                print(
                    "SUCCESS:",
                    recipient
                )


            except Exception as recipient_error:

                error_text = str(
                    recipient_error
                ).strip()


                if not error_text:

                    error_text = (
                        repr(
                            recipient_error
                        )
                    )


                print(
                    "RECIPIENT ERROR:",
                    recipient,
                    error_text
                )


                failed.append(
                    {
                        "email": recipient,
                        "error": error_text
                    }
                )


        # -------------------------------------------------
        # FINAL RESPONSE
        # -------------------------------------------------

        print(
            "--------------------------------------------------"
        )

        print(
            "SEND FINISHED"
        )

        print(
            "Sent:",
            len(sent)
        )

        print(
            "Failed:",
            len(failed)
        )

        print(
            "--------------------------------------------------"
        )


        return jsonify(
            {
                "ok": True,

                "total":
                len(recipient_list),

                "sent":
                sent,

                "failed":
                failed
            }
        )


    # =====================================================
    # GMAIL AUTHENTICATION ERROR
    # =====================================================

    except smtplib.SMTPAuthenticationError as error:

        error_text = str(
            error
        )


        print(
            "SMTP AUTHENTICATION ERROR:",
            repr(error)
        )


        return jsonify(
            {
                "error":
                "Gmail authentication failed. "
                "Please check the Gmail address and "
                "16-character Gmail App Password. "
                "Server response: "
                + error_text
            }
        ), 502


    # =====================================================
    # SMTP CONNECTION ERROR
    # =====================================================

    except smtplib.SMTPConnectError as error:

        error_text = str(
            error
        )


        print(
            "SMTP CONNECTION ERROR:",
            repr(error)
        )


        return jsonify(
            {
                "error":
                "Could not connect to Gmail SMTP. "
                "Server response: "
                + error_text
            }
        ), 502


    # =====================================================
    # SMTP SERVER ERROR
    # =====================================================

    except smtplib.SMTPServerDisconnected as error:

        error_text = str(
            error
        )


        print(
            "SMTP DISCONNECTED:",
            repr(error)
        )


        return jsonify(
            {
                "error":
                "Gmail SMTP disconnected the connection. "
                "Server response: "
                + error_text
            }
        ), 502


    # =====================================================
    # GENERAL SMTP ERROR
    # =====================================================

    except smtplib.SMTPException as error:

        error_text = str(
            error
        )


        print(
            "GENERAL SMTP ERROR:",
            repr(error)
        )


        return jsonify(
            {
                "error":
                "Gmail SMTP error: "
                + error_text
            }
        ), 502


    # =====================================================
    # GENERAL ERROR
    # =====================================================

    except Exception as error:

        error_text = str(
            error
        ).strip()


        if not error_text:

            error_text = repr(
                error
            )


        print(
            "UNEXPECTED EMAIL ERROR:",
            repr(error)
        )


        return jsonify(
            {
                "error":
                "Email sending failed: "
                + error_text
            }
        ), 502


    # =====================================================
    # SMTP CLEANUP
    # =====================================================

    finally:

        if smtp is not None:

            try:

                smtp.quit()

                print(
                    "SMTP connection closed."
                )

            except Exception as close_error:

                print(
                    "SMTP close warning:",
                    repr(close_error)
                )


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

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

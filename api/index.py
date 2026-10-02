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


# ---------------------------------------------------------
# APPLICATION
# ---------------------------------------------------------

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

app.secret_key = os.getenv(
    "SESSION_SECRET",
    "change-this-secret"
)


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

LOGIN_PASSWORD = os.getenv(
    "APP_LOGIN_PASSWORD",
    "change-login-password"
)

TURNSTILE_SECRET_KEY = os.getenv(
    "TURNSTILE_SECRET_KEY",
    ""
)

MAX_RECIPIENTS = 25

MIN_SEND_INTERVAL = 2.0

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


# ---------------------------------------------------------
# BASIC HELPERS
# ---------------------------------------------------------

def is_valid_email(email):
    """
    Basic email-format validation.
    """

    if not email:
        return False

    email = email.strip()

    return bool(
        EMAIL_PATTERN.fullmatch(email)
    )


def parse_recipients(value):
    """
    Accepts:
        email1@example.com
        email2@example.com,email3@example.com
        email4@example.com;email5@example.com

    Removes duplicates while preserving order.
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


def authentication_required(function):
    """
    Protect dashboard/API routes behind login.
    """

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("authenticated"):
            return redirect("/login")

        return function(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------
# SPINTAX
# ---------------------------------------------------------

def resolve_spintax(text):
    """
    Supports simple syntax:

        {Hello|Hi|Hey}

    This is intended for normal content variation,
    not spam-filter evasion.
    """

    if not text:
        return ""

    pattern = re.compile(
        r"\{([^{}|]+(?:\|[^{}|]+)+)\}"
    )

    def replace_match(match):

        choices = match.group(1).split("|")

        return secrets.choice(choices)

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


# ---------------------------------------------------------
# HTML SANITIZER
# ---------------------------------------------------------

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

    def handle_starttag(self, tag, attrs):

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

                    lower_value = value.lower()

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

            safe_value = str(value).replace(
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

        self.output.append(data)


def sanitize_html(value):

    parser = SafeHTMLParser()

    parser.feed(
        value or ""
    )

    parser.close()

    return "".join(
        parser.output
    )


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


# ---------------------------------------------------------
# CLOUDFLARE TURNSTILE
# ---------------------------------------------------------

def verify_turnstile(token):

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
        ).encode("utf-8")

        request_object = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=payload,
            method="POST"
        )

        with urllib.request.urlopen(
            request_object,
            timeout=10
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

        return bool(
            data.get("success")
        )

    except Exception:

        return False


# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------

@app.route(
    "/login",
    methods=["GET", "POST"]
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
            str(LOGIN_PASSWORD)
        ):

            session.clear()

            session["authenticated"] = True

            return redirect("/")

        return render_template(
            "login.html",
            error="Invalid password."
        )

    return render_template(
        "login.html"
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ---------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# SEND EMAIL
# ---------------------------------------------------------

@app.post("/api/send")
@authentication_required
def send_email():

    data = request.get_json(
        silent=True
    ) or {}

    # -----------------------------------------------------
    # TURNSTILE
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

        return jsonify(
            {
                "error":
                "Cloudflare verification failed."
            }
        ), 403

    # -----------------------------------------------------
    # INPUTS
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

    message_html = sanitize_html(
        str(
            data.get(
                "message_html",
                ""
            )
        )
    )

    raw_recipients = data.get(
        "recipients",
        []
    )

    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not is_valid_email(
        gmail_address
    ):

        return jsonify(
            {
                "error":
                "Please enter a valid Gmail address."
            }
        ), 400

    if not app_password:

        return jsonify(
            {
                "error":
                "Please enter the Gmail App Password."
            }
        ), 400

    if not subject:

        return jsonify(
            {
                "error":
                "Please enter an email subject."
            }
        ), 400

    if not message_html.strip():

        return jsonify(
            {
                "error":
                "Please enter the message body."
            }
        ), 400

    # -----------------------------------------------------
    # RECIPIENTS
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
                str(x)
                for x in raw_recipients
            )
        )

    else:

        recipient_list = []

    if not recipient_list:

        return jsonify(
            {
                "error":
                "No recipients were found."
            }
        ), 400

    # -----------------------------------------------------
    # FILTER INVALID ADDRESSES
    # -----------------------------------------------------

    invalid_recipients = []

    valid_recipients = []

    for recipient in recipient_list:

        if is_valid_email(
            recipient
        ):

            valid_recipients.append(
                recipient
            )

        else:

            invalid_recipients.append(
                {
                    "email": recipient,
                    "error":
                    "Invalid email address."
                }
            )

    sent = []

    failed = []

    # -----------------------------------------------------
    # SMTP CONNECTION
    # -----------------------------------------------------

    smtp = None

    try:

        smtp_context = ssl.create_default_context()

        smtp = smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=smtp_context,
            timeout=30
        )

        smtp.login(
            gmail_address,
            app_password
        )

        # -------------------------------------------------
        # SEQUENTIAL SENDING
        # -------------------------------------------------

        last_send_time = 0

        for recipient in valid_recipients:

            # Conservative pacing. This is intentionally
            # not designed to bypass provider limits.

            elapsed = (
                time.monotonic()
                - last_send_time
            )

            if elapsed < MIN_SEND_INTERVAL:

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
                    message_html
                    .replace(
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

            except Exception as send_error:

                failed.append(
                    {
                        "email": recipient,
                        "error": str(
                            send_error
                        )
                    }
                )

        # Add invalid addresses to failures.

        failed.extend(
            invalid_recipients
        )

        return jsonify(
            {
                "ok": True,
                "total": len(
                    recipient_list
                ),
                "sent": sent,
                "failed": failed
            }
        )

    except smtplib.SMTPAuthenticationError:

        return jsonify(
            {
                "error":
                "Gmail authentication failed. "
                "Check the Gmail address and App Password."
            }
        ), 502

    except smtplib.SMTPConnectError:

        return jsonify(
            {
                "error":
                "Could not connect to Gmail SMTP."
            }
        ), 502

    except smtplib.SMTPException as smtp_error:

        return jsonify(
            {
                "error":
                "Gmail SMTP error: "
                + str(smtp_error)
            }
        ), 502

    except Exception as error:

        return jsonify(
            {
                "error":
                "Sending error: "
                + str(error)
            }
        ), 502

    finally:

        if smtp is not None:

            try:
                smtp.quit()
            except Exception:
                pass


# ---------------------------------------------------------
# LOCAL DEVELOPMENT
# ---------------------------------------------------------

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

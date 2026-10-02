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
    redirect,
    Response,
    stream_with_context
)

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

from html.parser import HTMLParser


# ============================================================
# APPLICATION
# ============================================================

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)


# ============================================================
# APPLICATION SETTINGS
# ============================================================

app.secret_key = os.getenv(
    "SESSION_SECRET",
    "change-this-secret"
)


LOGIN_PASSWORD = os.getenv(
    "APP_LOGIN_PASSWORD",
    "change-this-password"
)


TURNSTILE_SECRET_KEY = os.getenv(
    "TURNSTILE_SECRET_KEY",
    ""
)


MAX_RECIPIENTS = 25


# Keep sending within the provider's acceptable behavior.
# This is intentionally not a 7-second bulk-send bypass.
SEND_INTERVAL_SECONDS = 3.0


EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


# ============================================================
# EMAIL VALIDATION
# ============================================================

def is_valid_email(email):
    """
    Basic email validation.
    """

    if not email:
        return False

    email = str(email).strip()

    return bool(
        EMAIL_PATTERN.fullmatch(email)
    )


# ============================================================
# RECIPIENT PARSING
# ============================================================

def parse_recipients(value):
    """
    Accepts:
        email1@example.com
        email2@example.com

    or comma / semicolon / whitespace separated values.

    Removes duplicates while keeping original order.
    Maximum 25 recipients.
    """

    if not value:
        return []

    pieces = re.split(
        r"[\s,;]+",
        str(value)
    )

    recipients = []

    seen = set()

    for piece in pieces:

        email = piece.strip().lower()

        if not email:
            continue

        if email in seen:
            continue

        seen.add(email)

        recipients.append(email)

        if len(recipients) >= MAX_RECIPIENTS:
            break

    return recipients


# ============================================================
# LOGIN DECORATOR
# ============================================================

def login_required(function):
    """
    Protect dashboard/API routes.
    """

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("authenticated"):
            return redirect("/login")

        return function(
            *args,
            **kwargs
        )

    return wrapper


# ============================================================
# SPINTAX
# ============================================================

def resolve_spintax(text):
    """
    Supports simple forms such as:

        {Hi|Hello|Hey}

    This is ordinary message variation.
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

    current = text

    for _ in range(20):

        updated = pattern.sub(
            replace_match,
            current
        )

        if updated == current:
            break

        current = updated

    return current


# ============================================================
# SAFE HTML PARSER
# ============================================================

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

        safe_attributes = []

        for name, value in attrs:

            # --------------------------------------------
            # LINKS
            # --------------------------------------------

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

                    href = str(
                        value
                    ).lower()

                    if not href.startswith(
                        (
                            "https://",
                            "http://",
                            "mailto:"
                        )
                    ):
                        continue

            # --------------------------------------------
            # SPAN
            # --------------------------------------------

            elif tag == "span":

                if name != "class":
                    continue

            # --------------------------------------------
            # OTHER TAGS
            # --------------------------------------------

            else:

                continue


            safe_value = str(
                value
            ).replace(
                '"',
                "&quot;"
            )


            safe_attributes.append(
                f' {name}="{safe_value}"'
            )


        self.output.append(
            "<"
            + tag
            + "".join(safe_attributes)
            + ">"
        )


    def handle_endtag(self, tag):

        if tag in self.ALLOWED_TAGS:

            self.output.append(
                "</"
                + tag
                + ">"
            )


    def handle_data(self, data):

        self.output.append(
            data
        )


# ============================================================
# HTML CLEANER
# ============================================================

def sanitize_html(value):

    parser = SafeHTMLParser()

    parser.feed(
        value or ""
    )

    parser.close()

    return "".join(
        parser.output
    )


# ============================================================
# HTML -> PLAIN TEXT
# ============================================================

def html_to_plain_text(html):

    if not html:
        return ""

    text = html


    text = re.sub(
        r"<br\s*/?>",
        "\n",
        text,
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


# ============================================================
# CLOUDFLARE TURNSTILE
# ============================================================

def verify_turnstile(token):

    # If no secret is configured, don't block sending.
    if not TURNSTILE_SECRET_KEY:
        return True


    if not token:
        return False


    try:

        form_data = urllib.parse.urlencode(
            {
                "secret": TURNSTILE_SECRET_KEY,
                "response": token
            }
        ).encode("utf-8")


        verification_request = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=form_data,
            method="POST"
        )


        with urllib.request.urlopen(
            verification_request,
            timeout=10
        ) as response:

            result = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )


        return bool(
            result.get("success")
        )


    except Exception as error:

        print(
            "TURNSTILE VERIFICATION ERROR:",
            repr(error)
        )

        return False


# ============================================================
# SERVER-SENT EVENT HELPER
# ============================================================

def make_event(
    event_name,
    data
):
    """
    Creates one SSE event.
    """

    json_data = json.dumps(
        data,
        ensure_ascii=False
    )

    return (
        f"event: {event_name}\n"
        f"data: {json_data}\n\n"
    )


# ============================================================
# LOGIN
# ============================================================

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


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
@login_required
def index():

    return render_template(
        "index.html",
        turnstile_site_key=os.getenv(
            "TURNSTILE_SITE_KEY",
            ""
        )
    )


# ============================================================
# LIVE EMAIL SENDING
# ============================================================

@app.post("/api/send-stream")
@login_required
def send_stream():

    data = request.get_json(
        silent=True
    ) or {}


    # ========================================================
    # READ FORM DATA
    # ========================================================

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


    recipients_input = data.get(
        "recipients",
        []
    )


    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    )


    # ========================================================
    # BASIC VALIDATION
    # ========================================================

    if not is_valid_email(
        gmail_address
    ):

        return jsonify(
            error="Please enter a valid Gmail address."
        ), 400


    if not app_password:

        return jsonify(
            error="Gmail App Password is required."
        ), 400


    if not subject:

        return jsonify(
            error="Email subject is required."
        ), 400


    if not message_html.strip():

        return jsonify(
            error="Message body is required."
        ), 400


    # ========================================================
    # CLOUDFLARE
    # ========================================================

    if not verify_turnstile(
        turnstile_token
    ):

        return jsonify(
            error=(
                "Cloudflare verification failed. "
                "Please complete verification again."
            )
        ), 403


    # ========================================================
    # RECIPIENT LIST
    # ========================================================

    if isinstance(
        recipients_input,
        str
    ):

        recipients = parse_recipients(
            recipients_input
        )

    elif isinstance(
        recipients_input,
        list
    ):

        recipients = parse_recipients(
            " ".join(
                str(item)
                for item in recipients_input
            )
        )

    else:

        recipients = []


    if not recipients:

        return jsonify(
            error="No recipients found."
        ), 400


    # ========================================================
    # SEPARATE VALID / INVALID
    # ========================================================

    valid_recipients = []

    invalid_recipients = []


    for recipient in recipients:

        if is_valid_email(
            recipient
        ):

            valid_recipients.append(
                recipient
            )

        else:

            invalid_recipients.append(
                recipient
            )


    # ========================================================
    # STREAM GENERATOR
    # ========================================================

    @stream_with_context
    def generate():

        total = len(recipients)

        sent_count = 0

        failed_count = len(
            invalid_recipients
        )

        processed_count = failed_count

        smtp = None


        # ====================================================
        # INITIAL STATE
        # ====================================================

        yield make_event(
            "start",
            {
                "total": total,
                "sent": 0,
                "failed": failed_count,
                "remaining": max(
                    0,
                    total - processed_count
                )
            }
        )


        # ====================================================
        # INVALID RECIPIENTS
        # ====================================================

        for invalid_email in invalid_recipients:

            print(
                "Invalid recipient:",
                invalid_email
            )


            yield make_event(
                "progress",
                {
                    "total": total,
                    "sent": sent_count,
                    "failed": failed_count,
                    "remaining": max(
                        0,
                        total - processed_count
                    )
                }
            )


        # ====================================================
        # IF NO VALID EMAILS
        # ====================================================

        if not valid_recipients:

            yield make_event(
                "complete",
                {
                    "total": total,
                    "sent": sent_count,
                    "failed": failed_count,
                    "remaining": 0
                }
            )

            return


        # ====================================================
        # CONNECT TO GMAIL
        # ====================================================

        try:

            ssl_context = (
                ssl.create_default_context()
            )


            smtp = smtplib.SMTP_SSL(
                "smtp.gmail.com",
                465,
                context=ssl_context,
                timeout=30
            )


            smtp.login(
                gmail_address,
                app_password
            )


        except smtplib.SMTPAuthenticationError:

            yield make_event(
                "error",
                {
                    "message": (
                        "Gmail authentication failed. "
                        "Check your Gmail address and "
                        "App Password."
                    )
                }
            )

            return


        except smtplib.SMTPConnectError:

            yield make_event(
                "error",
                {
                    "message": (
                        "Could not connect to Gmail SMTP."
                    )
                }
            )

            return


        except smtplib.SMTPException as error:

            yield make_event(
                "error",
                {
                    "message": (
                        "Gmail SMTP error: "
                        + str(error)
                    )
                }
            )

            return


        except Exception as error:

            yield make_event(
                "error",
                {
                    "message": (
                        "SMTP connection failed: "
                        + str(error)
                    )
                }
            )

            return


        # ====================================================
        # SEND EMAILS
        # ====================================================

        last_send_time = 0


        for recipient in valid_recipients:

            # ------------------------------------------------
            # PROVIDER-FRIENDLY PACING
            # ------------------------------------------------

            if last_send_time:

                elapsed = (
                    time.monotonic()
                    - last_send_time
                )


                if elapsed < SEND_INTERVAL_SECONDS:

                    time.sleep(
                        SEND_INTERVAL_SECONDS
                        - elapsed
                    )


            # ------------------------------------------------
            # CREATE PERSONALIZED CONTENT
            # ------------------------------------------------

            try:

                first_name = (
                    recipient
                    .split(
                        "@",
                        1
                    )[0]
                )


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


                plain_text = (
                    html_to_plain_text(
                        personalized_html
                    )
                )


                # --------------------------------------------
                # MIME MESSAGE
                # --------------------------------------------

                message = MIMEMultipart(
                    "alternative"
                )


                if sender_name:

                    message["From"] = formataddr(
                        (
                            sender_name,
                            gmail_address
                        )
                    )

                else:

                    message["From"] = (
                        gmail_address
                    )


                message["To"] = (
                    recipient
                )


                message["Subject"] = (
                    personalized_subject
                )


                message.attach(
                    MIMEText(
                        plain_text,
                        "plain",
                        "utf-8"
                    )
                )


                message.attach(
                    MIMEText(
                        personalized_html,
                        "html",
                        "utf-8"
                    )
                )


                # --------------------------------------------
                # SEND
                # --------------------------------------------

                smtp.sendmail(
                    gmail_address,
                    [recipient],
                    message.as_string()
                )


                sent_count += 1

                processed_count += 1

                last_send_time = (
                    time.monotonic()
                )


                # --------------------------------------------
                # ONLY UPDATE COUNTERS
                # --------------------------------------------

                yield make_event(
                    "progress",
                    {
                        "total": total,
                        "sent": sent_count,
                        "failed": failed_count,
                        "remaining": max(
                            0,
                            total - processed_count
                        )
                    }
                )


            except Exception as recipient_error:

                failed_count += 1

                processed_count += 1


                print(
                    "SEND ERROR:",
                    recipient,
                    repr(
                        recipient_error
                    )
                )


                # --------------------------------------------
                # UPDATE FAILED COUNTER
                # --------------------------------------------

                yield make_event(
                    "progress",
                    {
                        "total": total,
                        "sent": sent_count,
                        "failed": failed_count,
                        "remaining": max(
                            0,
                            total - processed_count
                        )
                    }
                )


        # ====================================================
        # COMPLETE EVENT
        # ====================================================

        yield make_event(
            "complete",
            {
                "total": total,
                "sent": sent_count,
                "failed": failed_count,
                "remaining": 0
            }
        )


        # ====================================================
        # CLOSE SMTP
        # ====================================================

        if smtp is not None:

            try:

                smtp.quit()

            except Exception:

                pass


    # ========================================================
    # STREAM RESPONSE
    # ========================================================

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":
                "no-cache, no-transform",

            "X-Accel-Buffering":
                "no",

            "Connection":
                "keep-alive"
        }
    )


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

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

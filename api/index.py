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


# =========================================================
# APPLICATION
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
# CONFIGURATION
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

# Provider-compatible pacing.
# Do not use this to bypass provider limits.
MIN_SEND_INTERVAL = 2.0

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


# =========================================================
# EMAIL VALIDATION
# =========================================================

def is_valid_email(email):

    if not email:
        return False

    return bool(
        EMAIL_PATTERN.fullmatch(
            email.strip()
        )
    )


# =========================================================
# RECIPIENT PARSER
# =========================================================

def parse_recipients(value):

    if not value:
        return []

    pieces = re.split(
        r"[\s,;]+",
        str(value)
    )

    result = []

    seen = set()

    for piece in pieces:

        email = piece.strip().lower()

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
# LOGIN CHECK
# =========================================================

def authentication_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get(
            "authenticated"
        ):
            return redirect("/login")

        return function(
            *args,
            **kwargs
        )

    return wrapper


# =========================================================
# SPINTAX
# =========================================================

def resolve_spintax(text):

    if not text:
        return ""

    pattern = re.compile(
        r"\{([^{}|]+(?:\|[^{}|]+)+)\}"
    )

    def replace_match(match):

        choices = match.group(
            1
        ).split("|")

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

class SafeHTMLParser(
    HTMLParser
):

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

                    lower_value = str(
                        value
                    ).lower()

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

    if not TURNSTILE_SECRET_KEY:
        return True

    if not token:
        return False

    try:

        payload = urllib.parse.urlencode(
            {
                "secret":
                    TURNSTILE_SECRET_KEY,

                "response":
                    token
            }
        ).encode("utf-8")


        verification_request = (
            urllib.request.Request(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data=payload,
                method="POST"
            )
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
# LOGIN
# =========================================================

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

            session[
                "authenticated"
            ] = True

            return redirect("/")


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

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# =========================================================
# MAIN DASHBOARD
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
# SERVER-SENT EVENT
# =========================================================

def sse_event(
    event_name,
    payload
):

    data = json.dumps(
        payload,
        ensure_ascii=False
    )

    return (
        f"event: {event_name}\n"
        f"data: {data}\n\n"
    )


# =========================================================
# LIVE SEND API
# =========================================================

@app.post("/api/send-stream")
@authentication_required
def send_stream():

    data = request.get_json(
        silent=True
    ) or {}


    # -----------------------------------------------------
    # INPUT
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


    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    )


    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not is_valid_email(
        gmail_address
    ):

        return jsonify(
            error="Please enter a valid Gmail address."
        ), 400


    if not app_password:

        return jsonify(
            error="Please enter the Gmail App Password."
        ), 400


    if not subject:

        return jsonify(
            error="Please enter an email subject."
        ), 400


    if not message_html.strip():

        return jsonify(
            error="Please enter the message body."
        ), 400


    # -----------------------------------------------------
    # TURNSTILE
    # -----------------------------------------------------

    if not verify_turnstile(
        turnstile_token
    ):

        return jsonify(
            error="Cloudflare verification failed. "
                  "Please complete verification again."
        ), 403


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
                str(item)
                for item in raw_recipients
            )
        )

    else:

        recipient_list = []


    if not recipient_list:

        return jsonify(
            error="No recipients were found."
        ), 400


    # -----------------------------------------------------
    # VALID / INVALID
    # -----------------------------------------------------

    valid_recipients = []

    invalid_recipients = []


    for recipient in recipient_list:

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


    # -----------------------------------------------------
    # STREAM GENERATOR
    # -----------------------------------------------------

    @stream_with_context
    def generate():

        total = len(
            recipient_list
        )

        sent_count = 0

        failed_count = len(
            invalid_recipients
        )

        processed_count = failed_count

        smtp = None


        # -------------------------------------------------
        # INITIAL COUNTER
        # -------------------------------------------------

        yield sse_event(
            "start",
            {
                "total":
                    total,

                "sent":
                    0,

                "failed":
                    failed_count,

                "remaining":
                    total - processed_count
            }
        )


        # -------------------------------------------------
        # INVALID RECIPIENTS
        # -------------------------------------------------

        for _invalid_email in invalid_recipients:

            processed_count += 1

            yield sse_event(
                "progress",
                {
                    "total":
                        total,

                    "sent":
                        sent_count,

                    "failed":
                        failed_count,

                    "remaining":
                        max(
                            0,
                            total - processed_count
                        )
                }
            )


        # -------------------------------------------------
        # NO VALID RECIPIENTS
        # -------------------------------------------------

        if not valid_recipients:

            yield sse_event(
                "complete",
                {
                    "total":
                        total,

                    "sent":
                        sent_count,

                    "failed":
                        failed_count,

                    "remaining":
                        0
                }
            )

            return


        # -------------------------------------------------
        # CONNECT GMAIL
        # -------------------------------------------------

        try:

            smtp_context = (
                ssl.create_default_context()
            )


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


        except smtplib.SMTPAuthenticationError as error:

            yield sse_event(
                "error",
                {
                    "message":
                        "Gmail authentication failed. "
                        "Check your Gmail address and App Password."
                }
            )

            return


        except smtplib.SMTPConnectError as error:

            yield sse_event(
                "error",
                {
                    "message":
                        "Could not connect to Gmail SMTP."
                }
            )

            return


        except smtplib.SMTPException as error:

            yield sse_event(
                "error",
                {
                    "message":
                        "Gmail SMTP error: "
                        + str(error)
                }
            )

            return


        except Exception as error:

            yield sse_event(
                "error",
                {
                    "message":
                        "Email connection failed: "
                        + str(error)
                }
            )

            return


        # -------------------------------------------------
        # SEND LOOP
        # -------------------------------------------------

        last_send_time = 0


        for recipient in valid_recipients:


            # ---------------------------------------------
            # PROVIDER-FRIENDLY PACING
            # ---------------------------------------------

            elapsed = (
                time.monotonic()
                - last_send_time
            )


            if (
                last_send_time > 0
                and elapsed < MIN_SEND_INTERVAL
            ):

                time.sleep(
                    MIN_SEND_INTERVAL
                    - elapsed
                )


            # ---------------------------------------------
            # PERSONALIZATION
            # ---------------------------------------------

            try:

                first_name = (
                    recipient.split(
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


                plain_body = (
                    html_to_plain_text(
                        personalized_html
                    )
                )


                email_message = (
                    MIMEMultipart(
                        "alternative"
                    )
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


                email_message["To"] = (
                    recipient
                )


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
                # SEND
                # -----------------------------------------

                smtp.sendmail(
                    gmail_address,
                    [recipient],
                    email_message.as_string()
                )


                sent_count += 1

                processed_count += 1

                last_send_time = (
                    time.monotonic()
                )


                # -----------------------------------------
                # ONLY COUNTERS
                # -----------------------------------------

                yield sse_event(
                    "progress",
                    {
                        "total":
                            total,

                        "sent":
                            sent_count,

                        "failed":
                            failed_count,

                        "remaining":
                            max(
                                0,
                                total - processed_count
                            )
                    }
                )


            except Exception as recipient_error:

                failed_count += 1

                processed_count += 1


                print(
                    "RECIPIENT SEND ERROR:",
                    recipient,
                    repr(
                        recipient_error
                    )
                )


                # -----------------------------------------
                # ONLY COUNTERS
                # -----------------------------------------

                yield sse_event(
                    "progress",
                    {
                        "total":
                            total,

                        "sent":
                            sent_count,

                        "failed":
                            failed_count,

                        "remaining":
                            max(
                                0,
                                total - processed_count
                            )
                    }
                )


        # -------------------------------------------------
        # COMPLETE
        # -------------------------------------------------

        yield sse_event(
            "complete",
            {
                "total":
                    total,

                "sent":
                    sent_count,

                "failed":
                    failed_count,

                "remaining":
                    0
            }
        )


        # -------------------------------------------------
        # CLOSE SMTP
        # -------------------------------------------------

        if smtp is not None:

            try:
                smtp.quit()

            except Exception:
                pass


    # -----------------------------------------------------
    # STREAM RESPONSE
    # -----------------------------------------------------

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

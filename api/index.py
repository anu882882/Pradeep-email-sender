import os
import re
import ssl
import smtplib
import secrets
import time
from functools import wraps
from html.parser import HTMLParser

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
    "Baby882@#"
)

TURNSTILE_SECRET = os.getenv(
    "TURNSTILE_SECRET_KEY",
    ""
)

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)

COOLDOWN = 5


def valid_email(value):
    return bool(
        EMAIL_PATTERN.fullmatch(
            str(value).strip()
        )
    )


def auth_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if session.get("login"):
            return function(*args, **kwargs)

        return redirect("/login")

    return wrapper


def parse_recipients(value):

    if isinstance(value, list):
        items = value
    else:
        items = re.split(
            r"[\s,;]+",
            str(value or "")
        )

    result = []
    seen = set()

    for item in items:

        email = str(item).strip().lower()

        if not email:
            continue

        if email in seen:
            continue

        seen.add(email)
        result.append(email)

    return result


def safe_message(subject, message):

    combined = (
        str(subject) +
        " " +
        str(message)
    )

    if re.search(
        r"<\s*(script|iframe|object|embed|form)\b",
        combined,
        re.I
    ):
        return False, "Unsafe HTML detected."

    if re.search(
        r"javascript\s*:",
        combined,
        re.I
    ):
        return False, "Unsafe content detected."

    links = re.findall(
        r"https?://",
        combined,
        re.I
    )

    if len(links) > 5:
        return False, "Too many links in message."

    if re.search(
        r"(.)\1{10,}",
        combined
    ):
        return False, "Repeated characters detected."

    return True, "OK"


def resolve_spintax(text):

    pattern = re.compile(
        r"\{([^{}]+)\}"
    )

    def replace(match):

        options = [
            x.strip()
            for x in match.group(1).split("|")
            if x.strip()
        ]

        if not options:
            return ""

        return options[
            secrets.randbelow(
                len(options)
            )
        ]

    previous = None

    while previous != text:

        previous = text

        text = pattern.sub(
            replace,
            text
        )

    return text


# -------------------------------------------------
# HTML SANITIZER
# -------------------------------------------------

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

ALLOWED_ATTRS = {
    "span": {"class"},
    "a": {"href", "target", "rel"}
}


class EmailHTMLSanitizer(HTMLParser):

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

        tag = tag.lower()

        if tag not in ALLOWED_TAGS:
            return

        allowed = ALLOWED_ATTRS.get(
            tag,
            set()
        )

        clean_attrs = []

        for name, value in attrs:

            name = name.lower()

            if name not in allowed:
                continue

            value = str(value or "")

            if tag == "span":

                if name == "class" and value != "small-caps":
                    continue

            if tag == "a":

                if name == "href":

                    if not re.match(
                        r"^https?://",
                        value,
                        re.I
                    ):
                        continue

            clean_attrs.append(
                (name, value)
            )

        self.output.append(
            "<" + tag
        )

        for name, value in clean_attrs:

            escaped = (
                value
                .replace("&", "&amp;")
                .replace('"', "&quot;")
            )

            self.output.append(
                f' {name}="{escaped}"'
            )

        self.output.append(">")

    def handle_startendtag(
        self,
        tag,
        attrs
    ):

        self.handle_starttag(
            tag,
            attrs
        )

    def handle_endtag(self, tag):

        tag = tag.lower()

        if tag in ALLOWED_TAGS:

            self.output.append(
                f"</{tag}>"
            )

    def handle_data(self, data):

        self.output.append(
            escape_html(data)
        )

    def get_html(self):

        return "".join(
            self.output
        )


def sanitize_html(html):

    parser = EmailHTMLSanitizer()

    parser.feed(
        str(html or "")
    )

    parser.close()

    return parser.get_html()


def html_to_plain(html):

    text = str(html or "")

    text = re.sub(
        r"<br\s*/?>",
        "\n",
        text,
        flags=re.I
    )

    text = re.sub(
        r"</p\s*>",
        "\n\n",
        text,
        flags=re.I
    )

    text = re.sub(
        r"</div\s*>",
        "\n",
        text,
        flags=re.I
    )

    text = re.sub(
        r"<li\s*>",
        "- ",
        text,
        flags=re.I
    )

    text = re.sub(
        r"<[^>]+>",
        "",
        text
    )

    return (
        text
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
    )


def resolve_spintax_html(html):

    class TextSpintaxParser(HTMLParser):

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

            self.output.append(
                "<" + tag
            )

            for name, value in attrs:

                escaped = (
                    str(value or "")
                    .replace("&", "&amp;")
                    .replace('"', "&quot;")
                )

                self.output.append(
                    f' {name}="{escaped}"'
                )

            self.output.append(">")

        def handle_startendtag(
            self,
            tag,
            attrs
        ):

            self.handle_starttag(
                tag,
                attrs
            )

            self.output.append(
                f"</{tag}>"
            )

        def handle_endtag(self, tag):

            self.output.append(
                f"</{tag}>"
            )

        def handle_data(self, data):

            self.output.append(
                escape_html(
                    resolve_spintax(
                        data
                    )
                )
            )

    parser = TextSpintaxParser()

    parser.feed(
        html
    )

    parser.close()

    return "".join(
        parser.output
    )


def escape_html(text):

    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


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

        if password == LOGIN:

            session["login"] = True
            session["last_send"] = 0

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


@app.route("/")
@auth_required
def home():

    return render_template(
        "index.html",
        turnstile_site_key=os.getenv(
            "TURNSTILE_SITE_KEY",
            ""
        )
    )


@app.route(
    "/api/send-batch",
    methods=["POST"]
)
@auth_required
def send_batch():

    now = time.time()

    last_send = session.get(
        "last_send",
        0
    )

    if now - last_send < COOLDOWN:

        return jsonify(
            error=(
                f"Please wait "
                f"{COOLDOWN} seconds."
            )
        ), 429

    data = request.get_json(
        silent=True
    ) or {}

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

    raw_html = str(
        data.get(
            "message_html",
            ""
        )
    )

    recipients = parse_recipients(
        data.get(
            "recipients",
            []
        )
    )

    if not sender:

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
            error="Email subject required."
        ), 400

    if not raw_html.strip():

        return jsonify(
            error="Message required."
        ), 400

    if not recipients:

        return jsonify(
            error="No recipients."
        ), 400

    if len(recipients) > 5:

        return jsonify(
            error="Only 5 recipients per batch."
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

    clean_html = sanitize_html(
        raw_html
    )

    clean_html = resolve_spintax_html(
        clean_html
    )

    plain_text = html_to_plain(
        clean_html
    )

    safe, reason = safe_message(
        subject,
        plain_text
    )

    if not safe:

        return jsonify(
            error=reason
        ), 400

    sent = []
    failed = []

    try:

        context = (
            ssl.create_default_context()
        )

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=context,
            timeout=30
        ) as smtp:

            smtp.login(
                gmail,
                app_password
            )

            session["last_send"] = time.time()

            for recipient in recipients:

                try:

                    personalized_plain = (
                        plain_text.replace(
                            "{name}",
                            recipient.split("@")[0]
                        )
                    )

                    personalized_html = (
                        clean_html.replace(
                            "{name}",
                            escape_html(
                                recipient.split("@")[0]
                            )
                        )
                    )

                    mail = MIMEMultipart(
                        "alternative"
                    )

                    mail["Subject"] = resolve_spintax(
                        subject
                    )

                    mail["From"] = (
                        f"{sender} <{gmail}>"
                    )

                    mail["To"] = recipient

                    mail.attach(
                        MIMEText(
                            personalized_plain,
                            "plain",
                            "utf-8"
                        )
                    )

                    html_document = f"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
body {{
    font-family: Arial, sans-serif;
    color: #222;
    line-height: 1.6;
}}

.small-caps {{
    font-variant: small-caps;
    font-feature-settings: "smcp";
    letter-spacing: .02em;
}}

a {{
    color: #2563eb;
}}
</style>
</head>
<body>
{personalized_html}
</body>
</html>
"""

                    mail.attach(
                        MIMEText(
                            html_document,
                            "html",
                            "utf-8"
                        )
                    )

                    refused = smtp.sendmail(
                        gmail,
                        [recipient],
                        mail.as_string()
                    )

                    if refused:

                        failed.append(
                            recipient
                        )

                    else:

                        sent.append(
                            recipient
                        )

                except Exception:

                    failed.append(
                        recipient
                    )

        return jsonify(
            success=True,
            sent=sent,
            failed=failed,
            sender=gmail
        )

    except smtplib.SMTPAuthenticationError:

        return jsonify(
            error="Gmail authentication failed."
        ), 401

    except Exception as error:

        return jsonify(
            error=str(error)
        ), 500


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

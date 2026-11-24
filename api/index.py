
import os
import re
import ssl
import smtplib
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify
)


app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    "change-this-secret-key"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get(
        "COOKIE_SECURE", "true"
    ).lower() == "true"
)

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

MAX_RECIPIENTS = 25
BATCH_SIZE = 5

EMAIL_PATTERN = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$",
    re.IGNORECASE
)


def is_valid_email(email):
    return bool(
        EMAIL_PATTERN.fullmatch(str(email).strip())
    )


def parse_recipients(raw_value):
    recipients = []
    seen = set()

    if isinstance(raw_value, list):
        lines = raw_value
    else:
        lines = re.split(r"[\n,;]+", str(raw_value or ""))

    for item in lines:
        name = ""
        email = ""

        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            email = str(item.get("email", "")).strip().lower()

        else:
            line = str(item).strip()

            if not line:
                continue

            match = re.match(
                r'^(.*?)\s*<([^<>]+)>$',
                line
            )

            if match:
                name = match.group(1).strip().strip('"')
                email = match.group(2).strip().lower()
            else:
                email = line.lower()

        if is_valid_email(email) and email not in seen:
            seen.add(email)

            recipients.append({
                "name": name,
                "email": email
            })

    return recipients


def send_one_email(
    recipient,
    sender_name,
    sender_email,
    app_password,
    subject,
    body,
    is_html
):
    email = recipient["email"]
    name = recipient["name"] or email.split("@")[0]

    personalized_subject = (
        subject
        .replace("{{name}}", name)
        .replace("{{email}}", email)
    )

    personalized_body = (
        body
        .replace("{{name}}", name)
        .replace("{{email}}", email)
    )

    message = MIMEText(
        personalized_body,
        "html" if is_html else "plain",
        "utf-8"
    )

    message["Subject"] = personalized_subject
    message["From"] = formataddr(
        (sender_name, sender_email)
    )

    message["To"] = (
        formataddr((recipient["name"], email))
        if recipient["name"]
        else email
    )

    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        context=context,
        timeout=30
    ) as server:

        server.login(
            sender_email,
            app_password
        )

        server.sendmail(
            sender_email,
            [email],
            message.as_string()
        )

    return email


@app.route("/")
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        password = request.form.get("password", "")

        if LOGIN_PASSWORD and password == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True

            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Incorrect password. Please try again."
        )

    if session.get("logged_in"):
        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/send", methods=["POST"])
def send():

    if not session.get("logged_in"):
        return jsonify({
            "success": False,
            "error": "Session expired. Please log in again."
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        data = request.form.to_dict()

    # Support both frontend field names
    sender_name = str(
        data.get("sender_name") or data.get("name") or ""
    ).strip()

    sender_email = str(
        data.get("sender_email") or data.get("gmail") or ""
    ).strip().lower()

    app_password = str(
        data.get("app_password") or data.get("password") or ""
    ).replace(" ", "").strip()

    subject = str(
        data.get("subject") or ""
    ).strip()

    body = str(
        data.get("body") or data.get("message_body") or ""
    )

    recipients_raw = (
        data.get("recipients")
        or data.get("recipient_emails")
        or data.get("emails")
        or ""
    )

    is_html = data.get("is_html", data.get("html", False))

    if isinstance(is_html, str):
        is_html = is_html.lower() in ("true", "1", "yes", "on")
    else:
        is_html = bool(is_html)

    consent = data.get(
        "consent",
        data.get("recipient_consent", False)
    )

    if isinstance(consent, str):
        consent = consent.lower() in ("true", "1", "yes", "on")
    else:
        consent = bool(consent)

    # Required fields validation
    if not all([
        sender_name,
        sender_email,
        app_password,
        subject,
        body.strip()
    ]):
        return jsonify({
            "success": False,
            "error": "Please complete all required fields."
        }), 400

    if not is_valid_email(sender_email):
        return jsonify({
            "success": False,
            "error": "Please enter a valid sender email address."
        }), 400

    if not consent:
        return jsonify({
            "success": False,
            "error": "Please confirm recipient consent."
        }), 400

    # Parse recipients from text or list
    recipients = parse_recipients(recipients_raw)

    if not recipients:
        return jsonify({
            "success": False,
            "error": "No valid recipient email addresses found."
        }), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "success": False,
            "error": (
                f"Maximum {MAX_RECIPIENTS} recipients are allowed."
            )
        }), 400

    results = []

    # Send emails in batches of 5
    for start in range(0, len(recipients), BATCH_SIZE):

        batch = recipients[start:start + BATCH_SIZE]

        with ThreadPoolExecutor(
            max_workers=BATCH_SIZE
        ) as executor:

            futures = {
                executor.submit(
                    send_one_email,
                    recipient,
                    sender_name,
                    sender_email,
                    app_password,
                    subject,
                    body,
                    is_html
                ): recipient

                for recipient in batch
            }

            for future in as_completed(futures):

                recipient = futures[future]

                try:
                    email = future.result()

                    results.append({
                        "success": True,
                        "email": email,
                        "result": "success",
                        "message": f"SMTP accepted email for {email}."
                    })

                except Exception as exc:

                    error_message = str(exc).replace(
                        app_password,
                        "[hidden]"
                    )

                    results.append({
                        "success": False,
                        "email": recipient["email"],
                        "result": "error",
                        "message": (
                            f"Failed for {recipient['email']}: "
                            f"{error_message[:250]}"
                        )
                    })

    sent = sum(
        1 for item in results
        if item["success"]
    )

    failed = len(results) - sent

    return jsonify({
        "success": failed == 0,
        "total": len(recipients),
        "sent": sent,
        "failed": failed,
        "results": results,
        "message": (
            f"Completed: {sent} sent, {failed} failed."
        )
    }), 200


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "app": "Bulk Email Sender"
    })


if __name__ == "__main__":
    app.run(debug=True)


import os
import re
import json
import ssl
import smtplib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, Response, jsonify
)

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

app.secret_key = os.environ.get("SESSION_SECRET", "change-this-secret-key")

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

MAX_RECIPIENTS = 25
BATCH_SIZE = 5
BATCH_DELAY_SECONDS = 1

EMAIL_PATTERN = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$",
    re.IGNORECASE
)


def is_valid_email(email):
    return bool(EMAIL_PATTERN.fullmatch(email.strip()))


def parse_recipients(raw_value):
    recipients = []
    seen = set()

    for line in re.split(r"[\n,;]+", raw_value or ""):
        line = line.strip()

        if not line:
            continue

        match = re.match(r'^(.*?)\s*<([^<>]+)>$', line)

        if match:
            name = match.group(1).strip().strip('"')
            email = match.group(2).strip().lower()
        else:
            name = ""
            email = line.strip().lower()

        if is_valid_email(email) and email not in seen:
            seen.add(email)
            recipients.append({
                "name": name,
                "email": email
            })

    return recipients


def stream_event(data):
    return json.dumps(data, ensure_ascii=False) + "\n"


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
        subject.replace("{{name}}", name)
        .replace("{{email}}", email)
    )

    personalized_body = (
        body.replace("{{name}}", name)
        .replace("{{email}}", email)
    )

    message = MIMEText(
        personalized_body,
        "html" if is_html else "plain",
        "utf-8"
    )

    message["Subject"] = personalized_subject
    message["From"] = formataddr((sender_name, sender_email))
    message["To"] = (
        formataddr((recipient["name"], email))
        if recipient["name"] else email
    )
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        context=context,
        timeout=25
    ) as server:
        server.login(sender_email, app_password)
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
            "error": "Your session has expired. Please log in again."
        }), 401

    data = request.get_json(silent=True) or {}

    sender_name = str(data.get("sender_name", "")).strip()
    sender_email = str(data.get("sender_email", "")).strip().lower()
    app_password = str(data.get("app_password", "")).replace(" ", "")
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))
    recipients_raw = str(data.get("recipients", ""))
    is_html = bool(data.get("is_html"))
    consent = bool(data.get("consent"))

    if not all([
        sender_name,
        sender_email,
        app_password,
        subject,
        body.strip()
    ]):
        return jsonify({
            "error": "Please complete all required fields."
        }), 400

    if not is_valid_email(sender_email):
        return jsonify({
            "error": "Please enter a valid Gmail address."
        }), 400

    if not consent:
        return jsonify({
            "error": "Please confirm recipient consent before sending."
        }), 400

    recipients = parse_recipients(recipients_raw)

    if not recipients:
        return jsonify({
            "error": "No valid recipient email addresses were found."
        }), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "error": f"Maximum {MAX_RECIPIENTS} recipients are allowed."
        }), 400

    def generate():
        total = len(recipients)
        sent = 0
        failed = 0

        yield stream_event({
            "type": "start",
            "total": total,
            "sent": sent,
            "failed": failed,
            "message": f"Starting delivery to {total} recipients."
        })

        for batch_start in range(0, total, BATCH_SIZE):
            batch = recipients[batch_start:batch_start + BATCH_SIZE]
            batch_number = (batch_start // BATCH_SIZE) + 1

            yield stream_event({
                "type": "batch",
                "message": f"Processing batch {batch_number}."
            })

            with ThreadPoolExecutor(max_workers=BATCH_SIZE) as executor:
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
                        sent += 1

                        yield stream_event({
                            "type": "success",
                            "email": email,
                            "sent": sent,
                            "failed": failed,
                            "total": total,
                            "message": f"SMTP accepted email for {email}."
                        })

                    except Exception as exc:
                        failed += 1

                        error_message = str(exc).replace(
                            app_password, "[hidden]"
                        )

                        yield stream_event({
                            "type": "error",
                            "email": recipient["email"],
                            "sent": sent,
                            "failed": failed,
                            "total": total,
                            "message": (
                                f"Failed for {recipient['email']}: "
                                f"{error_message[:250]}"
                            )
                        })

            if batch_start + BATCH_SIZE < total:
                time.sleep(BATCH_DELAY_SECONDS)

        yield stream_event({
            "type": "complete",
            "sent": sent,
            "failed": failed,
            "total": total,
            "message": "Sending process completed."
        })

    return Response(
        generate(),
        mimetype="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache, no-store",
            "X-Accel-Buffering": "no"
        }
    )


if __name__ == "__main__":
    app.run(debug=True)

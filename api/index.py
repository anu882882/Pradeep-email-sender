import os
import re
import ssl
import smtplib
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, jsonify
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
        timeout=20
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
            "success": False,
            "error": "Session expired. Please log in again."
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

    recipients = parse_recipients(recipients_raw)

    if not recipients:
        return jsonify({
            "success": False,
            "error": "No valid recipient email addresses found."
        }), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "success": False,
            "error": f"Maximum {MAX_RECIPIENTS} recipients are allowed."
        }), 400

    results = []

    for start in range(0, len(recipients), BATCH_SIZE):
        batch = recipients[start:start + BATCH_SIZE]

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
                    results.append({
                        "success": True,
                        "email": email,
                        "message": f"SMTP accepted email for {email}."
                    })

                except Exception as exc:
                    error_message = str(exc).replace(
                        app_password, "[hidden]"
                    )

                    results.append({
                        "success": False,
                        "email": recipient["email"],
                        "message": (
                            f"Failed for {recipient['email']}: "
                            f"{error_message[:250]}"
                        )
                    })

    sent = sum(1 for item in results if item["success"])
    failed = len(results) - sent

    return jsonify({
        "success": failed == 0,
        "total": len(recipients),
        "sent": sent,
        "failed": failed,
        "results": results,
        "message": f"Completed: {sent} sent, {failed} failed."
    })


if __name__ == "__main__":
    app.run(debug=True)

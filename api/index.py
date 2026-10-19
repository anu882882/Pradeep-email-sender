
import os
import re
import ssl
import smtplib
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from email.utils import formataddr

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
    static_url_path="/static"
)

app.secret_key = os.environ.get("SESSION_SECRET", "replace-this-with-a-long-random-secret")

BATCH_SIZE = 5
MAX_RECIPIENTS = 25

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def parse_recipients(raw):
    items = re.split(r"[,;\s]+", raw or "")
    results = []
    seen = set()

    for item in items:
        email = item.strip().lower()
        if email and EMAIL_PATTERN.fullmatch(email) and email not in seen:
            seen.add(email)
            results.append(email)

    return results


@app.get("/")
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = os.environ.get("LOGIN_PASSWORD", "")

        if not password:
            return render_template(
                "login.html",
                error="LOGIN_PASSWORD environment variable is not configured."
            ), 500

        if request.form.get("password", "") == password:
            session["logged_in"] = True
            return redirect(url_for("home"))

        return render_template("login.html", error="Incorrect password."), 401

    return render_template("login.html")


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


def send_one(sender_name, gmail, app_password, recipient, subject, body, html_mode):
    message = EmailMessage()
    message["From"] = formataddr((sender_name, gmail))
    message["To"] = recipient
    message["Subject"] = subject

    if html_mode:
        message.set_content("This email contains an HTML message.")
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        "smtp.gmail.com", 465, context=context, timeout=25
    ) as server:
        server.login(gmail, app_password)
        server.send_message(message)

    return True


@app.post("/send-batch")
def send_batch():
    if not session.get("logged_in"):
        return jsonify({"error": "Your session expired. Please sign in again."}), 401

    data = request.get_json(silent=True) or {}

    sender_name = str(data.get("sender_name", "")).strip()
    gmail = str(data.get("gmail", "")).strip()
    app_password = str(data.get("app_password", "")).replace(" ", "")
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))
    recipients = parse_recipients(data.get("recipients", ""))
    html_mode = data.get("html_mode") is True

    if not sender_name or not gmail or not app_password or not subject or not body.strip():
        return jsonify({"error": "Please complete all message fields."}), 400

    if not EMAIL_PATTERN.fullmatch(gmail):
        return jsonify({"error": "Enter a valid sender email address."}), 400

    if not recipients:
        return jsonify({"error": "Enter at least one valid recipient."}), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({"error": f"Maximum {MAX_RECIPIENTS} unique recipients per request."}), 400

    sent = []
    failed = []

    # Five concurrent messages per batch. Never retry failed messages automatically.
    for start in range(0, len(recipients), BATCH_SIZE):
        batch = recipients[start:start + BATCH_SIZE]

        with ThreadPoolExecutor(max_workers=BATCH_SIZE) as executor:
            futures = {
                recipient: executor.submit(
                    send_one,
                    sender_name,
                    gmail,
                    app_password,
                    recipient,
                    subject,
                    body,
                    html_mode
                )
                for recipient in batch
            }

            for recipient, future in futures.items():
                try:
                    future.result()
                    sent.append(recipient)
                except Exception:
                    failed.append(recipient)

    return jsonify({
        "total": len(recipients),
        "sent": len(sent),
        "failed": len(failed),
        "sent_recipients": sent,
        "failed_recipients": failed,
        "message": f"Finished: {len(sent)} sent, {len(failed)} failed."
    })


@app.errorhandler(500)
def server_error(error):
    app.logger.exception("Internal server error")
    return "Internal Server Error. Check the Vercel Function Logs.", 500

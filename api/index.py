
import os
import re
import ssl
import smtplib
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
    static_url_path="/static",
)

app.secret_key = os.environ.get("SESSION_SECRET", "change-this-secret-before-deploying")
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_RECIPIENTS = 25
BATCH_SIZE = 5


def valid_email(value):
    value = (value or "").strip()
    return bool(EMAIL_PATTERN.fullmatch(value))


def parse_recipients(raw):
    parts = re.split(r"[,;\s]+", raw or "")
    result = []
    seen = set()

    for item in parts:
        email = item.strip().lower()
        if email and valid_email(email) and email not in seen:
            seen.add(email)
            result.append(email)

    return result[:MAX_RECIPIENTS]


def send_one_email(sender_name, gmail, app_password,
                   recipient, subject, body, html_mode=False):
    msg = EmailMessage()
    msg["From"] = f"{sender_name} <{gmail}>"
    msg["To"] = recipient
    msg["Subject"] = subject or "(No subject)"
    msg.set_content(body or "")

    if html_mode:
        msg.add_alternative(body or "", subtype="html")

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        "smtp.gmail.com", 465, context=context, timeout=25
    ) as smtp:
        smtp.login(gmail, app_password)
        smtp.send_message(msg)

    return {"success": True, "recipient": recipient, "error": None}


@app.route("/health")
def health():
    return jsonify({"ok": True})


@app.route("/")
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        expected = os.environ.get("LOGIN_PASSWORD")

        if not expected:
            return render_template(
                "login.html",
                error="LOGIN_PASSWORD environment variable is not configured."
            )

        password = request.form.get("password", "")

        if password and password == expected:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("home"))

        return render_template("login.html", error="Incorrect password.")

    if session.get("logged_in"):
        return redirect(url_for("home"))

    return render_template("login.html", error=None)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/send-one", methods=["POST"])
def send_one():
    if not session.get("logged_in"):
        return jsonify({"success": False, "error": "Please log in again."}), 401

    data = request.get_json(silent=True) or {}

    sender_name = str(data.get("senderName", "")).strip()
    gmail = str(data.get("gmail", "")).strip()
    app_password = str(data.get("appPassword", "")).replace(" ", "")
    recipient = str(data.get("recipient", "")).strip().lower()
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))
    html_mode = data.get("htmlMode") is True

    if not sender_name or not gmail or not app_password:
        return jsonify({
            "success": False,
            "recipient": recipient,
            "error": "Enter sender name, Gmail and App Password."
        }), 400

    if not valid_email(gmail) or not valid_email(recipient):
        return jsonify({
            "success": False,
            "recipient": recipient,
            "error": "Invalid email address."
        }), 400

    try:
        result = send_one_email(
            sender_name, gmail, app_password,
            recipient, subject, body, html_mode
        )
        return jsonify(result)
    except Exception as exc:
        # Return a safe error message; do not expose credentials.
        message = str(exc).strip() or "SMTP sending failed."
        return jsonify({
            "success": False,
            "recipient": recipient,
            "error": message[:240]
        }), 200


if __name__ == "__main__":
    app.run(debug=False)

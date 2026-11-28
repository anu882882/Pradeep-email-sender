
import os
import re
import ssl
import smtplib
from email.message import EmailMessage
from email.utils import formataddr
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, render_template, request, redirect, url_for, session, jsonify

app = Flask(__name__, template_folder="../templates", static_folder="../static")

app.secret_key = os.environ.get("SESSION_SECRET")
if not app.secret_key:
    raise RuntimeError("Set SESSION_SECRET in environment variables.")

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 5

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true"
)


def logged_in():
    return session.get("authenticated") is True


def valid_email(email):
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))


@app.route("/")
def home():
    if not logged_in():
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":
        if LOGIN_PASSWORD and request.form.get("password", "") == LOGIN_PASSWORD:
            session.clear()
            session["authenticated"] = True
            return redirect(url_for("home"))
        error = "Incorrect password. Please try again."

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))


def send_email(recipient, sender, gmail, password, subject, body, is_html):
    personalized = body.replace("{{email}}", recipient)
    personalized = personalized.replace("{{name}}", recipient.split("@")[0])

    message = EmailMessage()
    message["From"] = formataddr((sender, gmail))
    message["To"] = recipient
    message["Subject"] = subject

    if is_html:
        message.set_content("This email contains an HTML message.")
        message.add_alternative(personalized, subtype="html")
    else:
        message.set_content(personalized)

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        context=ssl.create_default_context(),
        timeout=30
    ) as server:
        server.login(gmail, password)
        server.send_message(message)


@app.route("/send", methods=["POST"])
def send():
    if not logged_in():
        return jsonify(message="Please log in again."), 401

    data = request.get_json(silent=True) or {}

    sender = str(data.get("sender_name", "")).strip()
    gmail = str(data.get("gmail", "")).strip()
    password = str(data.get("app_password", "")).replace(" ", "")
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("message", ""))
    is_html = bool(data.get("is_html"))
    consent = bool(data.get("consent_confirmed"))

    if not all([sender, gmail, password, subject, body]):
        return jsonify(message="Please complete all email fields."), 400

    if not valid_email(gmail):
        return jsonify(message="Enter a valid Gmail address."), 400

    if not consent:
        return jsonify(message="Recipient consent confirmation is required."), 400

    recipients = list(dict.fromkeys(
        item.strip().lower()
        for item in re.split(r"[\s,;]+", str(data.get("recipients", "")))
        if item.strip()
    ))

    if not recipients:
        return jsonify(message="Enter recipient email addresses."), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify(message=f"Maximum {MAX_RECIPIENTS} recipients per request."), 400

    invalid = [email for email in recipients if not valid_email(email)]
    if invalid:
        return jsonify(message="Invalid recipient email address.", invalid_recipients=invalid), 400

    sent = 0
    failed = []

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_SENDS) as executor:
        tasks = {
            executor.submit(
                send_email, email, sender, gmail, password, subject, body, is_html
            ): email for email in recipients
        }

        for task in as_completed(tasks):
            try:
                task.result()
                sent += 1
            except Exception:
                failed.append(tasks[task])

    return jsonify(
        message=f"Finished. SMTP accepted {sent} message(s); {len(failed)} failed.",
        total=len(recipients),
        sent=sent,
        failed=len(failed),
        failed_recipients=failed
    )


@app.route("/health")
def health():
    return jsonify(status="ok")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

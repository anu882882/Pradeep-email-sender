
import os
import re
import ssl
import smtplib
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from email.utils import formataddr

from flask import Flask, render_template, request, redirect, url_for, session, jsonify

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

app.secret_key = os.environ.get("SESSION_SECRET", "change-this-secret-before-deployment")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
)

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 5


def logged_in():
    return session.get("authenticated") is True


def valid_email(address):
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", address))


@app.route("/", methods=["GET"])
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
        password = request.form.get("password", "")

        if LOGIN_PASSWORD and password == LOGIN_PASSWORD:
            session.clear()
            session["authenticated"] = True
            return redirect(url_for("home"))

        error = "Incorrect password. Please try again."

    return render_template("login.html", error=error)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


def send_one_email(recipient, sender_name, gmail, app_password,
                   subject, body, is_html):
    message = EmailMessage()
    message["From"] = formataddr((sender_name, gmail))
    message["To"] = recipient
    message["Subject"] = subject

    personalized = body.replace("{{email}}", recipient)
    personalized = personalized.replace("{{name}}", recipient.split("@")[0])

    if is_html:
        message.set_content("This email contains an HTML message.")
        message.add_alternative(personalized, subtype="html")
    else:
        message.set_content(personalized)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        "smtp.gmail.com",
        465,
        context=context,
        timeout=30
    ) as server:
        server.login(gmail, app_password)
        server.send_message(message)

    return recipient


@app.route("/send", methods=["POST"])
def send():
    if not logged_in():
        return jsonify({"message": "Please log in again."}), 401

    data = request.get_json(silent=True) or {}

    sender_name = str(data.get("sender_name", "")).strip()
    gmail = str(data.get("gmail", "")).strip()
    app_password = str(data.get("app_password", "")).replace(" ", "")
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("message", ""))
    is_html = bool(data.get("is_html", False))
    consent = bool(data.get("consent_confirmed", False))

    if not all([sender_name, gmail, app_password, subject, body]):
        return jsonify({"message": "Please complete all email fields."}), 400

    if not valid_email(gmail):
        return jsonify({"message": "Please enter a valid Gmail address."}), 400

    if not consent:
        return jsonify({"message": "Recipient consent confirmation is required."}), 400

    raw_recipients = str(data.get("recipients", ""))
    recipients = list(dict.fromkeys(
        item.strip().lower()
        for item in re.split(r"[\s,;]+", raw_recipients)
        if item.strip()
    ))

    if not recipients:
        return jsonify({"message": "Please enter recipient email addresses."}), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "message": f"A maximum of {MAX_RECIPIENTS} recipients is allowed per request."
        }), 400

    invalid = [email for email in recipients if not valid_email(email)]

    if invalid:
        return jsonify({
            "message": "One or more recipient email addresses are invalid.",
            "invalid_recipients": invalid
        }), 400

    sent = 0
    failed_recipients = []

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_SENDS) as executor:
        futures = {
            executor.submit(
                send_one_email,
                recipient,
                sender_name,
                gmail,
                app_password,
                subject,
                body,
                is_html
            ): recipient
            for recipient in recipients
        }

        for future in as_completed(futures):
            recipient = futures[future]
            try:
                future.result()
                sent += 1
            except Exception:
                failed_recipients.append(recipient)

    failed = len(failed_recipients)

    return jsonify({
        "message": f"Finished. SMTP accepted {sent} message(s); {failed} failed.",
        "total": len(recipients),
        "sent": sent,
        "failed": failed,
        "failed_recipients": failed_recipients
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

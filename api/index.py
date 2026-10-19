
import os
import re
import ssl
import smtplib
import secrets
import urllib.parse
import urllib.request
import json

from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, url_for, session, jsonify

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

app.secret_key = os.environ.get("SESSION_SECRET", "")

BATCH_SIZE = 5
MAX_RECIPIENTS = 25
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def verify_turnstile(token):
    secret = os.environ.get("TURNSTILE_SECRET_KEY", "")
    if not secret or not token:
        return False

    data = urllib.parse.urlencode({
        "secret": secret,
        "response": token,
    }).encode()

    try:
        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=8) as response:
            result = json.loads(response.read().decode())
        return bool(result.get("success"))
    except Exception:
        app.logger.exception("Turnstile verification failed")
        return False


def parse_recipients(raw):
    recipients = []
    seen = set()

    for item in re.split(r"[,;\s]+", raw or ""):
        email = item.strip().lower()
        if email and email not in seen and EMAIL_PATTERN.fullmatch(email):
            seen.add(email)
            recipients.append(email)

    return recipients


def send_one(recipient, sender_name, gmail, app_password, subject, body, html_mode):
    message = EmailMessage()
    message["From"] = f"{sender_name} <{gmail}>"
    message["To"] = recipient
    message["Subject"] = subject

    if html_mode:
        message.set_content("This message contains HTML content. Please use an HTML-capable email client.")
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=20) as smtp:
        smtp.login(gmail, app_password)
        smtp.send_message(message)

    return recipient


@app.get("/")
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get("TURNSTILE_SITE_KEY", ""),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if not app.secret_key:
        return (
            "Server configuration error: SESSION_SECRET is not set in Vercel.",
            500,
        )

    if request.method == "POST":
        expected_password = os.environ.get("LOGIN_PASSWORD", "")
        password = request.form.get("password", "")
        token = request.form.get("cf-turnstile-response", "")

        if not expected_password:
            return "Server configuration error: LOGIN_PASSWORD is not set.", 500

        if not secrets.compare_digest(password, expected_password):
            return render_template(
                "login.html",
                error="Incorrect password.",
                turnstile_site_key=os.environ.get("TURNSTILE_SITE_KEY", ""),
            ), 401

        if not verify_turnstile(token):
            return render_template(
                "login.html",
                error="Verification failed. Please try again.",
                turnstile_site_key=os.environ.get("TURNSTILE_SITE_KEY", ""),
            ), 400

        session.clear()
        session["logged_in"] = True
        return redirect(url_for("home"))

    return render_template(
        "login.html",
        error=None,
        turnstile_site_key=os.environ.get("TURNSTILE_SITE_KEY", ""),
    )


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.post("/send-batch")
def send_batch():
    if not session.get("logged_in"):
        return jsonify({"error": "Please log in again."}), 401

    data = request.get_json(silent=True) or {}

    if not verify_turnstile(data.get("turnstile_token", "")):
        return jsonify({"error": "Verification failed. Please try again."}), 400

    sender_name = str(data.get("sender_name", "")).strip()[:100]
    gmail = str(data.get("gmail", "")).strip().lower()
    app_password = str(data.get("app_password", "")).replace(" ", "")
    subject = str(data.get("subject", "")).strip()[:250]
    body = str(data.get("body", "")).strip()
    html_mode = bool(data.get("html_mode", False))
    recipients = parse_recipients(str(data.get("recipients", "")))

    if not sender_name or not subject or not body:
        return jsonify({"error": "Fill in the sender name, subject, and message."}), 400

    if not EMAIL_PATTERN.fullmatch(gmail):
        return jsonify({"error": "Enter a valid Gmail address."}), 400

    if not app_password:
        return jsonify({"error": "Enter your Gmail app password."}), 400

    if not recipients:
        return jsonify({"error": "Enter at least one valid recipient address."}), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "error": f"Maximum {MAX_RECIPIENTS} recipients are allowed per request."
        }), 400

    results = []

    # Send in groups of five. All sends finish before this request returns.
    for start in range(0, len(recipients), BATCH_SIZE):
        batch = recipients[start:start + BATCH_SIZE]

        with ThreadPoolExecutor(max_workers=BATCH_SIZE) as executor:
            futures = {
                recipient: executor.submit(
                    send_one,
                    recipient,
                    sender_name,
                    gmail,
                    app_password,
                    subject,
                    body,
                    html_mode,
                )
                for recipient in batch
            }

            for recipient, future in futures.items():
                try:
                    future.result()
                    results.append({"recipient": recipient, "status": "Sent"})
                except Exception:
                    app.logger.exception("Email send failed for %s", recipient)
                    results.append({
                        "recipient": recipient,
                        "status": "Failed",
                        "message": "SMTP delivery failed. Check credentials and provider limits.",
                    })

    return jsonify({
        "total": len(results),
        "sent": sum(item["status"] == "Sent" for item in results),
        "failed": sum(item["status"] == "Failed" for item in results),
        "results": results,
    })


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=False)

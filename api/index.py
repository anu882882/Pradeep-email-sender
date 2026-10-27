
import os
import re
import ssl
import time
import smtplib
from email.message import EmailMessage
from email.utils import formataddr
from flask import Flask, render_template, request, redirect, url_for, session, jsonify

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

app.secret_key = os.environ.get("SESSION_SECRET") or os.urandom(32).hex()
app.config["MAX_CONTENT_LENGTH"] = 1_000_000

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
MAIL_GAP_SECONDS = max(
    0.0, min(float(os.environ.get("MAIL_GAP_SECONDS", "0.5")), 10.0)
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def logged_in():
    return session.get("logged_in") is True


def open_smtp(sender, password):
    context = ssl.create_default_context()

    if SMTP_PORT == 465:
        server = smtplib.SMTP_SSL(
            SMTP_HOST, SMTP_PORT, timeout=20, context=context
        )
        server.ehlo()
    else:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()

    server.login(sender, password)
    return server


def make_message(sender, sender_name, recipient, subject, body, html_mode):
    msg = EmailMessage()
    msg["From"] = formataddr((sender_name or sender, sender))
    msg["To"] = recipient
    msg["Subject"] = subject

    if html_mode:
        msg.set_content("Please view this message in an HTML-compatible email client.")
        msg.add_alternative(body, subtype="html")
    else:
        msg.set_content(body)

    return msg


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        if not LOGIN_PASSWORD:
            error = "LOGIN_PASSWORD is missing from environment variables."
        elif request.form.get("password", "") == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("index"))
        else:
            error = "Incorrect password."

    return render_template("login.html", error=error)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    if not logged_in():
        return redirect(url_for("login"))
    return render_template("index.html")


@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify({"error": "Session expired. Please sign in again."}), 401

    data = request.get_json(silent=True) or {}

    sender = str(data.get("senderEmail", "")).strip().lower()
    password = str(data.get("appPassword", "")).replace(" ", "")
    sender_name = str(data.get("senderName", "")).strip()[:100]
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True
    recipients = data.get("recipients", [])

    if data.get("consentConfirmed") is not True:
        return jsonify({"error": "Confirm that recipients agreed to receive email."}), 400

    if not EMAIL_RE.fullmatch(sender):
        return jsonify({"error": "Enter a valid Gmail address."}), 400

    if not sender.endswith("@gmail.com"):
        return jsonify({"error": "Use a Gmail address for this SMTP configuration."}), 400

    if not password:
        return jsonify({"error": "Enter your Google App Password."}), 400

    if not isinstance(recipients, list):
        return jsonify({"error": "Recipients must be a list."}), 400

    clean = []
    for item in recipients:
        if isinstance(item, str):
            address = item.strip().lower()
            if EMAIL_RE.fullmatch(address) and address not in clean:
                clean.append(address)

    if not clean:
        return jsonify({"error": "No valid recipients found."}), 400

    if len(clean) > 5:
        return jsonify({"error": "Maximum 5 recipients per request."}), 400

    if not subject or not body:
        return jsonify({"error": "Subject and message body are required."}), 400

    if len(subject) > 200 or len(body) > 100_000:
        return jsonify({"error": "Subject or message is too long."}), 400

    results = []
    server = None

    try:
        server = open_smtp(sender, password)

        for i, recipient in enumerate(clean):
            msg = make_message(
                sender, sender_name, recipient, subject, body, html_mode
            )

            try:
                refused = server.send_message(msg)

                if refused:
                    results.append({
                        "email": recipient,
                        "status": "failed",
                        "detail": "Recipient rejected by SMTP server."
                    })
                else:
                    results.append({
                        "email": recipient,
                        "status": "sent",
                        "detail": "SMTP server accepted the message."
                    })

            except smtplib.SMTPRecipientsRefused:
                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": "Recipient address was rejected."
                })
            except smtplib.SMTPDataError as exc:
                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": f"SMTP rejected message (code {exc.smtp_code})."
                })
            except (smtplib.SMTPException, OSError) as exc:
                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": f"SMTP error: {str(exc)[:120]}"
                })
                break

            if i < len(clean) - 1 and MAIL_GAP_SECONDS:
                time.sleep(MAIL_GAP_SECONDS)

    except smtplib.SMTPAuthenticationError:
        return jsonify({
            "error": "Gmail login failed. Verify your Gmail address and App Password."
        }), 400
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        return jsonify({
            "error": f"SMTP connection failed: {str(exc)[:160]}"
        }), 502
    finally:
        if server is not None:
            try:
                server.quit()
            except (smtplib.SMTPException, OSError):
                pass

    sent = sum(item["status"] == "sent" for item in results)
    failed = len(clean) - sent
    completed = {item["email"] for item in results}

    for recipient in clean:
        if recipient not in completed:
            results.append({
                "email": recipient,
                "status": "failed",
                "detail": "Not attempted because the SMTP connection failed."
            })

    return jsonify({
        "total": len(clean),
        "sent": sent,
        "failed": failed,
        "results": results
    })

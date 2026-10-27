```python
import os
import re
import time
import ssl
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

app.secret_key = os.environ.get("SESSION_SECRET") or os.urandom(32).hex()

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))

# Email ke beech 1 second ka configured gap
MAIL_GAP_SECONDS = max(
    0.0,
    min(float(os.environ.get("MAIL_GAP_SECONDS", "1")), 30.0)
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def logged_in():
    return session.get("logged_in") is True


def open_smtp(sender, password):
    """SMTP connection open karke sender ko authenticate kare."""
    if SMTP_PORT == 465:
        server = smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=30,
            context=ssl.create_default_context(),
        )
    else:
        server = smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT,
            timeout=30,
        )
        server.ehlo()
        server.starttls(context=ssl.create_default_context())
        server.ehlo()

    server.login(sender, password)
    return server


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "login_configured": bool(LOGIN_PASSWORD),
        "smtp_host": SMTP_HOST,
        "smtp_port": SMTP_PORT,
        "mail_gap_seconds": MAIL_GAP_SECONDS,
    })


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")

        if not LOGIN_PASSWORD:
            return render_template(
                "login.html",
                error="LOGIN_PASSWORD environment variable is not configured.",
            ), 500

        if password == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            session.permanent = False
            return redirect(url_for("index"))

        return render_template(
            "login.html",
            error="Incorrect password. Please try again.",
        ), 401

    if logged_in():
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    if not logged_in():
        return redirect(url_for("login"))

    return render_template("index.html")


@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not logged_in():
        return jsonify({
            "success": False,
            "error": "Your session has expired. Please sign in again.",
        }), 401

    data = request.get_json(silent=True) or {}

    if data.get("consentConfirmed") is not True:
        return jsonify({
            "success": False,
            "error": "Please confirm that the recipients agreed to receive these emails.",
        }), 400

    sender = data.get("sender", "").strip()
    password = data.get("appPassword", "")
    sender_name = data.get("senderName", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "")
    body_mode = data.get("bodyMode", "text")
    recipients = data.get("recipients", [])

    if not sender or not EMAIL_RE.fullmatch(sender):
        return jsonify({
            "success": False,
            "error": "Enter a valid sender email address.",
        }), 400

    if not sender.lower().endswith("@gmail.com"):
        return jsonify({
            "success": False,
            "error": "Please use a Gmail address.",
        }), 400

    if not password:
        return jsonify({
            "success": False,
            "error": "Enter your Gmail App Password.",
        }), 400

    if not subject:
        return jsonify({
            "success": False,
            "error": "Enter an email subject.",
        }), 400

    if not isinstance(body, str) or not body.strip():
        return jsonify({
            "success": False,
            "error": "Enter the email message.",
        }), 400

    if body_mode not in ("text", "html"):
        body_mode = "text"

    if not isinstance(recipients, list) or not recipients:
        return jsonify({
            "success": False,
            "error": "Add at least one recipient.",
        }), 400

    # Frontend se ek request mein maximum 5 recipients.
    if len(recipients) > 5:
        return jsonify({
            "success": False,
            "error": "Send no more than 5 recipients per batch.",
        }), 400

    cleaned_recipients = []
    seen = set()

    for item in recipients:
        if not isinstance(item, str):
            continue

        address = item.strip()

        if not EMAIL_RE.fullmatch(address):
            continue

        if address.lower() not in seen:
            cleaned_recipients.append(address)
            seen.add(address.lower())

    if not cleaned_recipients:
        return jsonify({
            "success": False,
            "error": "No valid recipient addresses were provided.",
        }), 400

    results = []
    sent = 0
    failed = 0
    server = None

    try:
        server = open_smtp(sender, password)

        for index, recipient in enumerate(cleaned_recipients):
            try:
                message = EmailMessage()
                message["From"] = formataddr(
                    (sender_name, sender) if sender_name else ("", sender)
                )
                message["To"] = recipient
                message["Subject"] = subject

                if body_mode == "html":
                    message.set_content(
                        "This email contains an HTML message. "
                        "Please view it in an HTML-compatible email client."
                    )
                    message.add_alternative(body, subtype="html")
                else:
                    message.set_content(body)

                server.send_message(message)
                sent += 1

                results.append({
                    "recipient": recipient,
                    "status": "sent",
                    "message": "SMTP server accepted the message.",
                })

            except (smtplib.SMTPException, OSError, ValueError) as exc:
                failed += 1
                results.append({
                    "recipient": recipient,
                    "status": "failed",
                    "message": str(exc)[:300],
                })

                # Authentication/connection errors can invalidate
                # the current SMTP connection.
                if isinstance(exc, (smtplib.SMTPServerDisconnected, OSError)):
                    try:
                        server.quit()
                    except Exception:
                        pass

                    server = None

                    if index < len(cleaned_recipients) - 1:
                        try:
                            server = open_smtp(sender, password)
                        except Exception as reconnect_error:
                            for remaining in cleaned_recipients[index + 1:]:
                                failed += 1
                                results.append({
                                    "recipient": remaining,
                                    "status": "failed",
                                    "message": (
                                        "SMTP reconnect failed: "
                                        + str(reconnect_error)[:200]
                                    ),
                                })
                            break

            # Wait only between recipients, not after the last one.
            if index < len(cleaned_recipients) - 1 and MAIL_GAP_SECONDS > 0:
                time.sleep(MAIL_GAP_SECONDS)

    except (smtplib.SMTPException, OSError, ValueError) as exc:
        return jsonify({
            "success": False,
            "error": "SMTP connection or authentication failed: "
                     + str(exc)[:300],
            "sent": sent,
            "failed": failed,
            "results": results,
        }), 502

    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass

    return jsonify({
        "success": failed == 0,
        "sent": sent,
        "failed": failed,
        "total": len(cleaned_recipients),
        "results": results,
        "mail_gap_seconds": MAIL_GAP_SECONDS,
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
```

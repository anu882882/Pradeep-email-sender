
import os
import re
import ssl
import smtplib
from functools import wraps
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, url_for, session, jsonify

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
    static_url_path="/static",
)

app.secret_key = os.environ.get("SESSION_SECRET", "change-this-secret-before-deploying")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith("/send-"):
                return jsonify({"success": False, "error": "Please sign in again."}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        expected = os.environ.get("LOGIN_PASSWORD", "")
        supplied = request.form.get("password", "")

        if expected and supplied and supplied == expected:
            session.clear()
            session["authenticated"] = True
            return redirect(url_for("index"))

        return render_template("login.html", error="Incorrect password. Please try again.")

    if session.get("authenticated"):
        return redirect(url_for("index"))

    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/send-one", methods=["POST"])
@login_required
def send_one():
    data = request.get_json(silent=True) or {}

    sender_name = str(data.get("senderName", "")).strip()[:150]
    gmail = str(data.get("gmail", "")).strip()
    app_password = str(data.get("appPassword", "")).replace(" ", "")
    subject = str(data.get("subject", "")).strip()[:300]
    body = str(data.get("body", ""))
    recipient = str(data.get("recipient", "")).strip().lower()
    html_mode = data.get("htmlMode") is True

    if not all([sender_name, gmail, app_password, subject, body, recipient]):
        return jsonify({"success": False, "error": "Please complete all required fields."}), 400

    if not EMAIL_PATTERN.fullmatch(gmail) or not EMAIL_PATTERN.fullmatch(recipient):
        return jsonify({"success": False, "error": "Invalid email address."}), 400

    if len(body) > 100000:
        return jsonify({"success": False, "error": "Message body is too long."}), 400

    message = EmailMessage()
    message["From"] = f"{sender_name} <{gmail}>"
    message["To"] = recipient
    message["Subject"] = subject

    if html_mode:
        message.set_content("This message contains HTML content. Please view it in an HTML-compatible email client.")
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=context,
            timeout=25,
        ) as server:
            server.login(gmail, app_password)
            server.send_message(message)

        return jsonify({"success": True, "recipient": recipient})

    except smtplib.SMTPAuthenticationError:
        return jsonify({
            "success": False,
            "error": "Gmail authentication failed. Check your Gmail and App Password."
        }), 400
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        return jsonify({
            "success": False,
            "error": f"Mail server error: {str(exc)[:250]}"
        }), 502
    except Exception:
        app.logger.exception("Unexpected email sending error")
        return jsonify({"success": False, "error": "Unexpected server error."}), 500

from flask import Flask, render_template, request, jsonify
import smtplib
import ssl
import re
from email.mime.text import MIMEText
from email.utils import formataddr
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static"
)

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    return bool(EMAIL_RE.fullmatch(value.strip()))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/send", methods=["POST"])
def send_email():
    data = request.get_json(silent=True) or {}

    sender_name = str(data.get("sender_name", "")).strip()
    gmail = str(data.get("gmail", "")).strip()
    app_password = str(data.get("app_password", "")).strip()
    recipient = str(data.get("recipient", "")).strip()
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))

    if not sender_name:
        return jsonify({
            "success": False,
            "message": "Sender Name is required."
        }), 400

    if not valid_email(gmail):
        return jsonify({
            "success": False,
            "message": "Enter a valid Gmail address."
        }), 400

    if not app_password:
        return jsonify({
            "success": False,
            "message": "Google App Password is required."
        }), 400

    if not valid_email(recipient):
        return jsonify({
            "success": False,
            "message": "Enter a valid recipient email."
        }), 400

    if not subject:
        return jsonify({
            "success": False,
            "message": "Subject is required."
        }), 400

    if not body.strip():
        return jsonify({
            "success": False,
            "message": "Message body is required."
        }), 400

    try:
        message = MIMEText(body, "plain", "utf-8")

        message["Subject"] = subject
        message["From"] = formataddr((sender_name, gmail))
        message["To"] = recipient

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=context,
            timeout=30
        ) as server:

            server.login(gmail, app_password)

            server.sendmail(
                gmail,
                [recipient],
                message.as_string()
            )

        return jsonify({
            "success": True,
            "message": f"Email sent to {recipient}."
        })

    except smtplib.SMTPAuthenticationError:
        return jsonify({
            "success": False,
            "message": (
                "Gmail authentication failed. "
                "Check the Gmail address and Google App Password."
            )
        }), 401

    except smtplib.SMTPException as exc:
        return jsonify({
            "success": False,
            "message": f"SMTP error: {str(exc)}"
        }), 500

    except Exception as exc:
        return jsonify({
            "success": False,
            "message": f"Server error: {str(exc)}"
        }), 500


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "Secure Mail Console"
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

from flask import Flask, render_template, request, jsonify
import smtplib
import ssl
from email.mime.text import MIMEText
from email.utils import formataddr

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/send", methods=["POST"])
def send_email():
    data = request.get_json(silent=True) or {}

    sender_name = data.get("sender_name", "").strip()
    gmail = data.get("gmail", "").strip()
    app_password = data.get("app_password", "").strip()
    recipient = data.get("recipient", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "")

    if not all([
        sender_name,
        gmail,
        app_password,
        recipient,
        subject,
        body
    ]):
        return jsonify({
            "success": False,
            "message": "Please complete all required fields."
        }), 400

    # This version intentionally sends to one recipient per request.
    if "," in recipient or ";" in recipient or "\n" in recipient:
        return jsonify({
            "success": False,
            "message": "Please send to one recipient at a time."
        }), 400

    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = formataddr((sender_name, gmail))
        msg["To"] = recipient

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
                msg.as_string()
            )

        return jsonify({
            "success": True,
            "message": "Email sent successfully."
        })

    except smtplib.SMTPAuthenticationError:
        return jsonify({
            "success": False,
            "message": "Gmail authentication failed. Check your email and App Password."
        }), 401

    except Exception as exc:
        return jsonify({
            "success": False,
            "message": str(exc)
        }), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

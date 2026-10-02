from flask import Flask, render_template, request, jsonify
import smtplib
import ssl
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


@app.route("/")
def home():
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

    if not sender_name:
        return jsonify({
            "success": False,
            "message": "Sender name is required."
        }), 400

    if not gmail:
        return jsonify({
            "success": False,
            "message": "Gmail address is required."
        }), 400

    if not app_password:
        return jsonify({
            "success": False,
            "message": "Gmail App Password is required."
        }), 400

    if not recipient:
        return jsonify({
            "success": False,
            "message": "Recipient is required."
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

    # One recipient per request
    if any(x in recipient for x in [",", ";", "\n", "\r"]):
        return jsonify({
            "success": False,
            "message": "Please enter one recipient email at a time."
        }), 400

    try:

        message = MIMEText(
            body,
            "plain",
            "utf-8"
        )

        message["Subject"] = subject
        message["From"] = formataddr(
            (sender_name, gmail)
        )
        message["To"] = recipient

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=context,
            timeout=30
        ) as server:

            server.login(
                gmail,
                app_password
            )

            server.sendmail(
                gmail,
                [recipient],
                message.as_string()
            )

        return jsonify({
            "success": True,
            "message": "Email sent successfully."
        })

    except smtplib.SMTPAuthenticationError:

        return jsonify({
            "success": False,
            "message": (
                "Gmail authentication failed. "
                "Use a valid Google App Password."
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


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

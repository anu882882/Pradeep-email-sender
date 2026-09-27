import os, ssl, smtplib, re
from functools import wraps
from email.mime.text import MIMEText
from flask import Flask, render_template, request, jsonify, session, redirect

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=ROOT + "/templates",
    static_folder=ROOT + "/static"
)

app.secret_key = os.getenv("SESSION_SECRET", "change-me")
LOGIN_PASS = os.getenv("APP_LOGIN_PASSWORD", "")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid_email(e):
    return bool(EMAIL_RE.fullmatch(e.strip()))


def clean_password(p):
    # Removes spaces/newlines accidentally added while copying
    return "".join(str(p).split())


def login_required(f):
    @wraps(f)
    def check(*args, **kwargs):
        if not session.get("login"):
            if request.path.startswith("/api/"):
                return jsonify(error="Login required"), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return check


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        if request.form.get("password") == LOGIN_PASS:
            session["login"] = True
            return redirect("/")

        return render_template(
            "login.html",
            error="Wrong password"
        )

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
@login_required
def home():
    return render_template("index.html")


@app.route("/api/protection")
@login_required
def protection():
    return jsonify(
        active=True,
        tls=True,
        authentication=True
    )


# =========================================================
# GMAIL DIAGNOSTICS
# =========================================================

@app.route("/api/diagnostics", methods=["POST"])
@login_required
def diagnostics():

    data = request.get_json() or {}

    gmail = str(
        data.get("gmail", "")
    ).strip().lower()

    # Important: remove spaces from copied App Password
    password = clean_password(
        data.get("app_password", "")
    )

    if not valid_email(gmail):
        return jsonify(
            error="Enter a valid Gmail address."
        ), 400

    if not password:
        return jsonify(
            error="Enter Gmail App Password."
        ), 400

    result = {
        "success": False,
        "connection": False,
        "tls": False,
        "authentication": False,
        "domain": gmail.split("@")[-1],
        "message": ""
    }

    try:

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=context,
            timeout=20
        ) as smtp:

            result["connection"] = True
            result["tls"] = True

            smtp.login(
                gmail,
                password
            )

            result["authentication"] = True
            result["success"] = True
            result["message"] = (
                "Gmail authentication successful."
            )

    except smtplib.SMTPAuthenticationError:

        result["message"] = (
            "Gmail authentication failed. "
            "Use a valid 16-character Gmail App Password."
        )

    except smtplib.SMTPConnectError:

        result["message"] = (
            "Could not connect to Gmail SMTP."
        )

    except smtplib.SMTPException as e:

        result["message"] = str(e)

    except Exception as e:

        result["message"] = str(e)

    return jsonify(result)


# =========================================================
# SEND EMAIL
# =========================================================

@app.route("/api/send", methods=["POST"])
@login_required
def send():

    data = request.get_json() or {}

    name = str(
        data.get("sender_name", "")
    ).strip()

    gmail = str(
        data.get("gmail", "")
    ).strip().lower()

    # Important: remove spaces from App Password
    password = clean_password(
        data.get("app_password", "")
    )

    subject = str(
        data.get("subject", "")
    ).strip()

    body = str(
        data.get("message", "")
    )

    raw = str(
        data.get("recipients", "")
    )

    recipients = list(
        dict.fromkeys(
            re.split(
                r"[\s,;]+",
                raw.strip().lower()
            )
        )
    )

    recipients = [
        x for x in recipients
        if x
    ]

    if not name:
        return jsonify(
            error="Sender name required."
        ), 400

    if not valid_email(gmail):
        return jsonify(
            error="Valid Gmail address required."
        ), 400

    if not password:
        return jsonify(
            error="Gmail App Password required."
        ), 400

    if not subject:
        return jsonify(
            error="Subject required."
        ), 400

    if not body.strip():
        return jsonify(
            error="Message required."
        ), 400

    if not recipients:
        return jsonify(
            error="Add recipients."
        ), 400

    if len(recipients) > 25:
        return jsonify(
            error="Maximum 25 recipients."
        ), 400

    invalid = [
        x for x in recipients
        if not valid_email(x)
    ]

    if invalid:
        return jsonify(
            error="Invalid recipient email.",
            invalid=invalid
        ), 400

    sent = []
    failed = []

    try:

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=context,
            timeout=30
        ) as smtp:

            smtp.login(
                gmail,
                password
            )

            for recipient in recipients:

                try:

                    text = body.replace(
                        "{name}",
                        recipient.split("@")[0]
                    )

                    mail = MIMEText(
                        text,
                        "plain",
                        "utf-8"
                    )

                    mail["Subject"] = subject
                    mail["From"] = (
                        f"{name} <{gmail}>"
                    )
                    mail["To"] = recipient

                    refused = smtp.sendmail(
                        gmail,
                        [recipient],
                        mail.as_string()
                    )

                    if refused:

                        failed.append({
                            "email": recipient,
                            "error": "SMTP rejected recipient."
                        })

                    else:

                        sent.append(recipient)

                except Exception as e:

                    failed.append({
                        "email": recipient,
                        "error": str(e)
                    })

        return jsonify(
            success=bool(sent),
            total=len(recipients),
            sent=len(sent),
            failed=len(failed),
            remaining=(
                len(recipients)
                - len(sent)
                - len(failed)
            ),
            sent_emails=sent,
            failed_emails=failed
        )

    except smtplib.SMTPAuthenticationError:

        return jsonify(
            error=(
                "Gmail authentication failed. "
                "Check the App Password."
            )
        ), 401

    except smtplib.SMTPConnectError:

        return jsonify(
            error="Could not connect to Gmail SMTP."
        ), 502

    except Exception as e:

        return jsonify(
            error=str(e)
        ), 500


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv("PORT", 5000)
        )
    )

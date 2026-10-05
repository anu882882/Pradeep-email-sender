from flask import Flask, request, jsonify, render_template, redirect, url_for, session, Response, stream_with_context
from pathlib import Path
from email.mime.text import MIMEText
from email.utils import formataddr
import os, re, ssl, json, random, smtplib, secrets, time

ROOT = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(ROOT / "templates"),
    static_folder=str(ROOT / "static"),
    static_url_path="/static"
)

app.secret_key = os.environ.get("SESSION_SECRET", "")

MAX_RECIPIENTS = 25
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 20

try:
    MAIL_GAP_SECONDS = max(
        0.0,
        float(os.environ.get("MAIL_GAP_SECONDS", "0"))
    )
except ValueError:
    MAIL_GAP_SECONDS = 0.0

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)

SPINTAX_RE = re.compile(r"\{([^{}]+)\}")


def valid_email(value):
    return bool(EMAIL_RE.fullmatch(str(value or "").strip()))


def logged_in():
    return session.get("authenticated") is True


def expand_spintax(text):
    text = str(text or "")

    def replace(match):
        options = [
            x.strip()
            for x in match.group(1).split("|")
            if x.strip()
        ]

        if len(options) < 2:
            return match.group(0)

        return random.choice(options)

    for _ in range(10):
        new_text = SPINTAX_RE.sub(replace, text)

        if new_text == text:
            break

        text = new_text

    return text


def clean_recipients(values):
    if not isinstance(values, list):
        return []

    result = []
    seen = set()

    for value in values:
        email = str(value or "").strip().lower()

        if not valid_email(email):
            continue

        if email in seen:
            continue

        seen.add(email)
        result.append(email)

    return result[:MAX_RECIPIENTS]


@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":
        entered = str(request.form.get("password", ""))
        configured = os.environ.get("LOGIN_PASSWORD", "")

        if not configured:
            error = "LOGIN_PASSWORD is not configured."
        elif secrets.compare_digest(entered, configured):
            session.clear()
            session["authenticated"] = True
            return redirect(url_for("home"))
        else:
            error = "Incorrect password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    if not logged_in():
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get(
            "TURNSTILE_SITE_KEY",
            ""
        )
    )


def build_message(
    sender_name,
    sender_email,
    recipient,
    subject,
    body,
    html_mode
):
    # Spintax is permanently enabled.
    final_subject = expand_spintax(subject)
    final_body = expand_spintax(body)

    message = MIMEText(
        final_body,
        "html" if html_mode else "plain",
        "utf-8"
    )

    message["Subject"] = final_subject
    message["From"] = formataddr((sender_name, sender_email))
    message["To"] = recipient

    return message


@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not logged_in():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    data = request.get_json(silent=True) or {}

    sender_name = str(
        data.get("sender_name", "")
    ).strip()

    gmail = str(
        data.get("gmail", "")
    ).strip().lower()

    app_password = str(
        data.get("app_password", "")
    ).strip()

    subject = str(
        data.get("subject", "")
    ).strip()

    body = str(
        data.get("body", "")
    )

    html_mode = bool(
        data.get("html_mode", False)
    )

    recipients = clean_recipients(
        data.get("recipients", [])
    )

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

    if not subject:
        return jsonify({
            "success": False,
            "message": "Email subject is required."
        }), 400

    if not body.strip():
        return jsonify({
            "success": False,
            "message": "Message Body is required."
        }), 400

    if not recipients:
        return jsonify({
            "success": False,
            "message": "No valid recipients found."
        }), 400

    @stream_with_context
    def stream():
        total = len(recipients)
        sent = 0
        failed = 0
        smtp = None

        def event(name, **extra):
            payload = {
                "event": name,
                "total": total,
                "sent": sent,
                "failed": failed,
                "remaining": total - sent - failed
            }
            payload.update(extra)
            return json.dumps(
                payload,
                ensure_ascii=False
            ) + "\n"

        yield event("started")

        try:
            context = ssl.create_default_context()

            smtp = smtplib.SMTP_SSL(
                SMTP_HOST,
                SMTP_PORT,
                context=context,
                timeout=SMTP_TIMEOUT
            )

            smtp.ehlo()
            smtp.login(gmail, app_password)

            yield event("connected")

            for recipient in recipients:
                try:
                    message = build_message(
                        sender_name,
                        gmail,
                        recipient,
                        subject,
                        body,
                        html_mode
                    )

                    smtp.sendmail(
                        gmail,
                        [recipient],
                        message.as_string()
                    )

                    sent += 1

                    yield event(
                        "sent",
                        email=recipient
                    )

                except Exception as exc:
                    failed += 1

                    yield event(
                        "failed",
                        email=recipient,
                        error=str(exc)
                    )

                if (
                    MAIL_GAP_SECONDS > 0
                    and sent + failed < total
                ):
                    time.sleep(
                        MAIL_GAP_SECONDS
                    )

        except smtplib.SMTPAuthenticationError:
            yield event(
                "error",
                message=(
                    "Gmail authentication failed. "
                    "Check the Gmail address and App Password."
                )
            )
            return

        except smtplib.SMTPException as exc:
            yield event(
                "error",
                message=f"SMTP error: {exc}"
            )
            return

        except Exception as exc:
            yield event(
                "error",
                message=f"Server error: {exc}"
            )
            return

        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    pass

        yield event(
            "complete",
            message="sending compleate Babu❤️"
        )

    return Response(
        stream(),
        content_type="application/x-ndjson; charset=utf-8",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no"
        }
    )


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "mailer": "Gmail SMTP SSL",
        "spintax": True,
        "max_recipients": MAX_RECIPIENTS
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

import os
import re
import ssl
import smtplib
import json
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, Response, stream_with_context
)

from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(ROOT, "templates"),
    static_folder=os.path.join(ROOT, "static")
)

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    "change-this-secret"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax"
)


# ---------------- CONFIG ----------------

LOGIN_PASSWORD = os.environ.get(
    "APP_LOGIN_PASSWORD", ""
)

SENDER_NAME = os.environ.get(
    "SENDER_NAME", ""
)

SENDER_GMAIL = os.environ.get(
    "SENDER_GMAIL", ""
)

SENDER_APP_PASSWORD = os.environ.get(
    "SENDER_APP_PASSWORD", ""
)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

MAX_RECIPIENTS = 25
BATCH_SIZE = 5


EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(x):
    return bool(
        EMAIL_RE.fullmatch(
            str(x).strip()
        )
    )


def recipients(raw):
    raw = str(raw or "")
    raw = raw.replace(",", "\n").replace(";", "\n")

    out = []
    seen = set()

    for x in raw.split():
        x = x.strip().lower()

        if x and x not in seen:
            seen.add(x)
            out.append(x)

    return out


def login_required(fn):

    @wraps(fn)
    def wrapper(*args, **kwargs):

        if not session.get("logged_in"):

            if request.path.startswith("/api/"):
                return jsonify({
                    "success": False,
                    "error": "Login required."
                }), 401

            return redirect(
                url_for("login")
            )

        return fn(*args, **kwargs)

    return wrapper


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if session.get("logged_in"):
        return redirect(url_for("home"))

    if request.method == "POST":

        password = request.form.get(
            "password", ""
        )

        if not LOGIN_PASSWORD:
            return render_template(
                "login.html",
                error="Login password is not configured."
            )

        if password != LOGIN_PASSWORD:
            return render_template(
                "login.html",
                error="Incorrect password."
            )

        session.clear()
        session["logged_in"] = True

        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ---------------- HOME ----------------

@app.route("/")
@login_required
def home():
    return render_template("index.html")


# ---------------- HEALTH ----------------

@app.route("/api/health")
def health():

    return jsonify({
        "ok": True,
        "service": "Secure Mail Console"
    })


# ---------------- SEND ONE ----------------

def send_one(recipient, subject, message):

    try:

        body = message.replace(
            "{name}",
            recipient.split("@")[0]
        )

        mail = MIMEText(
            body,
            "plain",
            "utf-8"
        )

        mail["Subject"] = Header(
            subject,
            "utf-8"
        )

        mail["From"] = formataddr(
            (SENDER_NAME, SENDER_GMAIL)
        )

        mail["To"] = recipient

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=25
        ) as smtp:

            smtp.login(
                SENDER_GMAIL,
                SENDER_APP_PASSWORD
            )

            refused = smtp.sendmail(
                SENDER_GMAIL,
                [recipient],
                mail.as_string()
            )

        if refused:
            return {
                "email": recipient,
                "status": "failed",
                "message": "SMTP rejected recipient."
            }

        return {
            "email": recipient,
            "status": "sent",
            "message": "SMTP accepted."
        }

    except smtplib.SMTPAuthenticationError:
        return {
            "email": recipient,
            "status": "failed",
            "message": "Gmail authentication failed."
        }

    except Exception as e:
        return {
            "email": recipient,
            "status": "failed",
            "message": str(e)
        }


# ---------------- LIVE SEND ----------------

@app.route("/api/send-live", methods=["POST"])
@login_required
def send_live():

    data = request.get_json(
        silent=True
    ) or {}

    subject = str(
        data.get("subject", "")
    ).strip()

    message = str(
        data.get("message", "")
    )

    to = recipients(
        data.get("recipients", "")
    )

    if not SENDER_NAME:
        return jsonify({
            "success": False,
            "error": "SENDER_NAME is not configured."
        }), 500

    if not valid_email(SENDER_GMAIL):
        return jsonify({
            "success": False,
            "error": "SENDER_GMAIL is not configured correctly."
        }), 500

    if not SENDER_APP_PASSWORD:
        return jsonify({
            "success": False,
            "error": "SENDER_APP_PASSWORD is not configured."
        }), 500

    if not subject:
        return jsonify({
            "success": False,
            "error": "Subject required."
        }), 400

    if not message.strip():
        return jsonify({
            "success": False,
            "error": "Message required."
        }), 400

    if not to:
        return jsonify({
            "success": False,
            "error": "Add recipients."
        }), 400

    if len(to) > MAX_RECIPIENTS:
        return jsonify({
            "success": False,
            "error": "Maximum 25 recipients."
        }), 400

    bad = [
        x for x in to
        if not valid_email(x)
    ]

    if bad:
        return jsonify({
            "success": False,
            "error": "Invalid recipient email.",
            "invalid": bad
        }), 400

    def stream():

        total = len(to)
        sent = 0
        failed = 0

        yield json.dumps({
            "type": "start",
            "total": total,
            "batch": BATCH_SIZE
        }) + "\n"

        for start in range(
            0,
            total,
            BATCH_SIZE
        ):

            batch = to[
                start:start + BATCH_SIZE
            ]

            with ThreadPoolExecutor(
                max_workers=BATCH_SIZE
            ) as pool:

                jobs = [
                    pool.submit(
                        send_one,
                        email,
                        subject,
                        message
                    )
                    for email in batch
                ]

                for job in as_completed(jobs):

                    result = job.result()

                    if result["status"] == "sent":
                        sent += 1
                    else:
                        failed += 1

                    done = sent + failed
                    remaining = total - done

                    yield json.dumps({
                        "type": "recipient",
                        "email": result["email"],
                        "status": result["status"],
                        "message": result["message"],
                        "total": total,
                        "sent": sent,
                        "failed": failed,
                        "remaining": remaining,
                        "percent": round(
                            done / total * 100,
                            1
                        )
                    }) + "\n"

        yield json.dumps({
            "type": "complete",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": 0
        }) + "\n"

    return Response(
        stream_with_context(stream()),
        content_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )


@app.route("/api/send", methods=["POST"])
@login_required
def send():
    return send_live()


# ---------------- PROTECTION ----------------

@app.route("/api/protection")
@login_required
def protection():

    return jsonify({
        "active": True,
        "real_smtp_check": True,
        "duplicate_filter": True,
        "invalid_filter": True,
        "max_recipients": 25,
        "batch_size": 5,
        "fake_cloudflare": False
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT", 5000
            )
        )
    )

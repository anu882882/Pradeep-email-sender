from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import os
import re
import json
import urllib.request
import urllib.error
import secrets
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static"
)

app.secret_key = os.environ.get("SESSION_SECRET", "")

MAX_RECIPIENTS = 25

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "")

TURNSTILE_SECRET_KEY = os.environ.get(
    "TURNSTILE_SECRET_KEY",
    ""
)

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    return bool(
        EMAIL_RE.fullmatch(
            value.strip()
        )
    )


def parse_recipients(value):
    if not value:
        return []

    pieces = re.split(
        r"[\s,;]+",
        value
    )

    result = []

    for piece in pieces:
        email = piece.strip().lower()

        if not email:
            continue

        if not valid_email(email):
            continue

        if email not in result:
            result.append(email)

    return result[:MAX_RECIPIENTS]


def authenticated():
    return session.get("authenticated") is True


# --------------------------------------------------
# TURNSTILE
# --------------------------------------------------

def verify_turnstile(token, remote_ip=None):

    if not TURNSTILE_SECRET_KEY:
        return False, "TURNSTILE_SECRET_KEY is not configured."

    if not token:
        return False, "Cloudflare verification is required."

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(
        payload
    ).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={
            "Content-Type":
                "application/x-www-form-urlencoded"
        },
        method="POST"
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=10
        ) as response:

            result = json.loads(
                response.read().decode("utf-8")
            )

        if result.get("success") is True:
            return True, None

        return False, "Cloudflare verification failed."

    except Exception:
        return False, "Unable to verify Cloudflare."


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if authenticated():
        return redirect(
            url_for("home")
        )

    error = None

    if request.method == "POST":

        password = str(
            request.form.get(
                "password",
                ""
            )
        )

        configured_password = os.environ.get(
            "LOGIN_PASSWORD",
            ""
        )

        if not configured_password:

            error = (
                "LOGIN_PASSWORD is not configured."
            )

        elif secrets.compare_digest(
            password,
            configured_password
        ):

            session["authenticated"] = True

            return redirect(
                url_for("home")
            )

        else:

            error = "Incorrect password."

    return render_template(
        "login.html",
        error=error
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route("/")
def home():

    if not authenticated():
        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get(
            "TURNSTILE_SITE_KEY",
            ""
        ),
        from_email=RESEND_FROM_EMAIL
    )


# --------------------------------------------------
# RESEND BATCH API
# --------------------------------------------------

def send_resend_batch(
    sender_name,
    recipients,
    subject,
    body,
    is_html
):

    if not RESEND_API_KEY:
        raise RuntimeError(
            "RESEND_API_KEY is not configured."
        )

    if not RESEND_FROM_EMAIL:
        raise RuntimeError(
            "RESEND_FROM_EMAIL is not configured."
        )

    # Resend requires a verified sender/domain.
    # Example:
    # Secure Mail <hello@yourdomain.com>

    from_value = RESEND_FROM_EMAIL.strip()

    if sender_name:
        from_value = (
            f"{sender_name} <{RESEND_FROM_EMAIL.strip()}>"
        )

    email_items = []

    for recipient in recipients:

        item = {
            "from": from_value,
            "to": [recipient],
            "subject": subject
        }

        if is_html:
            item["html"] = body
        else:
            item["text"] = body

        email_items.append(item)

    # One batch request for all recipients.
    payload = json.dumps(
        email_items
    ).encode("utf-8")

    idempotency_key = (
        "secure-mail-console/"
        + secrets.token_hex(16)
    )

    req = urllib.request.Request(
        "https://api.resend.com/emails/batch",
        data=payload,
        headers={
            "Authorization":
                f"Bearer {RESEND_API_KEY}",

            "Content-Type":
                "application/json",

            "Idempotency-Key":
                idempotency_key
        },
        method="POST"
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=30
        ) as response:

            response_body = (
                response
                .read()
                .decode("utf-8")
            )

            status_code = response.status

    except urllib.error.HTTPError as exc:

        error_body = ""

        try:
            error_body = (
                exc.read()
                .decode("utf-8")
            )
        except Exception:
            pass

        try:
            error_json = json.loads(
                error_body
            )

            message = (
                error_json.get("message")
                or error_json.get("error")
                or error_body
            )

        except Exception:
            message = error_body or str(exc)

        raise RuntimeError(
            f"Resend API error ({exc.code}): {message}"
        )

    except urllib.error.URLError as exc:

        raise RuntimeError(
            f"Unable to connect to Resend: {exc.reason}"
        )

    if status_code < 200 or status_code >= 300:

        raise RuntimeError(
            "Resend returned an unsuccessful response."
        )

    try:
        return json.loads(
            response_body
        )
    except Exception:
        return {
            "raw": response_body
        }


# --------------------------------------------------
# SEND BATCH
# --------------------------------------------------

@app.route(
    "/send-batch",
    methods=["POST"]
)
def send_batch():

    if not authenticated():

        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    sender_name = str(
        data.get(
            "sender_name",
            ""
        )
    ).strip()

    subject = str(
        data.get(
            "subject",
            ""
        )
    ).strip()

    body = str(
        data.get(
            "body",
            ""
        )
    )

    is_html = bool(
        data.get(
            "is_html",
            False
        )
    )

    recipients = data.get(
        "recipients",
        []
    )

    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    ).strip()

    # --------------------------------------------------
    # VALIDATION
    # --------------------------------------------------

    if not RESEND_API_KEY:

        return jsonify({
            "success": False,
            "message":
                "RESEND_API_KEY is not configured in Vercel."
        }), 500

    if not RESEND_FROM_EMAIL:

        return jsonify({
            "success": False,
            "message":
                "RESEND_FROM_EMAIL is not configured in Vercel."
        }), 500

    if not sender_name:

        return jsonify({
            "success": False,
            "message":
                "Sender Name is required."
        }), 400

    if not subject:

        return jsonify({
            "success": False,
            "message":
                "Subject is required."
        }), 400

    if not body.strip():

        return jsonify({
            "success": False,
            "message":
                "Message body is required."
        }), 400

    if not isinstance(
        recipients,
        list
    ):

        return jsonify({
            "success": False,
            "message":
                "Invalid recipient list."
        }), 400

    clean_recipients = []

    for item in recipients:

        email = str(
            item
        ).strip().lower()

        if not valid_email(email):
            continue

        if email not in clean_recipients:
            clean_recipients.append(email)

    clean_recipients = clean_recipients[
        :MAX_RECIPIENTS
    ]

    if not clean_recipients:

        return jsonify({
            "success": False,
            "message":
                "No valid recipients found."
        }), 400

    # --------------------------------------------------
    # TURNSTILE
    # --------------------------------------------------

    verified, verify_error = verify_turnstile(
        turnstile_token,
        request.headers.get(
            "X-Forwarded-For",
            request.remote_addr
        )
    )

    if not verified:

        return jsonify({
            "success": False,
            "message": verify_error
        }), 403

    # --------------------------------------------------
    # SEND THROUGH RESEND
    # --------------------------------------------------

    try:

        result = send_resend_batch(
            sender_name=sender_name,
            recipients=clean_recipients,
            subject=subject,
            body=body,
            is_html=is_html
        )

    except Exception as exc:

        return jsonify({
            "success": False,
            "message": str(exc),
            "total": len(clean_recipients),
            "sent_count": 0,
            "failed_count": len(clean_recipients),
            "remaining": 0
        }), 502

    # --------------------------------------------------
    # SUCCESS
    #
    # At this point Resend accepted the batch request.
    # Individual delivery happens in Resend's system.
    # --------------------------------------------------

    return jsonify({

        "success": True,

        "message": (
            f"{len(clean_recipients)} email(s) "
            "accepted by the email provider."
        ),

        "total":
            len(clean_recipients),

        "sent_count":
            len(clean_recipients),

        "failed_count":
            0,

        "remaining":
            0,

        "provider":
            "Resend",

        "provider_response":
            result

    })


# --------------------------------------------------
# HEALTH
# --------------------------------------------------

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "Secure Mail Console",
        "mailer": "Resend API"
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

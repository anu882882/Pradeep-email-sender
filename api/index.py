
import os
import re
import json
import time
import html
import urllib.request
import urllib.error
import urllib.parse
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
    static_url_path="/static",
)

app.secret_key = os.environ.get("SESSION_SECRET", "replace-this-secret")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
TURNSTILE_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
RESEND_URL = "https://api.resend.com/emails"
VERIFY_TTL = 600


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith(("/send-", "/verify-")):
                return jsonify({
                    "success": False,
                    "error": "Please sign in again."
                }), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def verify_turnstile(token, remote_ip=None):
    secret = os.environ.get("TURNSTILE_SECRET_KEY", "")
    if not secret or not token:
        return False, "Spam Protection is not configured."

    fields = {
        "secret": secret,
        "response": token,
    }
    if remote_ip:
        fields["remoteip"] = remote_ip

    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        TURNSTILE_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))

        if result.get("success") is not True:
            return False, "Verification failed. Please try again."

        expected = os.environ.get("TURNSTILE_HOSTNAME", "").strip().lower()
        actual = str(result.get("hostname", "")).lower()

        if expected and actual != expected:
            return False, "Verification hostname did not match."

        return True, ""

    except Exception:
        app.logger.exception("Turnstile verification request failed")
        return False, "Cloudflare verification is temporarily unavailable."


def send_with_resend(sender_name, recipient, subject, body, html_mode):
    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    from_email = os.environ.get("RESEND_FROM_EMAIL", "").strip()

    if not api_key:
        raise ValueError("RESEND_API_KEY is missing in Vercel Environment Variables.")

    if not from_email or not EMAIL_PATTERN.fullmatch(from_email):
        raise ValueError(
            "Set RESEND_FROM_EMAIL to a valid sender address on your verified domain."
        )

    safe_name = sender_name.replace("\r", "").replace("\n", "").strip()
    from_value = f"{safe_name} <{from_email}>" if safe_name else from_email

    payload = {
        "from": from_value,
        "to": [recipient],
        "subject": subject,
    }

    if html_mode:
        payload["html"] = body
        payload["text"] = "This message is available in HTML format."
    else:
        payload["text"] = body

    req = urllib.request.Request(
        RESEND_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            result = json.loads(response.read().decode("utf-8"))

        email_id = result.get("id")
        if not email_id:
            raise RuntimeError("Resend did not return an email ID.")

        return email_id

    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8")[:1500]
        except Exception:
            detail = "No error details returned."

        app.logger.error("Resend API returned HTTP %s: %s", exc.code, detail)

        # Do not automatically retry: a send request may have been accepted.
        raise RuntimeError(
            f"Resend API error ({exc.code}). Check the API key, sender domain, "
            "recipient permissions and Resend logs."
        ) from exc


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

        return render_template("login.html", error="Incorrect password.")

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
    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get("TURNSTILE_SITE_KEY", ""),
    )


@app.route("/verify-turnstile", methods=["POST"])
@login_required
def verify_turnstile_route():
    data = request.get_json(silent=True) or {}
    token = str(data.get("token", "")).strip()

    if not token:
        session.pop("turnstile_verified_at", None)
        return jsonify({
            "success": False,
            "error": "Complete Spam Protection verification first."
        }), 400

    ok, error = verify_turnstile(token, request.remote_addr)

    if not ok:
        session.pop("turnstile_verified_at", None)
        return jsonify({"success": False, "error": error}), 400

    session["turnstile_verified_at"] = int(time.time())
    return jsonify({"success": True})


@app.route("/send-one", methods=["POST"])
@login_required
def send_one():
    verified_at = session.get("turnstile_verified_at", 0)

    if (
        not isinstance(verified_at, (int, float))
        or time.time() - verified_at > VERIFY_TTL
    ):
        session.pop("turnstile_verified_at", None)
        return jsonify({
            "success": False,
            "error": "Verification expired. Complete Spam Protection again."
        }), 401

    data = request.get_json(silent=True) or {}

    sender_name = str(data.get("senderName", "")).strip()[:150]
    recipient = str(data.get("recipient", "")).strip().lower()
    subject = str(data.get("subject", "")).strip()[:300]
    body = str(data.get("body", ""))
    html_mode = data.get("htmlMode") is True

    if not sender_name or not recipient or not subject or not body.strip():
        return jsonify({
            "success": False,
            "error": "Complete all required fields."
        }), 400

    if not EMAIL_PATTERN.fullmatch(recipient):
        return jsonify({
            "success": False,
            "error": "Invalid recipient email address."
        }), 400

    if len(body) > 100000:
        return jsonify({
            "success": False,
            "error": "Message body is too long."
        }), 400

    try:
        email_id = send_with_resend(
            sender_name, recipient, subject, body, html_mode
        )
        return jsonify({
            "success": True,
            "recipient": recipient,
            "emailId": email_id,
        })

    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 500

    except RuntimeError as exc:
        return jsonify({"success": False, "error": str(exc)}), 502

    except Exception:
        app.logger.exception("Unexpected Resend sending error")
        return jsonify({
            "success": False,
            "error": "Unexpected sending error. Check Vercel logs."
        }), 502

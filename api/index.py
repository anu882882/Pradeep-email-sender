import os
import re
import json
import time

from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    Response,
    stream_with_context,
)

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static",
)

app.secret_key = os.getenv(
    "SESSION_SECRET",
    "change-this-secret"
)

LOGIN_PASSWORD = os.getenv(
    "APP_LOGIN_PASSWORD",
    "change-this-password"
)

MAX_RECIPIENTS = 25
BATCH_SIZES = [8, 8, 9]

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def is_valid_email(email):
    return bool(
        email and
        EMAIL_PATTERN.fullmatch(
            str(email).strip()
        )
    )


def parse_recipients(value):
    if not value:
        return []

    pieces = re.split(
        r"[\s,;]+",
        str(value)
    )

    result = []
    seen = set()

    for item in pieces:
        email = item.strip().lower()

        if not email:
            continue

        if email in seen:
            continue

        seen.add(email)
        result.append(email)

        if len(result) >= MAX_RECIPIENTS:
            break

    return result


def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("authenticated"):
            return jsonify(
                error="Login required."
            ), 401

        return function(*args, **kwargs)

    return wrapper


def make_event(name, data):
    return (
        f"event: {name}\n"
        f"data: {json.dumps(data)}\n\n"
    )


# -------------------------------------------------
# APPROVED EMAIL PROVIDER HOOK
# -------------------------------------------------

def send_one(recipient, sender_data):
    """
    Connect this function to your approved,
    opt-in email provider.

    It intentionally does not implement Gmail
    bulk SMTP sending.
    """

    # Example placeholder:
    #
    # provider.send(
    #     to=recipient,
    #     subject=sender_data["subject"],
    #     html=sender_data["message"]
    # )

    return True


# -------------------------------------------------
# LOGIN
# -------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        password = str(
            request.form.get(
                "password",
                ""
            )
        )

        if password == str(LOGIN_PASSWORD):

            session.clear()

            session["authenticated"] = True

            return redirect("/")

        return render_template(
            "login.html",
            error="Invalid password."
        )

    return render_template(
        "login.html"
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# -------------------------------------------------
# HOME
# -------------------------------------------------

@app.route("/")
@login_required
def index():

    return render_template(
        "index.html"
    )


# -------------------------------------------------
# QUEUE / BATCH STREAM
# -------------------------------------------------

@app.post("/api/send-stream")
@login_required
def send_stream():

    data = (
        request.get_json(
            silent=True
        ) or {}
    )

    recipients_input = data.get(
        "recipients",
        []
    )

    if isinstance(
        recipients_input,
        list
    ):

        recipients = parse_recipients(
            " ".join(
                str(x)
                for x in recipients_input
            )
        )

    else:

        recipients = parse_recipients(
            recipients_input
        )

    if not recipients:

        return jsonify(
            error="No recipients found."
        ), 400

    total = len(recipients)

    valid = []
    invalid = []

    for email in recipients:

        if is_valid_email(email):
            valid.append(email)

        else:
            invalid.append(email)

    sender_data = {
        "sender_name": str(
            data.get(
                "sender_name",
                ""
            )
        ),

        "subject": str(
            data.get(
                "subject",
                ""
            )
        ),

        "message": str(
            data.get(
                "message_html",
                ""
            )
        ),
    }

    @stream_with_context
    def generate():

        sent = 0
        failed = len(invalid)
        processed = failed

        # Initial state
        yield make_event(
            "start",
            {
                "total": total,
                "sent": sent,
                "failed": failed,
                "remaining": total - processed,
                "batch": 0,
                "batch_size": 0,
            }
        )

        # Invalid addresses
        for _email in invalid:

            yield make_event(
                "progress",
                {
                    "total": total,
                    "sent": sent,
                    "failed": failed,
                    "remaining": max(
                        0,
                        total - processed
                    ),
                    "batch": 0,
                    "batch_size": 0,
                }
            )

        position = 0
        batch_number = 0

        # -----------------------------------------
        # 8 -> 8 -> 9
        # -----------------------------------------

        while position < len(valid):

            batch_number += 1

            if batch_number <= 2:
                batch_size = 8
            else:
                batch_size = 9

            batch = valid[
                position:
                position + batch_size
            ]

            actual_batch_size = len(batch)

            yield make_event(
                "batch_start",
                {
                    "batch": batch_number,
                    "batch_size": actual_batch_size,
                    "total": total,
                    "sent": sent,
                    "failed": failed,
                    "remaining": max(
                        0,
                        total - processed
                    ),
                }
            )

            # -------------------------------------
            # Process current batch
            # -------------------------------------

            for recipient in batch:

                try:

                    success = send_one(
                        recipient,
                        sender_data
                    )

                    if success:

                        sent += 1

                    else:

                        failed += 1

                except Exception as error:

                    failed += 1

                    print(
                        "SEND ERROR:",
                        recipient,
                        repr(error)
                    )

                processed += 1

                remaining = max(
                    0,
                    total - processed
                )

                yield make_event(
                    "progress",
                    {
                        "total": total,
                        "sent": sent,
                        "failed": failed,
                        "remaining": remaining,
                        "batch": batch_number,
                        "batch_size": actual_batch_size,
                    }
                )

            position += actual_batch_size

            yield make_event(
                "batch_complete",
                {
                    "batch": batch_number,
                    "batch_size": actual_batch_size,
                    "total": total,
                    "sent": sent,
                    "failed": failed,
                    "remaining": max(
                        0,
                        total - processed
                    ),
                }
            )

        # -----------------------------------------
        # FINAL EVENT
        # -----------------------------------------

        yield make_event(
            "complete",
            {
                "total": total,
                "sent": sent,
                "failed": failed,
                "remaining": 0,
                "batches": batch_number,
            }
        )

        time.sleep(0.1)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":
                "no-cache, no-transform",

            "X-Accel-Buffering":
                "no",

            "Connection":
                "keep-alive",
        }
    )


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                "5000"
            )
        )
    )

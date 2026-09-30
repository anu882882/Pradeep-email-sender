import os,re,ssl,smtplib,secrets,time
from flask import Flask,render_template,request,jsonify,session,redirect
from functools import wraps
from email.mime.text import MIMEText

app=Flask(__name__,template_folder="../templates",static_folder="../static")
app.secret_key=os.getenv("SESSION_SECRET","change-this-secret")
LOGIN=os.getenv("APP_LOGIN_PASSWORD","Baby882@#")

ER=re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
COOLDOWN=10

def valid(x):
    return bool(ER.fullmatch(str(x).strip()))

def auth(f):
    @wraps(f)
    def w(*a,**k):
        return f(*a,**k) if session.get("login") else redirect("/login")
    return w

def rec(x):
    return list(dict.fromkeys(
        i.strip().lower()
        for i in re.split(r"[\s,;]+",str(x))
        if i.strip()
    ))

def safe_message(subject,msg):
    text=subject+" "+msg

    if re.search(r"<\s*(script|iframe|object|embed)\b",text,re.I):
        return False,"Unsafe HTML detected."

    if re.search(r"javascript\s*:",text,re.I):
        return False,"Unsafe content detected."

    if len(re.findall(r"https?://",text,re.I))>5:
        return False,"Too many links in message."

    if re.search(r"(.)\1{10,}",text):
        return False,"Repeated characters detected."

    return True,"OK"

@app.route("/login",methods=["GET","POST"])
def login():

    if request.method=="POST":

        if request.form.get("password","")==LOGIN:
            session["login"]=1
            session["last_send"]=0
            return redirect("/")

        return render_template(
            "login.html",
            error="Wrong password."
        )

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
@auth
def home():
    return render_template("index.html")


@app.route("/api/send",methods=["POST"])
@auth
def send():

    now=time.time()

    if now-session.get("last_send",0)<COOLDOWN:
        return jsonify(
            error=f"Please wait {COOLDOWN} seconds before sending again."
        ),429

    d=request.get_json() or {}

    sender=str(d.get("sender_name","")).strip()
    gmail=str(d.get("gmail","")).strip().lower()
    pwd="".join(str(d.get("app_password","")).split())
    sub=str(d.get("subject","")).strip()
    msg=str(d.get("message",""))
    to=rec(d.get("recipients",""))

    if not sender:
        return jsonify(error="Sender name required."),400

    if not valid(gmail):
        return jsonify(error="Valid Gmail address required."),400

    if not pwd:
        return jsonify(error="Gmail App Password required."),400

    if not sub:
        return jsonify(error="Subject required."),400

    if not msg.strip():
        return jsonify(error="Message required."),400

    if not to:
        return jsonify(error="Add recipients first."),400

    if len(to)>25:
        return jsonify(error="Maximum 25 recipients."),400

    bad=[x for x in to if not valid(x)]

    if bad:
        return jsonify(
            error="Invalid recipient email.",
            invalid=bad
        ),400

    ok,reason=safe_message(sub,msg)

    if not ok:
        return jsonify(error=reason),400

    sent=[]
    failed=[]

    try:

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=ssl.create_default_context(),
            timeout=30
        ) as smtp:

            smtp.login(gmail,pwd)

            session["last_send"]=time.time()

            for email in to:

                reference="#REF-"+secrets.token_hex(4).upper()

                try:

                    text=msg.replace(
                        "{name}",
                        email.split("@")[0]
                    )

                    text=text.rstrip()+(
                        f"\n\nReference: {reference}"
                    )

                    mail=MIMEText(
                        text,
                        "plain",
                        "utf-8"
                    )

                    mail["Subject"]=sub
                    mail["From"]=f"{sender} <{gmail}>"
                    mail["To"]=email

                    refused=smtp.sendmail(
                        gmail,
                        [email],
                        mail.as_string()
                    )

                    if refused:
                        failed.append({
                            "email":email,
                            "ref":reference
                        })
                    else:
                        sent.append({
                            "email":email,
                            "ref":reference
                        })

                except Exception as e:

                    failed.append({
                        "email":email,
                        "ref":reference,
                        "error":str(e)
                    })

        return jsonify(
            success=True,
            total=len(to),
            sent=len(sent),
            failed=len(failed),
            sent_emails=sent,
            failed_emails=failed
        )

    except smtplib.SMTPAuthenticationError:

        return jsonify(
            error="Gmail authentication failed."
        ),401

    except Exception as e:

        return jsonify(error=str(e)),500


if __name__=="__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT",5000))
    )

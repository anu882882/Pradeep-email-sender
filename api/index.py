import os,re,ssl,smtplib,json,urllib.request,urllib.parse
from flask import Flask,render_template,request,jsonify,session,redirect
from functools import wraps
from email.mime.text import MIMEText

app=Flask(__name__,template_folder="../templates",static_folder="../static")
app.secret_key=os.getenv("SESSION_SECRET","change-this-secret")
LOGIN=os.getenv("APP_LOGIN_PASSWORD","Baby882@#")
TS_SECRET=os.getenv("TURNSTILE_SECRET_KEY","")
TS_SITE=os.getenv("TURNSTILE_SITE_KEY","")
ER=re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

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

def verify(token):
    if not TS_SECRET or not token:
        return False
    try:
        data=urllib.parse.urlencode({
            "secret":TS_SECRET,
            "response":token
        }).encode()
        req=urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=data,method="POST"
        )
        with urllib.request.urlopen(req,timeout=10) as r:
            return json.loads(r.read()).get("success",False)
    except:
        return False

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form.get("password","")==LOGIN:
            session["login"]=1
            return redirect("/")
        return render_template("login.html",error="Wrong password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@auth
def home():
    return render_template(
        "index.html",
        turnstile_sitekey=TS_SITE
    )

@app.route("/api/send",methods=["POST"])
@auth
def send():
    d=request.get_json() or {}

    sender=str(d.get("sender_name","")).strip()
    gmail=str(d.get("gmail","")).strip().lower()
    pwd="".join(str(d.get("app_password","")).split())
    sub=str(d.get("subject","")).strip()
    msg=str(d.get("message",""))
    to=rec(d.get("recipients",""))
    token=str(d.get("turnstile_token","")).strip()

    if not verify(token):
        return jsonify(
            error="Complete Spam Protection verification first."
        ),403

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

    sent=[]
    failed=[]

    try:
        with smtplib.SMTP_SSL(
            "smtp.gmail.com",465,
            context=ssl.create_default_context(),
            timeout=30
        ) as smtp:

            smtp.login(gmail,pwd)

            for email in to:
                try:
                    text=msg.replace(
                        "{name}",
                        email.split("@")[0]
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
                            "email":email
                        })
                    else:
                        sent.append({
                            "email":email
                        })

                except Exception as e:
                    failed.append({
                        "email":email,
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

import os,ssl,smtplib,re
from functools import wraps
from email.mime.text import MIMEText
from flask import Flask,render_template,request,jsonify,session,redirect,url_for

R=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app=Flask(app_name if False else __name__,template_folder=R+"/templates",static_folder=R+"/static")
app.secret_key=os.getenv("SESSION_SECRET","change-me")
PASS=os.getenv("APP_LOGIN_PASSWORD","")
RE=re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def ok(e): return bool(RE.fullmatch(e.strip()))
def login(f):
    @wraps(f)
    def x(*a,**k):
        if not session.get("login"): return redirect("/login")
        return f(*a,**k)
    return x

@app.route("/login",methods=["GET","POST"])
def signin():
    if request.method=="POST":
        if request.form.get("password")==PASS:
            session["login"]=1
            return redirect("/")
        return render_template("login.html",error="Wrong password")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@login
def home(): return render_template("index.html")

@app.route("/api/protection")
@login
def protection():
    return jsonify(active=True)

@app.route("/api/diagnostics",methods=["POST"])
@login
def diagnostics():
    d=request.get_json() or {}
    g=d.get("gmail","").strip()
    p=d.get("app_password","").strip()

    if not ok(g) or not p:
        return jsonify(error="Enter Gmail and App Password"),400

    try:
        with smtplib.SMTP_SSL(
            "smtp.gmail.com",465,
            context=ssl.create_default_context(),
            timeout=15
        ) as s:
            s.login(g,p)

        return jsonify(
            success=True,
            connection=True,
            tls=True,
            authentication=True,
            domain=g.split("@")[-1],
            message="SMTP authentication successful."
        )
    except smtplib.SMTPAuthenticationError:
        return jsonify(
            success=False,
            connection=True,
            tls=True,
            authentication=False,
            message="Gmail authentication failed."
        )
    except Exception as e:
        return jsonify(
            success=False,
            connection=False,
            tls=False,
            authentication=False,
            message=str(e)
        )

@app.route("/api/send",methods=["POST"])
@login
def send():
    d=request.get_json() or {}
    g=d.get("gmail","").strip()
    p=d.get("app_password","").strip()
    name=d.get("sender_name","").strip()
    sub=d.get("subject","").strip()
    body=d.get("message","")
    rs=list(dict.fromkeys(re.split(r"[\s,;]+",d.get("recipients","").strip().lower())))

    if not all([ok(g),p,name,sub,body]) or not rs:
        return jsonify(error="Complete all fields"),400
    if len(rs)>25:
        return jsonify(error="Maximum 25 recipients"),400

    sent=[];failed=[]

    try:
        with smtplib.SMTP_SSL(
            "smtp.gmail.com",465,
            context=ssl.create_default_context(),
            timeout=30
        ) as s:
            s.login(g,p)

            for r in rs:
                try:
                    m=MIMEText(body.replace("{name}",r.split("@")[0]),"plain","utf-8")
                    m["Subject"]=sub
                    m["From"]=f"{name} <{g}>"
                    m["To"]=r
                    s.sendmail(g,[r],m.as_string())
                    sent.append(r)
                except Exception as e:
                    failed.append({"email":r,"error":str(e)})

        return jsonify(
            success=bool(sent),
            total=len(rs),
            sent=len(sent),
            failed=len(failed),
            remaining=len(rs)-len(sent)-len(failed),
            sent_emails=sent,
            failed_emails=failed
        )
    except smtplib.SMTPAuthenticationError:
        return jsonify(error="Gmail authentication failed"),401
    except Exception as e:
        return jsonify(error=str(e)),500

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.getenv("PORT",5000)))

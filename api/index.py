import os,re,ssl,smtplib,secrets,json,urllib.request,urllib.parse
from functools import wraps
from flask import Flask,render_template,request,jsonify,session,redirect
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html.parser import HTMLParser

app=Flask(__name__,template_folder="../templates",static_folder="../static")
app.secret_key=os.getenv("SESSION_SECRET","change-this-secret")
LOGIN=os.getenv("APP_LOGIN_PASSWORD","Baby882@#")
TURNSTILE_SECRET=os.getenv("TURNSTILE_SECRET_KEY","")

EMAIL=re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def valid_email(x):
    return bool(EMAIL.fullmatch(x.strip()))

def recipients(text):
    items=re.split(r"[,;\s]+",text or "")
    out=[]
    seen=set()
    for x in items:
        x=x.strip().lower()
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out[:25]

def auth(f):
    @wraps(f)
    def w(*a,**k):
        if not session.get("login"):
            return redirect("/login")
        return f(*a,**k)
    return w

def spin(text):
    def repl(m):
        return secrets.choice(m.group(1).split("|"))
    for _ in range(20):
        new=re.sub(r"\{([^{}|]+(?:\|[^{}|]+)+)\}",repl,text)
        if new==text:
            break
        text=new
    return text

class Cleaner(HTMLParser):
    allowed={"div","p","br","strong","b","em","i","u","span",
             "a","ul","ol","li","style"}
    attrs={"a":{"href","target","rel"},"span":{"class"}}
    def __init__(self):
        super().__init__()
        self.out=[]
    def handle_starttag(self,t,a):
        if t not in self.allowed:return
        ok=[]
        for k,v in a:
            if k in self.attrs.get(t,set()):
                if k=="href" and not str(v).lower().startswith(("http://","https://","mailto:")):
                    continue
                ok.append((k,v))
        s="<"+t
        for k,v in ok:
            s+=f' {k}="{str(v).replace(chr(34),"&quot;")}"'
        self.out.append(s+">")
    def handle_endtag(self,t):
        if t in self.allowed:self.out.append("</"+t+">")
    def handle_data(self,d):
        self.out.append(d)
    def html(self):
        return "".join(self.out)

def clean_html(x):
    p=Cleaner()
    p.feed(x or "")
    return p.html()

def html_text(x):
    x=re.sub(r"<style.*?</style>","",x or "",flags=re.I|re.S)
    x=re.sub(r"<br\s*/?>","\n",x,flags=re.I)
    x=re.sub(r"</p>|</div>|</li>","\n",x,flags=re.I)
    x=re.sub(r"<[^>]+>","",x)
    return re.sub(r"\n{3,}","\n\n",x).strip()

def verify_turnstile(token):
    if not TURNSTILE_SECRET:
        return True
    if not token:
        return False

    data=urllib.parse.urlencode({
        "secret":TURNSTILE_SECRET,
        "response":token
    }).encode()

    try:
        req=urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=data,
            method="POST"
        )
        with urllib.request.urlopen(req,timeout=8) as r:
            result=json.loads(r.read().decode())
        return bool(result.get("success"))
    except Exception:
        return False

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        if secrets.compare_digest(
            str(request.form.get("password","")),
            str(LOGIN)
        ):
            session["login"]=True
            return redirect("/")
        return render_template("login.html",error="Invalid password.")
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
        turnstile_site_key=os.getenv("TURNSTILE_SITE_KEY","")
    )

@app.post("/api/send-batch")
@auth
def send_batch():
    d=request.get_json(silent=True) or {}

    if not verify_turnstile(d.get("turnstile_token","")):
        return jsonify(error="Cloudflare verification failed."),403

    gmail=str(d.get("gmail","")).strip()
    password="".join(str(d.get("app_password","")).split())
    subject=spin(str(d.get("subject","")).strip())
    message=clean_html(str(d.get("message_html","")))

    raw=d.get("recipients",[])
    if isinstance(raw,str):
        raw=recipients(raw)

    raw=[str(x).strip().lower() for x in raw]
    raw=list(dict.fromkeys(raw))

    if not gmail or not valid_email(gmail):
        return jsonify(error="Enter a valid Gmail address."),400

    if not password:
        return jsonify(error="Enter your Gmail App Password."),400

    if not subject:
        return jsonify(error="Subject is required."),400

    if not message:
        return jsonify(error="Message is required."),400

    if len(raw)>5:
        return jsonify(error="Maximum 5 recipients per batch."),400

    good=[x for x in raw if valid_email(x)]
    bad=[x for x in raw if not valid_email(x)]

    if not good:
        return jsonify(error="No valid recipients."),400

    sent=[]
    failed=bad[:]

    try:
        ctx=ssl.create_default_context()

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=ctx,
            timeout=30
        ) as smtp:

            smtp.login(gmail,password)

            for email in good:
                try:
                    local=email.split("@")[0]
                    body=message.replace("{name}",local)

                    plain=html_text(body)

                    msg=MIMEMultipart("alternative")
                    msg["From"]=gmail
                    msg["To"]=email
                    msg["Subject"]=spin(subject)

                    msg.attach(MIMEText(plain,"plain","utf-8"))
                    msg.attach(MIMEText(body,"html","utf-8"))

                    smtp.sendmail(gmail,[email],msg.as_string())
                    sent.append(email)

                except Exception:
                    failed.append(email)

    except Exception as e:
        return jsonify(
            error="Gmail SMTP connection/login failed.",
            detail=str(e)
        ),502

    return jsonify(sent=sent,failed=failed)

if __name__=="__main__":
    app.run()

import os,re,ssl,smtplib,secrets,json,urllib.request,urllib.parse
from functools import wraps
from flask import Flask,render_template,request,jsonify,session,redirect
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from html.parser import HTMLParser

app=Flask(__name__,template_folder="../templates",static_folder="../static")
app.secret_key=os.getenv("SESSION_SECRET","change-this-secret")
LOGIN=os.getenv("APP_LOGIN_PASSWORD","Baby882@#")
TURNSTILE=os.getenv("TURNSTILE_SECRET_KEY","")
ER=re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def valid(x):return bool(ER.fullmatch(x.strip()))

def parse(x):
    return list(dict.fromkeys(
        i.strip().lower() for i in re.split(r"[,;\s]+",x or "") if i.strip()
    ))[:25]

def auth(f):
    @wraps(f)
    def w(*a,**k):
        return f(*a,**k) if session.get("login") else redirect("/login")
    return w

def spin(x):
    def r(m):return secrets.choice(m.group(1).split("|"))
    for _ in range(20):
        y=re.sub(r"\{([^{}|]+(?:\|[^{}|]+)+)\}",r,x)
        if y==x:break
        x=y
    return x

class Clean(HTMLParser):
    tags={"div","p","br","strong","b","em","i","u","span","a","ul","ol","li","style"}
    def __init__(self):super().__init__();self.o=[]
    def handle_starttag(self,t,a):
        if t not in self.tags:return
        z="<"+t
        allow={"a":{"href","target","rel"},"span":{"class"}}.get(t,set())
        for k,v in a:
            if k in allow:
                if k=="href" and not str(v).lower().startswith(("http://","https://","mailto:")):continue
                z+=f' {k}="{str(v).replace(chr(34),"&quot;")}"'
        self.o.append(z+">")
    def handle_endtag(self,t):
        if t in self.tags:self.o.append("</"+t+">")
    def handle_data(self,d):self.o.append(d)

def clean(x):
    p=Clean();p.feed(x or "");return "".join(p.o)

def plain(x):
    x=re.sub(r"<style.*?</style>","",x or "",flags=re.I|re.S)
    x=re.sub(r"<br\s*/?>","\n",x,flags=re.I)
    x=re.sub(r"</p>|</div>|</li>","\n",x,flags=re.I)
    return re.sub(r"<[^>]+>","",x).strip()

def verify(token):
    if not TURNSTILE:return True
    if not token:return False
    try:
        d=urllib.parse.urlencode({"secret":TURNSTILE,"response":token}).encode()
        q=urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=d,method="POST"
        )
        with urllib.request.urlopen(q,timeout=8) as r:
            return bool(json.loads(r.read()).get("success"))
    except:return False

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        if secrets.compare_digest(str(request.form.get("password","")),str(LOGIN)):
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
def index():
    return render_template("index.html",turnstile_site_key=os.getenv("TURNSTILE_SITE_KEY",""))

@app.post("/api/send-batch")
@auth
def send():
    d=request.get_json(silent=True) or {}

    if not verify(d.get("turnstile_token","")):
        return jsonify(error="Cloudflare verification failed."),403

    gmail=str(d.get("gmail","")).strip()
    pwd="".join(str(d.get("app_password","")).split())
    sender=str(d.get("sender_name","")).strip()
    subject=str(d.get("subject","")).strip()
    msg=clean(str(d.get("message_html","")))
    batch=d.get("recipients",[])

    if isinstance(batch,str):batch=parse(batch)
    batch=list(dict.fromkeys(str(x).strip().lower() for x in batch))

    if len(batch)>5:return jsonify(error="Maximum 5 recipients per batch."),400
    if not valid(gmail):return jsonify(error="Enter a valid Gmail address."),400
    if not pwd:return jsonify(error="Enter your Gmail App Password."),400
    if not subject:return jsonify(error="Email subject is required."),400
    if not msg:return jsonify(error="Message body is required."),400

    good=[x for x in batch if valid(x)]
    failed=[x for x in batch if not valid(x)]
    sent=[]

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com",465,context=ssl.create_default_context(),timeout=30) as smtp:
            smtp.login(gmail,pwd)

            for email in good:
                try:
                    html=spin(msg.replace("{name}",email.split("@")[0]))
                    m=MIMEMultipart("alternative")
                    m["From"]=formataddr((sender,gmail)) if sender else gmail
                    m["To"]=email
                    m["Subject"]=spin(subject)
                    m.attach(MIMEText(plain(html),"plain","utf-8"))
                    m.attach(MIMEText(html,"html","utf-8"))
                    smtp.sendmail(gmail,[email],m.as_string())
                    sent.append(email)
                except:
                    failed.append(email)

    except Exception as e:
        return jsonify(error="Gmail SMTP connection/login failed.",detail=str(e)),502

    return jsonify(sent=sent,failed=failed)

if __name__=="__main__":app.run()

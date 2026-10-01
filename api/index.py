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
TURNSTILE_SECRET=os.getenv("TURNSTILE_SECRET_KEY","")

EMAIL_RE=re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def valid_email(x):
    return bool(EMAIL_RE.fullmatch(x.strip()))

def parse_recipients(text):
    items=re.split(r"[,;\s]+",text or "")
    out=[];seen=set()

    for x in items:
        x=x.strip().lower()
        if x and x not in seen:
            seen.add(x)
            out.append(x)

    return out[:25]

def auth(f):
    @wraps(f)
    def wrapper(*args,**kwargs):
        if not session.get("login"):
            return redirect("/login")
        return f(*args,**kwargs)
    return wrapper

def spin(text):
    def replace(m):
        return secrets.choice(m.group(1).split("|"))

    for _ in range(20):
        new=re.sub(
            r"\{([^{}|]+(?:\|[^{}|]+)+)\}",
            replace,
            text
        )
        if new==text:
            break
        text=new

    return text

class Cleaner(HTMLParser):
    allowed={
        "div","p","br","strong","b","em","i","u",
        "span","a","ul","ol","li","style"
    }

    def __init__(self):
        super().__init__()
        self.out=[]

    def handle_starttag(self,tag,attrs):
        if tag not in self.allowed:
            return

        allowed_attrs={
            "a":{"href","target","rel"},
            "span":{"class"}
        }

        s="<"+tag

        for key,val in attrs:
            if key in allowed_attrs.get(tag,set()):
                if key=="href" and not str(val).lower().startswith(
                    ("http://","https://","mailto:")
                ):
                    continue

                val=str(val).replace('"',"&quot;")
                s+=f' {key}="{val}"'

        self.out.append(s+">")

    def handle_endtag(self,tag):
        if tag in self.allowed:
            self.out.append("</"+tag+">")

    def handle_data(self,data):
        self.out.append(data)

    def html(self):
        return "".join(self.out)

def clean_html(value):
    parser=Cleaner()
    parser.feed(value or "")
    return parser.html()

def html_to_text(value):
    value=re.sub(
        r"<style.*?</style>",
        "",
        value or "",
        flags=re.I|re.S
    )
    value=re.sub(r"<br\s*/?>","\n",value,flags=re.I)
    value=re.sub(r"</p>|</div>|</li>","\n",value,flags=re.I)
    value=re.sub(r"<[^>]+>","",value)
    return re.sub(r"\n{3,}","\n\n",value).strip()

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

        with urllib.request.urlopen(req,timeout=8) as response:
            result=json.loads(response.read().decode())

        return bool(result.get("success"))

    except Exception:
        return False

@app.route("/login",methods=["GET","POST"])
def login():

    if request.method=="POST":

        password=str(request.form.get("password",""))

        if secrets.compare_digest(password,str(LOGIN)):
            session["login"]=True
            return redirect("/")

        return render_template(
            "login.html",
            error="Invalid password."
        )

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@auth
def index():
    return render_template(
        "index.html",
        turnstile_site_key=os.getenv("TURNSTILE_SITE_KEY","")
    )

@app.post("/api/send-batch")
@auth
def send_batch():

    data=request.get_json(silent=True) or {}

    if not verify_turnstile(data.get("turnstile_token","")):
        return jsonify(
            error="Cloudflare verification failed."
        ),403

    sender_name=str(
        data.get("sender_name","")
    ).strip()

    gmail=str(
        data.get("gmail","")
    ).strip()

    app_password="".join(
        str(data.get("app_password","")).split()
    )

    subject=str(
        data.get("subject","")
    ).strip()

    message=clean_html(
        str(data.get("message_html",""))
    )

    batch=data.get("recipients",[])

    if isinstance(batch,str):
        batch=parse_recipients(batch)

    batch=[
        str(x).strip().lower()
        for x in batch
    ]

    batch=list(dict.fromkeys(batch))

    if len(batch)>5:
        return jsonify(
            error="Maximum 5 recipients per batch."
        ),400

    if not valid_email(gmail):
        return jsonify(
            error="Enter a valid Gmail address."
        ),400

    if not app_password:
        return jsonify(
            error="Enter your Gmail App Password."
        ),400

    if not subject:
        return jsonify(
            error="Email subject is required."
        ),400

    if not message:
        return jsonify(
            error="Message body is required."
        ),400

    good=[x for x in batch if valid_email(x)]
    failed=[x for x in batch if not valid_email(x)]
    sent=[]

    if not good:
        return jsonify(
            sent=[],
            failed=failed
        )

    try:

        context=ssl.create_default_context()

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            context=context,
            timeout=30
        ) as smtp:

            smtp.login(
                gmail,
                app_password
            )

            for recipient in good:

                try:

                    name=recipient.split("@")[0]

                    html=message.replace(
                        "{name}",
                        name
                    )

                    html=spin(html)
                    plain=html_to_text(html)
                    final_subject=spin(subject)

                    msg=MIMEMultipart("alternative")

                    msg["From"]=formataddr(
                        (sender_name,gmail)
                    ) if sender_name else gmail

                    msg["To"]=recipient
                    msg["Subject"]=final_subject

                    msg.attach(
                        MIMEText(
                            plain,
                            "plain",
                            "utf-8"
                        )
                    )

                    msg.attach(
                        MIMEText(
                            html,
                            "html",
                            "utf-8"
                        )
                    )

                    smtp.sendmail(
                        gmail,
                        [recipient],
                        msg.as_string()
                    )

                    sent.append(recipient)

                except Exception:
                    failed.append(recipient)

    except Exception as e:

        return jsonify(
            error="Gmail SMTP connection/login failed.",
            detail=str(e)
        ),502

    return jsonify(
        sent=sent,
        failed=failed
    )

if __name__=="__main__":
    app.run()

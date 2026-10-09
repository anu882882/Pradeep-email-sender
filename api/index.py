
from pathlib import Path
import zipfile

project = Path("secure_mail_console_updated")
files = {
    "requirements.txt": "Flask==3.1.2\n",
    "vercel.json": '''{
  "version": 2,
  "builds": [{"src": "api/index.py", "use": "@vercel/python"}],
  "routes": [
    {"src": "/static/(.*)", "dest": "/static/$1"},
    {"src": "/(.*)", "dest": "api/index.py"}
  ]
}''',
    ".env.example": """LOGIN_PASSWORD=your_strong_password
SESSION_SECRET=your_long_random_secret
TURNSTILE_SITE_KEY=your_turnstile_site_key
TURNSTILE_SECRET_KEY=your_turnstile_secret_key
MAIL_GAP_SECONDS=0
""",
    "api/index.py": '''from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for
from pathlib import Path
import os, secrets

BASE_DIR = Path(__file__).resolve().parent.parent
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"),
            static_folder=str(BASE_DIR / "static"))
handler = app
app.secret_key = os.getenv("SESSION_SECRET", "")
LOGIN_PASSWORD = os.getenv("LOGIN_PASSWORD", "")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if LOGIN_PASSWORD and secrets.compare_digest(password, LOGIN_PASSWORD):
            session["authenticated"] = True
            return redirect(url_for("home"))
        return render_template("login.html", error="Incorrect password.")
    return render_template("login.html", error=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def home():
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    return render_template("index.html",
        turnstile_site_key=os.getenv("TURNSTILE_SITE_KEY", ""))

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "Secure Mail Console"})

if __name__ == "__main__":
    app.run(debug=True)
''',
    "templates/login.html": '''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Mail Console</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}"></head>
<body class="login-page"><main class="login-card">
<div class="logo">🛡️</div><h1>Secure Mail Console</h1>
<p>Sign in to continue</p>
{% if error %}<p class="error">{{ error }}</p>{% endif %}
<form method="post"><label>Password</label>
<input name="password" type="password" required>
<button type="submit">Sign In</button></form>
</main></body></html>
''',
    "templates/index.html": '''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Mail Console</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}"></head>
<body><header><b>🛡 Secure Mail Console</b><a href="/logout">Logout</a></header>
<main><h1>Bulk Email Sender</h1>
<section><h2>Compose Message</h2>
<label>Sender Name<input id="senderName"></label>
<label>Gmail Address<input id="gmail" type="email"></label>
<label>Google App Password<input id="appPassword" type="password"></label>
<label>Subject<input id="subject"></label>
<label>Message Body<textarea id="body" rows="8"></textarea></label>
<p>Spintax enabled: {Hi|Hello}</p>
<label>Recipients — one email per line, maximum 25
<textarea id="recipients" rows="5"></textarea></label>
<button id="send">Send All</button>
</section>
<section><h2>Progress Monitor</h2>
<div class="stats"><p>Total <b id="total">0</b></p>
<p>Sent <b id="sent">0</b></p><p>Failed <b id="failed">0</b></p>
<p>Remaining <b id="remaining">0</b></p></div>
<div class="track"><div id="bar"></div></div>
<p id="progress">0%</p><p id="status">Ready</p></section>
</main>
<div id="popup" class="popup"><div class="popup-card">
<h2>Sending complete</h2><p>PRADEEP ❤️</p><button id="close">Close</button>
</div></div>
<script>
const popup=document.getElementById("popup");
function closePopup(){popup.classList.remove("show")}
document.getElementById("close").onclick=closePopup;
document.addEventListener("click",()=>{if(popup.classList.contains("show"))closePopup()});
document.addEventListener("keydown",e=>{
 if(popup.classList.contains("show")&&(e.code==="Space"||e.key==="Escape")){
 e.preventDefault();closePopup()
 }
});
document.getElementById("send").onclick=()=>{
 document.getElementById("status").textContent=
 "This starter interface needs the email-sending backend connected.";
};
</script></body></html>
''',
    "static/style.css": '''*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:#172033;font:14px Arial,sans-serif}header{display:flex;justify-content:space-between;padding:22px;background:white;border-bottom:1px solid #ddd}a{color:#315fd4;text-decoration:none}main{max-width:850px;margin:28px auto;padding:0 16px}section,.login-card{background:white;border:1px solid #e1e7f0;border-radius:12px;padding:22px;margin:18px 0}h1{font-size:25px}label{display:block;margin:14px 0;font-weight:bold}input,textarea{display:block;width:100%;padding:11px;margin-top:7px;border:1px solid #d6deea;border-radius:7px;font:14px Arial}button{border:0;border-radius:7px;background:#315fd4;color:white;padding:12px 20px;cursor:pointer}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.stats p{padding:12px;background:#f7f9fd;border-radius:7px}.track{height:9px;background:#e9eef6;border-radius:20px;overflow:hidden}.track div{height:100%;width:0;background:#4777e5}.login-page{min-height:100vh;display:grid;place-items:center;padding:20px}.login-card{width:100%;max-width:390px}.login-card .logo{text-align:center;font-size:34px}.login-card h1,.login-card>p{text-align:center}.error{color:#b42318}.popup{display:none;position:fixed;inset:0;background:#17203377;align-items:center;justify-content:center}.popup.show{display:flex}.popup-card{background:white;border-radius:14px;padding:30px;text-align:center}@media(max-width:600px){.stats{grid-template-columns:repeat(2,1fr)}}
'''
}

for name, content in files.items():
    path = project / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

with zipfile.ZipFile("secure_mail_console_updated.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for path in project.rglob("*"):
        if path.is_file():
            z.write(path, path)

print("Project files created in secure_mail_console_updated/")
print("Note: this compact one-block setup is a starter UI; it does not include the complete SMTP sending implementation.")

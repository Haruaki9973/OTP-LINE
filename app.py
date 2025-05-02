from flask import Flask, render_template, request, redirect, url_for, session
import secrets, datetime, requests, os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# === OTP関連 ======================
otp_code = None
otp_expire = None

@app.route('/')
def home():
    return "<a href='/generate'>ワンタイムパスワードを発行</a>"

@app.route('/generate')
def generate():
    global otp_code, otp_expire
    otp_code = str(secrets.randbelow(1000000)).zfill(6)
    otp_expire = datetime.datetime.now() + datetime.timedelta(minutes=5)
    session.clear()
    session['otp'] = otp_code
    return render_template('otp_display.html', otp=otp_code)

@app.route('/otp')
def otp_input():
    return render_template('otp_input.html')

@app.route('/verify', methods=['POST'])
def verify():
    global otp_expire
    user_code = request.form["otp"]
    now = datetime.datetime.now()
    otp_in_session = session.get("otp")

    if otp_in_session is None or now > otp_expire:
        result = "期限切れ、またはコードが存在しません。"
        return render_template("otp_result.html", result=result)

    if user_code == otp_in_session:
        session["otp_verified"] = True
        return redirect("/line_login")
    else:
        result = "認証失敗。コードが違います。"
        return render_template("otp_result.html", result=result)

# === LINEログイン関連 ======================

LINE_CLIENT_ID = "（2007301531）"
LINE_CLIENT_SECRET = "（Uda24f034556b4c72c073abe3fca236dd）"
REDIRECT_URI = "https://otp-10.onrender.com"
@app.route("/line_login")
def line_login():
    if not session.get("otp_verified"):
        return "OTP認証を先に完了してください", 403

    state = secrets.token_urlsafe(16)
    session["line_state"] = state
    line_auth_url = (
        f"https://access.line.me/oauth2/v2.1/authorize?response_type=code"
        f"&client_id={LINE_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&state={state}"
        f"&scope=profile%20openid"
    )
    return redirect(line_auth_url)

@app.route("/line/callback")
def line_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if state != session.get("line_state"):
        return "不正なアクセスです", 403

    token_url = "https://api.line.me/oauth2/v2.1/token"
    headers = { "Content-Type": "application/x-www-form-urlencoded" }
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": LINE_CLIENT_ID,
        "client_secret": LINE_CLIENT_SECRET
    }
    token_res = requests.post(token_url, headers=headers, data=data).json()
    access_token = token_res.get("access_token")

    profile = requests.get(
        "https://api.line.me/v2/profile",
        headers={"Authorization": f"Bearer {access_token}"}
    ).json()

    session["line_verified"] = True
    session["line_name"] = profile.get("displayName")
    return redirect("/goto_secret")

@app.route("/goto_secret")
def goto_secret():
    if session.get("otp_verified") and session.get("line_verified"):
        return render_template("secret_redirect.html", name=session.get("line_name"))
    return "認証されていません", 403

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

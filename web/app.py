from flask import Flask, render_template, \
    request, redirect, url_for, session, g
from dataclasses import dataclass
import sqlite3
from function.main import sign

app = Flask(__name__)
app.config['SECRET_KEY'] = 'FANZHENYE'


@dataclass
class User:
    id: int
    username: str
    password: str


users = []

conn = sqlite3.connect('userInfo.db')
users_fromdb = conn.execute("SELECT ID, Username, password from user")
for user in users_fromdb:
    users.append(User(user[0], user[1], user[2]))
conn.close()


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        user = [u for u in users if u.id == session['user_id']][0]
        g.user = user
    # print(g.user, "g.user")


@app.route('/')
def hello():
    return redirect(url_for('login'))


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        # 登录操作
        session.pop('user_id', None)
        user_id = request.form.get("user_id", None)
        password = request.form.get("password", None)
        user = [u for u in users if u.id == int(user_id)]
        if len(user) > 0:
            user = user[0]
        if user and user.password == password:
            session['user_id'] = user.id
            return redirect(url_for('profile'))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for('login'))


@app.route("/profile")
def profile():
    if not g.user:
        return render_template("login.html")
    conn = sqlite3.connect('userInfo.db')
    users_fromdb = conn.execute("SELECT ID, Username, password from user where ID={}".format(g.user.id))
    logs = conn.execute("SELECT ID, Username,log_time,content from logs where ID={}".format(g.user.id))
    content = [u for u in users_fromdb]
    content2 = [u for u in logs]
    conn.close()
    return render_template("profile.html", content=content, logs=content2)


@app.route("/gosign")
def gosign():
    sign1 = sign("202221493", "fanzhenye@666","aidpaike")
    sign1.doallJob()
    return render_template("profile.html",success="yes")


@app.errorhandler(404)  # 传入错误码作为参数状态
def error_date(error):  # 接受错误作为参数
    return render_template("404.html"), 404  # 返回对应的http状态码，和返回404错误的html文件


if __name__ == '__main__':
    app.run(debug=True)

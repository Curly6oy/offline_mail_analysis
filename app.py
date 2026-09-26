from flask import Flask, render_template, request, redirect, url_for, session
import logging
import os
from analyzer.email_analyzer import analyze_eml

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
logging.basicConfig(filename="app.log", level=logging.INFO)

USERS = {"user1": os.environ.get("OFFLINE_MAIL_PASSWORD", "change-me")}

@app.route("/")
def index():
    return redirect(url_for("check" if "username" in session else "login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username in USERS and USERS[username] == password:
            session.clear()
            session["username"] = username
            return redirect(url_for("check"))
        return render_template("login.html", error="Неверные учётные данные"), 401
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/check", methods=["GET", "POST"])
def check():
    if "username" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        uploaded = request.files.get("email_file")
        if not uploaded or not uploaded.filename:
            return render_template("upload.html", error="Выберите .eml файл"), 400
        if not uploaded.filename.lower().endswith(".eml"):
            return render_template("upload.html", error="Поддерживается только .eml"), 400
        raw = uploaded.read()
        try:
            result = analyze_eml(raw, uploaded.filename)
        except ValueError as exc:
            return render_template("upload.html", error=str(exc)), 400
        logging.info("Local email analysis completed: risk=%s", result["risk"]["level"])
        return render_template("result.html", result=result)
    return render_template("upload.html")

@app.route("/vulnerabilities")
def vulnerabilities():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("vulnerabilities.html")

if __name__ == "__main__":
    app.run(debug=False)

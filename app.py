import logging
import os
import secrets
from functools import wraps

from flask import Flask, abort, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from analyzer.email_analyzer import analyze_eml

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY must be set")

app.config.update(
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_COOKIE_SECURE", "0") == "1",
)

PASSWORD_HASH = os.environ.get("OFFLINE_MAIL_PASSWORD_HASH")
if not PASSWORD_HASH:
    raise RuntimeError("OFFLINE_MAIL_PASSWORD_HASH must be set")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


def require_csrf():
    token = request.form.get("csrf_token", "")
    if not token or not secrets.compare_digest(token, session.get("csrf_token", "")):
        abort(400, description="Invalid CSRF token")


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.route("/")
def index():
    return redirect(url_for("check" if "username" in session else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        require_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == os.environ.get("OFFLINE_MAIL_USERNAME", "user1") and check_password_hash(PASSWORD_HASH, password):
            session.clear()
            session["username"] = username
            session["csrf_token"] = secrets.token_urlsafe(32)
            logging.info("User logged in")
            return redirect(url_for("check"))
        logging.warning("Failed login attempt")
        return render_template("login.html", error="Неверные учётные данные"), 401
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    require_csrf()
    session.clear()
    return redirect(url_for("login"))


@app.route("/healthz")
def healthz():
    return {"status": "ok"}


@app.route("/check", methods=["GET", "POST"])
@login_required
def check():
    if request.method == "POST":
        require_csrf()
        uploaded = request.files.get("email_file")
        if not uploaded or not uploaded.filename:
            return render_template("upload.html", error="Выберите .eml файл"), 400
        if not uploaded.filename.lower().endswith(".eml"):
            return render_template("upload.html", error="Поддерживается только .eml"), 400
        raw = uploaded.read()
        if not raw:
            return render_template("upload.html", error="Файл пустой"), 400
        try:
            result = analyze_eml(raw)
        except ValueError as exc:
            return render_template("upload.html", error=str(exc)), 400
        logging.info("Local email analysis completed: risk=%s", result["risk"]["level"])
        return render_template("result.html", result=result)
    return render_template("upload.html")


@app.route("/vulnerabilities")
@login_required
def vulnerabilities():
    return render_template("vulnerabilities.html")


@app.errorhandler(413)
def too_large(_error):
    return render_template("upload.html", error="Файл превышает максимальный размер 10 МБ"), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)

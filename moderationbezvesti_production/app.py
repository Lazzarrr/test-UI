import os
import secrets
import string
from datetime import date, datetime, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-this-key")
database_url = os.environ.get("DATABASE_URL", "sqlite:///moderation.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"
app.config["WTF_CSRF_TIME_LIMIT"] = 3600

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

ROLES = {"Модератор": 1, "Старший модератор": 2, "Глава модерации": 3}

class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(40), nullable=False, default="Модератор")
    joined = db.Column(db.Date, nullable=False, default=date.today)
    warnings = db.Column(db.Integer, nullable=False, default=0)
    preds = db.Column(db.Integer, nullable=False, default=0)
    must_change_password = db.Column(db.Boolean, nullable=False, default=True)
    active = db.Column(db.Boolean, nullable=False, default=True)

    @property
    def level(self):
        return ROLES.get(self.role, 0)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(120), nullable=False)
    punishment = db.Column(db.String(60), nullable=False)
    report_date = db.Column(db.Date, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("member.id"), nullable=False)
    author = db.relationship("Member", backref="reports")

class Setting(db.Model):
    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.Text, nullable=False, default="")

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("member.id"), nullable=False)
    actor = db.relationship("Member")
    action = db.Column(db.String(120), nullable=False)
    target = db.Column(db.String(160), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

@app.context_processor
def inject_helpers():
    return {"level": lambda user: user.level if user else 0}

def current_user():
    uid = session.get("member_id")
    return db.session.get(Member, uid) if uid else None

@app.context_processor
def inject_user():
    return {"user": current_user(), "new_credentials": session.pop("new_credentials", None)}

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or not user.active:
            session.clear()
            return redirect(url_for("login"))
        if user.must_change_password and request.endpoint != "change_password":
            return redirect(url_for("change_password"))
        return fn(*args, **kwargs)
    return wrapped

def role_required(min_level):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user().level < min_level:
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator

def log_action(action, target=""):
    db.session.add(AuditLog(actor_id=current_user().id, action=action, target=target))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("8 per minute")
def login():
    if current_user():
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        member = Member.query.filter_by(username=username, active=True).first()
        if member and check_password_hash(member.password_hash, password):
            session.clear()
            session["member_id"] = member.id
            return redirect(url_for("change_password" if member.must_change_password else "home"))
        flash("Неверный логин или пароль.")
    return render_template("login.html")

@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    member = current_user()
    if request.method == "POST":
        password = request.form.get("password", "")
        if len(password) < 14:
            flash("Пароль должен содержать не менее 14 символов.")
        else:
            member.password_hash = generate_password_hash(password)
            member.must_change_password = False
            db.session.commit()
            flash("Пароль изменён.")
            return redirect(url_for("home"))
    return render_template("change_password.html")

@app.route("/")
@login_required
def home():
    return render_template("home.html",
        member_count=Member.query.filter_by(active=True).count(),
        report_count=Report.query.count())

@app.route("/team")
@login_required
def team():
    members = Member.query.filter_by(active=True).order_by(Member.joined.asc()).all()
    return render_template("team.html", members=members)

def generate_credentials():
    alphabet = string.ascii_lowercase + string.digits
    while True:
        username = "mod_" + "".join(secrets.choice(alphabet) for _ in range(7))
        if not Member.query.filter_by(username=username).first():
            break
    password = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%") for _ in range(20))
    return username, password

@app.post("/members/create")
@role_required(2)
def create_member():
    display_name = request.form.get("display_name", "").strip()
    mode = request.form.get("mode", "manual")
    if not display_name:
        flash("Укажите имя или никнейм.")
        return redirect(url_for("team"))
    if mode == "auto":
        username, password = generate_credentials()
    else:
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or len(password) < 14:
            flash("Укажите логин и пароль не короче 14 символов.")
            return redirect(url_for("team"))
    if Member.query.filter_by(username=username).first():
        flash("Такой логин уже существует.")
        return redirect(url_for("team"))
    member = Member(username=username, password_hash=generate_password_hash(password),
                    display_name=display_name, role="Модератор", joined=date.today(),
                    must_change_password=True)
    db.session.add(member)
    log_action("Создан аккаунт", username)
    db.session.commit()
    session["new_credentials"] = {"username": username, "password": password}
    flash("Аккаунт создан. Передайте временные данные участнику безопасным способом.")
    return redirect(url_for("team"))

@app.post("/members/<int:member_id>/update")
@role_required(3)
def update_member(member_id):
    member = db.get_or_404(Member, member_id)
    role = request.form.get("role", member.role)
    if role not in ROLES:
        abort(400)
    try:
        joined = date.fromisoformat(request.form.get("joined", member.joined.isoformat()))
        warnings = max(0, int(request.form.get("warnings", member.warnings)))
        preds = max(0, int(request.form.get("preds", member.preds)))
    except (ValueError, TypeError):
        flash("Проверьте дату и числовые поля.")
        return redirect(url_for("team"))
    if member.id == current_user().id and role != "Глава модерации":
        flash("Нельзя понизить собственную роль.")
        return redirect(url_for("team"))
    member.role, member.joined = role, joined
    member.warnings, member.preds = warnings, preds
    log_action("Изменены данные участника", member.username)
    db.session.commit()
    flash("Изменения сохранены.")
    return redirect(url_for("team"))

@app.post("/members/<int:member_id>/reset")
@role_required(3)
def reset_password(member_id):
    member = db.get_or_404(Member, member_id)
    password = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%") for _ in range(20))
    member.password_hash = generate_password_hash(password)
    member.must_change_password = True
    log_action("Сброшен пароль", member.username)
    db.session.commit()
    session["new_credentials"] = {"username": member.username, "password": password}
    flash("Временный пароль создан.")
    return redirect(url_for("team"))

@app.route("/rules", methods=["GET", "POST"])
@login_required
def rules():
    setting = db.session.get(Setting, "rules")
    if not setting:
        setting = Setting(key="rules", value="Устав модерации пока не заполнен.")
        db.session.add(setting)
        db.session.commit()
    if request.method == "POST":
        if current_user().level < 2:
            abort(403)
        setting.value = request.form.get("rules", "")
        log_action("Изменён устав", "Устав модерации")
        db.session.commit()
        flash("Устав сохранён.")
        return redirect(url_for("rules"))
    return render_template("rules.html", rules=setting.value)

@app.route("/reports", methods=["GET", "POST"])
@login_required
def reports():
    if request.method == "POST":
        try:
            report_date = date.fromisoformat(request.form.get("report_date", ""))
        except ValueError:
            flash("Укажите корректную дату.")
            return redirect(url_for("reports"))
        target = request.form.get("target", "").strip()
        reason = request.form.get("reason", "").strip()
        punishment = request.form.get("punishment", "").strip()
        if not target or not reason or not punishment:
            flash("Заполните все поля отчёта.")
            return redirect(url_for("reports"))
        db.session.add(Report(target=target, punishment=punishment,
                              report_date=report_date, reason=reason,
                              author_id=current_user().id))
        log_action("Создан отчёт", target)
        db.session.commit()
        flash("Отчёт отправлен.")
        return redirect(url_for("reports"))
    rows = Report.query.order_by(Report.report_date.desc(), Report.id.desc()).all()
    return render_template("reports.html", rows=rows)

@app.route("/management")
@role_required(2)
def management():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
    return render_template("management.html", logs=logs)

@app.errorhandler(403)
def forbidden(_error):
    return render_template("message.html", message="У вас недостаточно прав для просмотра этой страницы."), 403

@app.errorhandler(404)
def not_found(_error):
    return render_template("message.html", message="Страница не найдена."), 404

def bootstrap():
    db.create_all()
    admin_name = os.environ.get("BOOTSTRAP_ADMIN", "").strip()
    admin_password = os.environ.get("BOOTSTRAP_PASSWORD", "")
    if admin_name and admin_password and not Member.query.filter_by(role="Глава модерации").first():
        admin = Member(username=admin_name, password_hash=generate_password_hash(admin_password),
                       display_name="Глава модерации", role="Глава модерации",
                       joined=date.today(), must_change_password=True)
        db.session.add(admin)
        db.session.commit()

with app.app_context():
    bootstrap()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

from flask import Flask, redirect, url_for, render_template, request, session, flash, jsonify
from datetime import timedelta, datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import uuid
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///default.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(minutes=5)

db = SQLAlchemy(app)

class users(db.Model):
    ''' Таблица пользователей '''
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    password = db.Column(db.String(200))
    role = db.Column(db.String(15), default="user")

    def __init__(self, name, email, password, role):
        self.name = name
        self.email = email
        self.password = generate_password_hash(password)
        self.role = role

    def check_password(self, password):
        ''' Проверка пароля '''
        return check_password_hash(self.password, password)


class used_tokens(db.Model):
    ''' Таблица использованных токенов (защита от Replay Attack) '''
    _id = db.Column("id", db.Integer, primary_key=True)
    jti = db.Column(db.String(100), unique=True)


with app.app_context():
    ''' Инициализация базы данных '''
    db.create_all()

    admin_name = os.getenv("ADMIN")
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")

    admin_user = users.query.filter_by(name=admin_name).first()
    if not admin_user:
        admin_user = users(name=admin_name, email=admin_email, password=admin_password, role="admin")
        db.session.add(admin_user)
        db.session.commit()


def create_token(username, role, exp_minutes, is_refresh=False):
    ''' Создаём токен для пользователя '''
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=exp_minutes),
        "jti": str(uuid.uuid4()),  # Уникальный идентификатор токена
        "type": "refresh" if is_refresh else "access"
    }
    return jwt.encode(payload, app.secret_key, algorithm="HS256")


@app.route("/")
def home():
    ''' Домашняя страница '''
    return render_template("index.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    """Эндпоинт для авторизации"""
    if request.method == "POST":
        user = request.form["nm"]
        password = request.form["password"]
        found_user = users.query.filter_by(name=user).first()

        if found_user and found_user.check_password(password):
            access_token = create_token(user, found_user.role, 5)
            refresh_token = create_token(user, found_user.role, 1440, is_refresh=True)
            return jsonify({"access_token": access_token, "refresh_token": refresh_token})
        else:
            flash("Invalid username or password")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/protected", methods=["GET"])
def protected():
    """Защищённый ресурс. Доступ имеет только админ"""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return render_template("protected.html")

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])

        # Проверка на повторное использование токена
        jti = payload["jti"]
        if used_tokens.query.filter_by(jti=jti).first():
            return jsonify({"error": "Token already used"}), 401

        # Пометка токена как использованного
        new_token = used_tokens(jti=jti)
        db.session.add(new_token)
        db.session.commit()

        if payload.get("role") == "admin":
            flag = "practice{you_are_the_real_admin}"
            return render_template("view.html", values=users.query.all(), flag=flag)
        else:
            return jsonify({"message": f"Hello, {payload['sub']}!"})

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


@app.route("/refresh", methods=["GET", "POST"])
def refresh():

    ''' Эндпоинт для обновления токена '''

    if request.method == "GET":
        return render_template("refresh.html")

    data = request.json
    refresh_token = data.get("refresh_token")

    try:
        payload = jwt.decode(refresh_token, app.secret_key, algorithms=["HS256"])
        if payload["type"] != "refresh":
            return jsonify({"error": "Invalid token type"}), 401

        user_role = payload.get("role", "user")

        # Генерация нового access токена
        new_access_token = create_token(payload["sub"], user_role, 5)
        return jsonify({"access_token": new_access_token})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


@app.route("/register", methods=["POST", "GET"])
def register():
    ''' Эндпоинт для регистрации пользователя '''
    if request.method == "POST":
        username = request.form["nm"]
        email = request.form["email"]
        password = request.form["password"]
        found_user = users.query.filter_by(name=username).first()

        if found_user:
            flash("User already exists!")
            return redirect(url_for("register"))

        new_user = users(name=username, email=email, password=password, role="user")
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful!")
        return redirect(url_for("login"))
    return render_template("register.html")

if __name__ == "__main__":
    app.run(debug=True)
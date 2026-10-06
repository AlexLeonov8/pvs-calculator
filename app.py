import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# --- НАСТРОЙКИ БЕЗОПАСНОСТИ ---
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# --- НАСТРОЙКА ВСТРОЕННОЙ БАЗЫ ДАННЫХ SQLite ---
# База данных сама создастся в папке вашего проекта в виде файла "pvs_local.db"
# Для этого НЕ нужны права администратора компьютера!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pvs_local.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# --- МОДЕЛЬ ДАННЫХ (ТАБЛИЦА В БД) ---
class User(db.Model):
    __tablename__ = 'pvs_users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)


# --- МАРШРУТЫ ---

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        accept_terms = request.form.get('accept_terms')

        if not accept_terms:
            flash('Необходимо согласиться с обработкой персональных данных!', 'danger')
            return redirect(url_for('register'))

        # Проверка существования пользователя в базе данных
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Этот Email уже зарегистрирован.', 'danger')
            return redirect(url_for('register'))

        # Хеширование пароля по стандартам безопасности (Bcrypt)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Сохранение нового пользователя в локальный файл БД
        new_user = User(email=email, password_hash=hashed_password, name=name)
        db.session.add(new_user)
        db.session.commit()

        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Поиск пользователя в локальной БД
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session['user_email'] = user.email
            session['user_name'] = user.name
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный email или пароль.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из профиля.', 'info')
    return redirect(url_for('index'))


if __name__ == '__main__':
    # Автоматическое создание локального файла БД при старте, если его нет
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='127.0.0.1', port=5000)

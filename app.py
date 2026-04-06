import hashlib
import json
import math
import os
import random
import string
from datetime import datetime
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "users.json")
REGISTRATION_LOG_FILE = os.path.join(BASE_DIR, "registration_log.json")
OPERATION_LOG_FILE = os.path.join(BASE_DIR, "operation_log.json")
MAX_LOGIN_ATTEMPTS = 3
ADMIN_USERNAME = "ADMIN"
AUTH_PERIOD_SECONDS = 120
QUESTIONS_TOTAL = 15
QUESTIONS_PER_ITERATION = 4
TOTAL_USERS_TARGET = 12

app = Flask(__name__)
app.secret_key = "change-this-secret-key"


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash


def validate_variant_28_password(password: str) -> bool:
    if len(password) < 3:
        return False
    if len(password) % 3 != 0:
        return False

    punct = set(string.punctuation)
    for idx, char in enumerate(password):
        mod = idx % 3
        if mod == 0 and not char.isalpha():
            return False
        if mod == 1 and char not in punct:
            return False
        if mod == 2 and not char.isdigit():
            return False
    return True


def password_to_a(password: str) -> float:
    if not password:
        return 1.0
    return (sum(ord(ch) for ch in password) / len(password)) / 10.0


def calc_mapping_value(a_value: float, x_value: float) -> float:
    return a_value * math.sin(1.0 / x_value)


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def build_security_questions() -> list[dict]:
    return [
        {"id": "q1", "question": "Ваше місто народження?", "answer": "lviv"},
        {"id": "q2", "question": "Улюблений колір?", "answer": "blue"},
        {"id": "q3", "question": "Ім'я першого вчителя?", "answer": "olena"},
        {"id": "q4", "question": "Улюблена пора року?", "answer": "spring"},
        {"id": "q5", "question": "Назва першої школи?", "answer": "school1"},
        {"id": "q6", "question": "Улюблений предмет у школі?", "answer": "math"},
        {"id": "q7", "question": "Улюблена книга?", "answer": "kobzar"},
        {"id": "q8", "question": "Улюблена страва?", "answer": "borsch"},
        {"id": "q9", "question": "Кличка домашньої тварини?", "answer": "barsik"},
        {"id": "q10", "question": "Улюблений музичний жанр?", "answer": "rock"},
        {"id": "q11", "question": "Улюблений фільм?", "answer": "matrix"},
        {"id": "q12", "question": "Хобі?", "answer": "reading"},
        {"id": "q13", "question": "Улюблений вид спорту?", "answer": "football"},
        {"id": "q14", "question": "Улюблений напій?", "answer": "tea"},
        {"id": "q15", "question": "Улюблена тварина?", "answer": "cat"},
    ]


SECURITY_QUESTIONS = build_security_questions()


def ensure_data_file() -> None:
    if not os.path.exists(DATA_FILE):
        users = {
            ADMIN_USERNAME: {
                "password_hash": "",
                "blocked": False,
                "password_restrictions_enabled": True,
                "access_level": 3,
                "crypto_a": 1.0,
                "security_answers": {item["id"]: item["answer"] for item in SECURITY_QUESTIONS},
            }
        }
        for idx in range(1, TOTAL_USERS_TARGET):
            users[f"user{idx}"] = {
                "password_hash": "",
                "blocked": False,
                "password_restrictions_enabled": True,
                "access_level": 2 if idx <= 4 else 1,
                "crypto_a": 1.0,
                "security_answers": {item["id"]: item["answer"] for item in SECURITY_QUESTIONS},
            }
        data = {"users": users}
        with open(DATA_FILE, "w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=2)

    if not os.path.exists(REGISTRATION_LOG_FILE):
        with open(REGISTRATION_LOG_FILE, "w", encoding="utf-8") as file:
            json.dump([], file, ensure_ascii=False, indent=2)

    if not os.path.exists(OPERATION_LOG_FILE):
        with open(OPERATION_LOG_FILE, "w", encoding="utf-8") as file:
            json.dump([], file, ensure_ascii=False, indent=2)

    migrate_data()


def load_data() -> dict:
    ensure_data_file()
    with open(DATA_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def save_data(data: dict) -> None:
    with open(DATA_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)


def get_user_record(username: str):
    data = load_data()
    return data["users"].get(username), data


def migrate_data() -> None:
    data = load_data_raw()
    changed = False
    for username, user in data.get("users", {}).items():
        if "access_level" not in user:
            user["access_level"] = 3 if username == ADMIN_USERNAME else 1
            changed = True
        if "crypto_a" not in user:
            user["crypto_a"] = 1.0
            changed = True
        if "security_answers" not in user:
            user["security_answers"] = {item["id"]: item["answer"] for item in SECURITY_QUESTIONS}
            changed = True
    while len(data.get("users", {})) < TOTAL_USERS_TARGET:
        idx = len(data["users"])
        new_username = f"user{idx}"
        if new_username in data["users"]:
            idx += 1
            new_username = f"user{idx}"
        data["users"][new_username] = {
            "password_hash": "",
            "blocked": False,
            "password_restrictions_enabled": True,
            "access_level": 1,
            "crypto_a": 1.0,
            "security_answers": {item["id"]: item["answer"] for item in SECURITY_QUESTIONS},
        }
        changed = True
    if changed:
        save_data(data)


def load_data_raw() -> dict:
    with open(DATA_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def append_json_log(path: str, item: dict) -> None:
    with open(path, "r", encoding="utf-8") as file:
        payload = json.load(file)
    payload.append(item)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(payload, file, ensure_ascii=False, indent=2)


def log_registration_event(actor: str, action: str, target: str, status: str, details: str = "") -> None:
    append_json_log(
        REGISTRATION_LOG_FILE,
        {
            "timestamp": now_iso(),
            "actor": actor,
            "action": action,
            "target": target,
            "status": status,
            "details": details,
        },
    )


def log_operation_event(user: str, action: str, status: str, details: str = "") -> None:
    append_json_log(
        OPERATION_LOG_FILE,
        {
            "timestamp": now_iso(),
            "user": user,
            "action": action,
            "status": status,
            "details": details,
        },
    )


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if session.get("username") != ADMIN_USERNAME:
            flash("Функція доступна тільки адміністратору.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped_view


def level_required(min_level: int):
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            user, _ = get_user_record(session.get("username", ""))
            if user is None:
                session.clear()
                return redirect(url_for("login"))
            if user["access_level"] < min_level:
                flash("Недостатній рівень доступу для виконання функції.", "error")
                log_operation_event(session["username"], f"ACCESS_DENIED_L{min_level}", "DENIED")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)

        return wrapped_view

    return decorator


@app.before_request
def periodic_auth_guard():
    if request.endpoint in {"login", "terminated", "static", "reauthenticate", "about", "logout"}:
        return
    if "username" not in session:
        return
    last_auth = session.get("last_auth_at")
    if not last_auth:
        session["last_auth_at"] = datetime.now().timestamp()
        return
    if datetime.now().timestamp() - float(last_auth) > AUTH_PERIOD_SECONDS:
        return redirect(url_for("reauthenticate"))


@app.route("/", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("dashboard"))

    session.setdefault("failed_attempts", 0)

    if request.method == "POST":
        if "exit" in request.form:
            return redirect(url_for("terminated"))

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user, data = get_user_record(username)
        if user is None:
            flash("Користувача не знайдено. Спробуйте ще раз або завершіть роботу.", "error")
            return render_template("login.html")

        if user["blocked"]:
            flash("Обліковий запис заблоковано адміністратором.", "error")
            return render_template("login.html")

        stored_hash = user["password_hash"]
        x_value = random.uniform(0.25, 2.0)
        expected_y = calc_mapping_value(float(user["crypto_a"]), x_value)
        user_a = password_to_a(password)
        provided_y = calc_mapping_value(user_a, x_value)
        if stored_hash == "":
            if password != "":
                session["failed_attempts"] += 1
                if session["failed_attempts"] >= MAX_LOGIN_ATTEMPTS:
                    return redirect(url_for("terminated"))
                flash("Невірний пароль. Для першого входу пароль має бути порожнім.", "error")
                return render_template("login.html")
        else:
            if not verify_password(password, stored_hash):
                session["failed_attempts"] += 1
                if session["failed_attempts"] >= MAX_LOGIN_ATTEMPTS:
                    return redirect(url_for("terminated"))
                flash(
                    f"Невірний пароль. Спроба {session['failed_attempts']} із {MAX_LOGIN_ATTEMPTS}.",
                    "error",
                )
                log_registration_event(username, "LOGIN", username, "FAILED", "wrong_password")
                return render_template("login.html")

            if abs(provided_y - expected_y) > 1e-9:
                session["failed_attempts"] += 1
                flash("Перевірка відображення пароля не пройдена.", "error")
                log_registration_event(username, "LOGIN", username, "FAILED", "mapping_check_failed")
                return render_template("login.html")

        session["failed_attempts"] = 0
        session["username"] = username
        session["force_password_change"] = stored_hash == ""
        session["restrictions_enabled"] = user["password_restrictions_enabled"]
        session["last_auth_at"] = datetime.now().timestamp()
        log_registration_event(username, "LOGIN", username, "SUCCESS", "user_logged_in")
        log_operation_event(username, "LOGIN", "SUCCESS")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/terminated")
def terminated():
    session.clear()
    return render_template("terminated.html")


@app.route("/dashboard")
@login_required
def dashboard():
    username = session["username"]
    user, _ = get_user_record(username)
    if user is None:
        session.clear()
        flash("Користувача видалено. Увійдіть повторно.", "error")
        return redirect(url_for("login"))

    if session.get("force_password_change"):
        return redirect(url_for("change_password", first=1))

    return render_template(
        "dashboard.html",
        username=username,
        is_admin=username == ADMIN_USERNAME,
        access_level=user["access_level"],
    )


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    username = session["username"]
    first_login = request.args.get("first", "0") == "1" or session.get("force_password_change", False)
    user, data = get_user_record(username)
    if user is None:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        if "cancel" in request.form:
            if first_login:
                return redirect(url_for("terminated"))
            flash("Зміну пароля скасовано.", "info")
            return redirect(url_for("dashboard"))

        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if user["password_hash"] != "":
            if not verify_password(old_password, user["password_hash"]):
                flash("Старий пароль введено неправильно.", "error")
                return render_template("change_password.html", first_login=first_login)

        if new_password != confirm_password:
            flash("Підтвердження не збігається з новим паролем.", "error")
            return render_template("change_password.html", first_login=first_login)

        if user["password_restrictions_enabled"] and not validate_variant_28_password(new_password):
            flash(
                "Пароль не відповідає варіанту №28: має чергуватися "
                "літера -> знак пунктуації -> цифра.",
                "error",
            )
            return render_template("change_password.html", first_login=first_login)

        data["users"][username]["password_hash"] = hash_password(new_password)
        data["users"][username]["crypto_a"] = password_to_a(new_password)
        save_data(data)
        session["force_password_change"] = False
        log_operation_event(username, "CHANGE_PASSWORD", "SUCCESS")
        flash("Пароль успішно змінено.", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html", first_login=first_login)


@app.route("/admin/users")
@login_required
@admin_required
def users_list():
    data = load_data()
    return render_template("users_list.html", users=data["users"])


@app.route("/admin/add_user", methods=["POST"])
@login_required
@admin_required
def add_user():
    username = request.form.get("new_username", "").strip()
    if not username:
        flash("Ім'я нового користувача не може бути порожнім.", "error")
        return redirect(url_for("users_list"))
    if username == ADMIN_USERNAME:
        flash("Ім'я ADMIN вже зарезервоване.", "error")
        return redirect(url_for("users_list"))

    data = load_data()
    if username in data["users"]:
        flash("Користувач із таким ім'ям вже існує.", "error")
        return redirect(url_for("users_list"))

    data["users"][username] = {
        "password_hash": "",
        "blocked": False,
        "password_restrictions_enabled": True,
        "access_level": 1,
        "crypto_a": 1.0,
        "security_answers": {item["id"]: item["answer"] for item in SECURITY_QUESTIONS},
    }
    save_data(data)
    log_registration_event(session["username"], "CREATE_USER", username, "SUCCESS")
    flash("Користувача додано з порожнім паролем.", "success")
    return redirect(url_for("users_list"))


@app.route("/admin/toggle_block/<username>", methods=["POST"])
@login_required
@admin_required
def toggle_block(username: str):
    data = load_data()
    user = data["users"].get(username)
    if user is None:
        flash("Користувача не знайдено.", "error")
        return redirect(url_for("users_list"))
    if username == ADMIN_USERNAME:
        flash("Обліковий запис ADMIN не можна блокувати.", "error")
        return redirect(url_for("users_list"))

    user["blocked"] = not user["blocked"]
    save_data(data)
    log_registration_event(session["username"], "TOGGLE_BLOCK", username, "SUCCESS", str(user["blocked"]))
    flash("Статус блокування оновлено.", "success")
    return redirect(url_for("users_list"))


@app.route("/admin/toggle_restrictions/<username>", methods=["POST"])
@login_required
@admin_required
def toggle_restrictions(username: str):
    data = load_data()
    user = data["users"].get(username)
    if user is None:
        flash("Користувача не знайдено.", "error")
        return redirect(url_for("users_list"))

    user["password_restrictions_enabled"] = not user["password_restrictions_enabled"]
    save_data(data)
    log_registration_event(
        session["username"],
        "TOGGLE_PASSWORD_RESTRICTIONS",
        username,
        "SUCCESS",
        str(user["password_restrictions_enabled"]),
    )
    flash("Параметр обмежень пароля оновлено.", "success")
    return redirect(url_for("users_list"))


@app.route("/admin/set_level/<username>", methods=["POST"])
@login_required
@admin_required
def set_level(username: str):
    level = int(request.form.get("access_level", "1"))
    if level < 1 or level > 3:
        flash("Рівень доступу має бути в межах 1..3.", "error")
        return redirect(url_for("users_list"))
    data = load_data()
    user = data["users"].get(username)
    if user is None:
        flash("Користувача не знайдено.", "error")
        return redirect(url_for("users_list"))
    if username == ADMIN_USERNAME:
        flash("Рівень ADMIN не змінюється.", "error")
        return redirect(url_for("users_list"))
    user["access_level"] = level
    save_data(data)
    log_registration_event(session["username"], "SET_LEVEL", username, "SUCCESS", str(level))
    flash("Рівень доступу оновлено.", "success")
    return redirect(url_for("users_list"))


@app.route("/reauth", methods=["GET", "POST"])
@login_required
def reauthenticate():
    username = session["username"]
    user, _ = get_user_record(username)
    if user is None:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "GET":
        selected = random.sample(SECURITY_QUESTIONS, QUESTIONS_PER_ITERATION)
        session["auth_questions"] = [item["id"] for item in selected]
        return render_template("reauth.html", questions=selected)

    asked_ids = session.get("auth_questions", [])
    if len(asked_ids) != QUESTIONS_PER_ITERATION:
        return redirect(url_for("reauthenticate"))

    answers = user.get("security_answers", {})
    for qid in asked_ids:
        user_answer = request.form.get(qid, "").strip().lower()
        if user_answer != answers.get(qid, "").strip().lower():
            session.clear()
            log_operation_event(username, "REAUTH", "FAILED", f"wrong_answer_{qid}")
            log_registration_event(username, "LOGOUT", username, "FORCED", "failed_periodic_auth")
            flash("Періодична аутентифікація не пройдена. Увійдіть знову.", "error")
            return redirect(url_for("login"))

    session["last_auth_at"] = datetime.now().timestamp()
    session.pop("auth_questions", None)
    log_operation_event(username, "REAUTH", "SUCCESS")
    flash("Періодичну аутентифікацію успішно пройдено.", "success")
    return redirect(url_for("dashboard"))


@app.route("/function/<int:function_id>")
@login_required
def protected_function(function_id: int):
    levels_map = {1: 1, 2: 1, 3: 2, 4: 2, 5: 3, 6: 3}
    min_level = levels_map.get(function_id)
    if min_level is None:
        flash("Такої функції не існує.", "error")
        return redirect(url_for("dashboard"))
    user, _ = get_user_record(session["username"])
    if user["access_level"] < min_level:
        log_operation_event(session["username"], f"FUNCTION_{function_id}", "DENIED")
        flash("Недостатній рівень доступу.", "error")
        return redirect(url_for("dashboard"))
    log_operation_event(session["username"], f"FUNCTION_{function_id}", "SUCCESS")
    flash(f"Функцію №{function_id} виконано успішно.", "success")
    return redirect(url_for("dashboard"))


@app.route("/admin/logs")
@login_required
@admin_required
def view_logs():
    with open(REGISTRATION_LOG_FILE, "r", encoding="utf-8") as file:
        registration_log = json.load(file)
    with open(OPERATION_LOG_FILE, "r", encoding="utf-8") as file:
        operation_log = json.load(file)
    registration_size = os.path.getsize(REGISTRATION_LOG_FILE)
    operation_size = os.path.getsize(OPERATION_LOG_FILE)
    return render_template(
        "logs.html",
        registration_log=list(reversed(registration_log[-50:])),
        operation_log=list(reversed(operation_log[-50:])),
        registration_size=registration_size,
        operation_size=operation_size,
    )


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/logout")
def logout():
    if session.get("username"):
        log_registration_event(session["username"], "LOGOUT", session["username"], "SUCCESS")
        log_operation_event(session["username"], "LOGOUT", "SUCCESS")
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    ensure_data_file()
    app.run(debug=True)

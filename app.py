import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DATABASE = INSTANCE_DIR / "site.db"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "5678"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-this")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    INSTANCE_DIR.mkdir(exist_ok=True)
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
        """
    )

    columns = {column["name"] for column in db.execute("PRAGMA table_info(users)")}
    if "is_admin" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )

    admin_user = db.execute(
        "SELECT id FROM users WHERE username = ?",
        (ADMIN_USERNAME,),
    ).fetchone()
    admin_hash = generate_password_hash(ADMIN_PASSWORD)

    if admin_user:
        db.execute(
            "UPDATE users SET password_hash = ?, is_admin = 1 WHERE username = ?",
            (admin_hash, ADMIN_USERNAME),
        )
    else:
        db.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
            (ADMIN_USERNAME, admin_hash),
        )

    db.commit()
    db.close()


def get_current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return get_db().execute(
        "SELECT id, username, is_admin FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if get_current_user() is None:
            flash("로그인이 필요합니다.", "error")
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


def get_post_or_404(post_id):
    post = get_db().execute(
        """
        SELECT posts.id, posts.title, posts.content, posts.user_id, posts.created_at,
               posts.updated_at, users.username
        FROM posts
        JOIN users ON users.id = posts.user_id
        WHERE posts.id = ?
        """,
        (post_id,),
    ).fetchone()
    if post is None:
        abort(404)
    return post


def can_manage_post(post, user):
    return user is not None and (user["is_admin"] or post["user_id"] == user["id"])


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.context_processor
def inject_user():
    return {"current_user": get_current_user()}


@app.route("/")
def home():
    posts = get_db().execute(
        """
        SELECT posts.id, posts.title, posts.content, posts.user_id, posts.created_at,
               posts.updated_at, users.username
        FROM posts
        JOIN users ON users.id = posts.user_id
        ORDER BY posts.created_at DESC, posts.id DESC
        """
    ).fetchall()
    return render_template("home.html", posts=posts)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not password:
            flash("아이디와 비밀번호를 모두 입력해주세요.", "error")
        elif username == ADMIN_USERNAME:
            flash("해당 아이디는 사용할 수 없습니다.", "error")
        elif len(password) < 4:
            flash("비밀번호는 최소 4자 이상이어야 합니다.", "error")
        elif password != confirm_password:
            flash("비밀번호 확인이 일치하지 않습니다.", "error")
        else:
            db = get_db()
            existing_user = db.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if existing_user:
                flash("이미 존재하는 아이디입니다.", "error")
            else:
                db.execute(
                    "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
                flash("회원가입이 완료되었습니다. 로그인해주세요.", "success")
                return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            flash(f"{user['username']}님, 환영합니다.", "success")
            return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    recent_posts = db.execute(
        """
        SELECT posts.id, posts.title, posts.created_at, users.username
        FROM posts
        JOIN users ON users.id = posts.user_id
        ORDER BY posts.created_at DESC, posts.id DESC
        LIMIT 5
        """
    ).fetchall()
    return render_template("dashboard.html", recent_posts=recent_posts)


@app.route("/board")
def board_list():
    posts = get_db().execute(
        """
        SELECT posts.id, posts.title, posts.content, posts.user_id, posts.created_at,
               posts.updated_at, users.username
        FROM posts
        JOIN users ON users.id = posts.user_id
        ORDER BY posts.created_at DESC, posts.id DESC
        """
    ).fetchall()
    return render_template("board_list.html", posts=posts)


@app.route("/board/create", methods=["GET", "POST"])
@login_required
def board_create():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        user = get_current_user()

        if not title or not content:
            flash("제목과 내용을 모두 입력해주세요.", "error")
        else:
            db = get_db()
            db.execute(
                """
                INSERT INTO posts (title, content, user_id, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (title, content, user["id"]),
            )
            db.commit()
            flash("게시글이 등록되었습니다.", "success")
            return redirect(url_for("board_list"))

    return render_template("board_form.html", mode="create", post=None)


@app.route("/board/<int:post_id>")
def board_detail(post_id):
    post = get_post_or_404(post_id)
    user = get_current_user()
    return render_template(
        "board_detail.html",
        post=post,
        can_manage=can_manage_post(post, user),
    )


@app.route("/board/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def board_edit(post_id):
    post = get_post_or_404(post_id)
    user = get_current_user()

    if not can_manage_post(post, user):
        flash("작성자 본인 또는 관리자만 수정할 수 있습니다.", "error")
        return redirect(url_for("board_detail", post_id=post_id))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        if not title or not content:
            flash("제목과 내용을 모두 입력해주세요.", "error")
        else:
            db = get_db()
            db.execute(
                """
                UPDATE posts
                SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (title, content, post_id),
            )
            db.commit()
            flash("게시글이 수정되었습니다.", "success")
            return redirect(url_for("board_detail", post_id=post_id))

    return render_template("board_form.html", mode="edit", post=post)


@app.route("/board/<int:post_id>/delete", methods=["POST"])
@login_required
def board_delete(post_id):
    post = get_post_or_404(post_id)
    user = get_current_user()

    if not can_manage_post(post, user):
        flash("작성자 본인 또는 관리자만 삭제할 수 있습니다.", "error")
        return redirect(url_for("board_detail", post_id=post_id))

    db = get_db()
    db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    db.commit()
    flash("게시글이 삭제되었습니다.", "success")
    return redirect(url_for("board_list"))


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("로그아웃되었습니다.", "success")
    return redirect(url_for("home"))


init_db()


if __name__ == "__main__":
    app.run(debug=True)

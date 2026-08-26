"""Northridge Campus Lost & Found — patched copy.

The two lab weaknesses are closed here:
  (a) login uses a bound-parameter SQL query and hashed passwords
  (b) /admin requires a Flask server-side session established at login

Same templates, same seed users, different control plane.
"""

from __future__ import annotations

import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "portal.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("PORTAL_SECRET", "dev-only-local-secret")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc: BaseException | None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def seed_if_needed() -> None:
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            location TEXT NOT NULL
        );
        """
    )
    if db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 0:
        db.executemany(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            [
                ("kofi.staff", generate_password_hash("lab-only"), "staff"),
                ("ama.admin", generate_password_hash("lab-only-admin"), "admin"),
            ],
        )
        db.executemany(
            "INSERT INTO items (title, location) VALUES (?, ?)",
            [
                ("Blue umbrella", "Library foyer"),
                ("Student ID card (Ama)", "Science block"),
                ("USB drive", "Lecture hall 2"),
            ],
        )
        db.commit()


@app.before_request
def _seed() -> None:
    seed_if_needed()


@app.context_processor
def inject_user() -> dict:
    return {
        "warning": "Patched build — still a local lab, not a production app.",
        "current_user": session.get("username"),
        "current_role": session.get("role"),
    }


def login_required(role: str | None = None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                return render_template("forbidden.html"), 403
            return view(*args, **kwargs)

        return wrapped

    return decorator


@app.route("/")
def home():
    items = get_db().execute("SELECT title, location FROM items ORDER BY id").fetchall()
    return render_template("home.html", items=items, role=session.get("role", "anonymous"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute(
            "SELECT id, username, role, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            return redirect(url_for("home"))
        error = "Unknown username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/admin")
@login_required(role="admin")
def admin():
    users = get_db().execute("SELECT username, role FROM users ORDER BY id").fetchall()
    return render_template("admin.html", users=users)


if __name__ == "__main__":
    print("Patched Northridge portal — local lab only")
    app.run(host="127.0.0.1", port=5003, debug=False)

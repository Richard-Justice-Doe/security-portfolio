"""Northridge Campus Lost & Found — VULNERABLE lab copy.

VULNERABLE BY DESIGN — LAB USE ONLY, DO NOT DEPLOY PUBLICLY

Two documented weaknesses live in this file (see ../vulnerability_notes.md):
  (a) login builds SQL with string formatting instead of bound parameters
  (b) /admin trusts a client-supplied `role` cookie instead of a server session

Compare with ../fixed/app.py for the patched behaviour.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, g, make_response, redirect, render_template, request, url_for

WARNING = "VULNERABLE BY DESIGN — LAB USE ONLY, DO NOT DEPLOY PUBLICLY"

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "portal.db"

app = Flask(__name__)
app.config["LAB_WARNING"] = WARNING


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
            password TEXT NOT NULL,
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
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            [
                ("kofi.staff", "lab-only", "staff"),
                ("ama.admin", "lab-only-admin", "admin"),
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
def inject_warning() -> dict:
    return {"warning": WARNING}


@app.route("/")
def home():
    items = get_db().execute("SELECT title, location FROM items ORDER BY id").fetchall()
    role = request.cookies.get("role", "anonymous")
    return render_template("home.html", items=items, role=role)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # Weakness (a): untrusted input is interpolated into SQL.
        # The patched copy in ../fixed/app.py uses a parameterised query.
        query = (
            "SELECT id, username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        row = db.execute(query).fetchone()
        if row:
            resp = make_response(redirect(url_for("home")))
            # Weakness (b): role is a client-writable cookie, not a server session.
            resp.set_cookie("role", row["role"])
            resp.set_cookie("username", row["username"])
            return resp
        error = "Unknown username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("home")))
    resp.delete_cookie("role")
    resp.delete_cookie("username")
    return resp


@app.route("/admin")
def admin():
    # Weakness (b): no server-side session. Anyone who can set a cookie named
    # `role` with the value `admin` is treated as an administrator.
    if request.cookies.get("role") != "admin":
        return render_template("forbidden.html"), 403
    users = get_db().execute("SELECT username, role FROM users ORDER BY id").fetchall()
    return render_template("admin.html", users=users)


if __name__ == "__main__":
    # Local demo binds localhost. The Docker image overrides host via Flask's
    # built-in server flags below so port-publish works *inside* the container.
    import os

    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
    print(WARNING)
    app.run(host=host, port=5002, debug=False)

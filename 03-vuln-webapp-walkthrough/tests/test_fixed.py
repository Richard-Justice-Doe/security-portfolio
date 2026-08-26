"""Defensive tests for the patched campus portal.

These tests assert secure behaviour: real credentials work, a missing
session cannot open /admin, and a staff session cannot open /admin.
They do not send attack payloads.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

FIXED = Path(__file__).resolve().parents[1] / "fixed"
sys.path.insert(0, str(FIXED))

from app import app, DB_PATH  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("app.DB_PATH", tmp_path / "portal.db")
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret"
    with app.test_client() as client:
        yield client


def test_home_renders(client):
    rv = client.get("/")
    assert rv.status_code == 200
    assert b"Unclaimed items" in rv.data


def test_login_rejects_wrong_password(client):
    rv = client.post("/login", data={"username": "kofi.staff", "password": "nope"}, follow_redirects=True)
    assert b"Unknown username or password" in rv.data


def test_staff_login_reaches_home(client):
    rv = client.post("/login", data={"username": "kofi.staff", "password": "lab-only"}, follow_redirects=True)
    assert rv.status_code == 200
    assert b"kofi.staff" in rv.data or b"staff" in rv.data


def test_admin_requires_session(client):
    rv = client.get("/admin", follow_redirects=False)
    assert rv.status_code in (302, 401, 403)


def test_client_supplied_role_cookie_is_ignored(client):
    """Patched app must not treat a client `role` cookie as authorisation."""
    client.set_cookie("role", "admin")
    rv = client.get("/admin", follow_redirects=False)
    assert rv.status_code in (302, 401, 403)


def test_staff_session_cannot_open_admin(client):
    client.post("/login", data={"username": "kofi.staff", "password": "lab-only"})
    rv = client.get("/admin")
    assert rv.status_code == 403


def test_admin_login_can_open_admin(client):
    client.post("/login", data={"username": "ama.admin", "password": "lab-only-admin"})
    rv = client.get("/admin")
    assert rv.status_code == 200
    assert b"ama.admin" in rv.data

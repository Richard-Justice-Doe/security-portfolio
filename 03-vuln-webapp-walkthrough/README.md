# Vulnerable Web App + Patch Walkthrough

A tiny **campus lost-and-found portal** shipped in two copies: an intentionally weak lab build and a patched build of the same features. The point of the folder is a **before/after code review**, not a public target.

> **VULNERABLE BY DESIGN — LAB USE ONLY, DO NOT DEPLOY PUBLICLY.**
> Run it on localhost (or in the provided Docker image published only to `127.0.0.1`). Do not scan, attack, or expose any system you do not own. A step-by-step exploit walkthrough is **not** included; see [vulnerability_notes.md](vulnerability_notes.md) for a high-level description of the two defects and how the patch closes them.

## Problem it solves

Hiring and admissions reviewers often want evidence that a candidate can (1) recognise classic web flaws in real code and (2) write the fix. This project is that artefact: two Flask apps, same UX, different control plane.

## The two lab weaknesses

| ID | Weak copy | Patched copy |
| --- | --- | --- |
| (a) SQL injection in login | Username/password concatenated into SQL | Bound parameter + password hashes |
| (b) Broken authentication on `/admin` | `role` is a client cookie | Flask signed session + `login_required(role="admin")` |

Details, with pointers into the source, are in [vulnerability_notes.md](vulnerability_notes.md).

## Layout

```
vulnerable/     Flask app with the two defects (port 5002)
fixed/          Same product, defects closed (port 5003)
tests/          Defensive tests against the patched app
Dockerfile      Isolated image of the weak copy, localhost publish only
```

## Setup (no Docker)

Python 3.10+. From this directory:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Legitimate lab accounts (synthetic, documented on the login page):

- staff: `kofi.staff` / `lab-only`
- admin: `ama.admin` / `lab-only-admin`

Run the **patched** app (preferred demo):

```bash
python fixed/app.py
```

Open [http://127.0.0.1:5003](http://127.0.0.1:5003). Sign in as `ama.admin`, open **Staff admin**, then sign out and confirm `/admin` redirects or 403s.

Run the **vulnerable** copy only inside this folder or Docker, still on loopback:

```bash
python vulnerable/app.py
```

[http://127.0.0.1:5002](http://127.0.0.1:5002) — same accounts, same pages, weaker checks. Do not publish the port.

## Setup (Docker, isolated)

The Dockerfile is labelled **VULNERABLE BY DESIGN — LAB USE ONLY, DO NOT DEPLOY PUBLICLY**. Publish *only* on loopback:

```bash
docker build -t campus-portal-vuln-lab .
docker run --rm -p 127.0.0.1:5002:5002 campus-portal-vuln-lab
```

Never use `-p 5002:5002` without `127.0.0.1`, and never push this image to a registry.

## Defensive tests (patched app)

```bash
pip install pytest
python -m pytest tests/test_fixed.py -q
```

The tests check: home renders, bad passwords fail, staff can log in, `/admin` is closed without a session, staff cannot open `/admin`, a real admin session can. They do not include attack payloads.

## Ethical use

- This is a **local teaching lab**, not a CTF write-up of a live system.
- Do not reuse `vulnerable/` as the starter for a real service.
- Do not point scanners or "practice exploits" at other people's applications.
- If you fork this repo, keep the red banner and the loopback bind.

## Example output

Patched app, unauthenticated `/admin`:

```
GET /admin  ->  302 to /login   (no session)
```

Patched app, staff session:

```
POST /login  kofi.staff / lab-only  ->  302 to /
GET  /admin                         ->  403 Staff only
```

Patched app, admin session:

```
POST /login  ama.admin / lab-only-admin  ->  302 to /
GET  /admin                              ->  200 staff directory
```

## Contributors

- [Richard Justice Doe](https://github.com/Richard-Justice-Doe) — author

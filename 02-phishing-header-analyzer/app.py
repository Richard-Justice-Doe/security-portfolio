"""Flask front end for the phishing / email-header analyzer."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, render_template, request

from analyzer import analyze_headers, load_sample

ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT / "samples"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MiB


def _list_samples() -> list[dict[str, str]]:
    items = []
    for path in sorted(SAMPLES.glob("*.eml")):
        items.append({"name": path.name, "stem": path.stem})
    return items


@app.route("/")
def index():
    return render_template("index.html", samples=_list_samples(), error=None)


@app.route("/analyze", methods=["POST"])
def analyze():
    raw = (request.form.get("headers") or "").strip()
    upload = request.files.get("eml")
    if upload and upload.filename:
        try:
            raw = upload.read().decode("utf-8", errors="replace")
        except OSError:
            return render_template("index.html", samples=_list_samples(), error="Could not read the uploaded file."), 400
    if not raw:
        return render_template(
            "index.html",
            samples=_list_samples(),
            error="Paste headers or upload a .eml file first.",
        ), 400
    report = analyze_headers(raw)
    return render_template("results.html", report=report, raw=raw)


@app.route("/demo/<name>")
def demo(name: str):
    path = (SAMPLES / name).resolve()
    if path.parent != SAMPLES.resolve() or not path.is_file():
        abort(404)
    report = analyze_headers(load_sample(path))
    return render_template("results.html", report=report, raw=load_sample(path), demo_name=name)


@app.route("/health")
def health():
    return {"ok": True, "samples": len(_list_samples())}


if __name__ == "__main__":
    # Bind localhost only — this is a local demo, not a public service.
    app.run(host="127.0.0.1", port=5001, debug=False)

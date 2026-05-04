"""
Phishing URL Analyzer — Flask Backend
======================================
Routes:
  GET/POST /login   → Login page
  GET      /logout  → Clear session and redirect to login
  GET      /        → Dashboard (protected — requires login)
  POST     /analyze → Analyze a URL, returns JSON + saves to history (protected)
  GET      /history → Return last 10 scan results as JSON (protected)

Usage:
  python app.py
  Then visit http://127.0.0.1:5000/
  Default credentials: admin / password123
"""

from functools import wraps
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from analyzer import PhishingAnalyzer

# ─── App Setup ────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = "phishing-analyzer-secret-key-2024"   # required for session

analyzer = PhishingAnalyzer()   # single shared instance (stateless, safe to reuse)

# ─── Hardcoded Credentials (no database needed) ───────────────────────────────

VALID_USERNAME = "admin"
VALID_PASSWORD = "password123"

# ─── Login Required Decorator ─────────────────────────────────────────────────

def login_required(f):
    """Redirect to /login if the user is not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    """Show login form (GET) or validate credentials (POST)."""
    # Already logged in → go straight to dashboard
    if session.get("logged_in"):
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username == VALID_USERNAME and password == VALID_PASSWORD:
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("home"))
        else:
            error = "Invalid username or password. Please try again."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    """Clear session and send user back to login page."""
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
@login_required
def home():
    """Dashboard — requires login. Passes existing scan history to template."""
    history = session.get("history", [])
    return render_template("index.html", username=session.get("username"), history=history)


@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    """
    Analyze a URL for phishing indicators.

    Expected request body (JSON):
        { "url": "<the URL to check>" }

    Returns JSON:
        {
            "original_url": str,
            "expanded_url": str,
            "score": int,        # 0–100
            "status": str,       # "Safe" | "Suspicious" | "Dangerous" | "Invalid URL"
            "reasons": [str]     # list of detected issues
        }
    """
    # ── Validate Content-Type ──────────────────────────────────────────────
    if not request.is_json:
        return jsonify({
            "error": "Request must be JSON",
            "hint": "Set Content-Type: application/json and send { \"url\": \"...\" }"
        }), 415

    data = request.get_json()

    # ── Validate Payload ───────────────────────────────────────────────────
    if "url" not in data or not isinstance(data["url"], str):
        return jsonify({
            "error": "Missing or invalid 'url' field",
            "hint": "Send { \"url\": \"https://example.com\" }"
        }), 400

    url = data["url"].strip()

    if not url:
        return jsonify({
            "error": "URL cannot be empty"
        }), 400

    # ── Run Analysis (unchanged PhishingAnalyzer logic) ───────────────────
    result = analyzer.analyze(url)

    # ── Save to scan history (newest first, max 10 entries) ───────────────
    history = session.get("history", [])
    history.insert(0, {
        "url":    result.get("original_url", url),
        "status": result.get("status", "Safe"),
        "score":  result.get("score", 0),
    })
    session["history"] = history[:10]   # keep last 10 only
    session.modified = True             # tell Flask the session changed

    return jsonify(result), 200


@app.route("/history", methods=["GET"])
@login_required
def history():
    """Return the current user's scan history as JSON."""
    return jsonify(session.get("history", []))


@app.route("/about")
def about():
    """About page — public, no login required."""
    return render_template("about.html")


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # debug=True gives auto-reload & detailed errors (fine for dev/college demo)
    app.run(debug=True, host="0.0.0.0", port=5000)

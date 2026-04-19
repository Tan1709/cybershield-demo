from flask import Flask, request, redirect, url_for, session, send_from_directory, Response, jsonify
import os
from functools import wraps
from pathlib import Path
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder="assets", template_folder=BASE_DIR)
logging.basicConfig(level=logging.INFO)

# Session secret key (demo). For production set via environment variable.
app.secret_key = os.environ.get("CYBERSHIELD_SECRET", "dev-secret-key-for-demo-only")

# Fixed demo credentials (per requirements)
VALID_USERNAME = "admin"
VALID_PASSWORD = "admin@123"

# Session key
AUTH_KEY = "cybershield_logged_in"

# Helpers
def safe_read_file(path: str) -> str:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    return p.read_text(encoding="utf-8")

# Prevent caching so back-button won't show protected pages after logout
@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get(AUTH_KEY) is True:
            return f(*args, **kwargs)
        return redirect(url_for("login"))
    return decorated

# --- Paths to files ---
INDEX_PATH = os.path.join(BASE_DIR, "index.html")
DASHBOARD_PATH = os.path.join(BASE_DIR, "realtime", "dashboard.html")
UPLOAD_DIR = os.path.join(BASE_DIR, "upload")
UPLOAD_DASHBOARD_FILE = os.path.join(UPLOAD_DIR, "udashboard.html")  # actual file on disk

# --- Login routes ---
@app.route("/", methods=["GET"])
@app.route("/login", methods=["GET"])
def login():
    # If already logged-in -> ensure upload_mode OFF and land on realtime dashboard
    if session.get(AUTH_KEY) is True:
        session.setdefault("upload_mode", False)
        session["upload_mode"] = False
        return redirect(url_for("realtime_dashboard"))
    try:
        content = safe_read_file(INDEX_PATH)
    except FileNotFoundError:
        return "Login page not found", 404
    return Response(content, mimetype="text/html")

@app.route("/login", methods=["POST"])
def login_post():
    username = request.form.get("username") or request.form.get("usernameInput") or request.form.get("user")
    password = request.form.get("password") or request.form.get("passwordInput") or request.form.get("pass")

    # JSON fallback
    if not username or not password:
        try:
            data = request.get_json(silent=True) or {}
            username = username or data.get("username")
            password = password or data.get("password")
        except Exception:
            pass

    if not username or not password:
        return redirect(url_for("login") + "?error=Please+fill+in+both+username+and+password")

    if username == VALID_USERNAME and password == VALID_PASSWORD:
        session.clear()
        session[AUTH_KEY] = True
        # Default behavior: after login Upload Mode = OFF and user lands on /realtime/dashboard
        session["upload_mode"] = False
        return redirect(url_for("realtime_dashboard"))
    else:
        return redirect(url_for("login") + "?error=Invalid+username+or+password")

# --- Server-side status endpoint used by client JS ---
@app.route("/auth/status", methods=["GET"])
def auth_status():
    """
    Returns JSON describing whether the user is authenticated and whether upload_mode is ON.
    Client JS MUST use this as single source-of-truth.
    """
    return jsonify({
        "authenticated": bool(session.get(AUTH_KEY) is True),
        "upload_mode": bool(session.get("upload_mode") is True)
    })

# --- Endpoint to set upload mode (call from client) ---
@app.route("/set_upload_mode", methods=["POST"])
@login_required
def set_upload_mode():
    """
    Expects JSON: {"mode": true|false} (boolean preferred).
    Sets session['upload_mode'] and returns the authoritative result.
    """
    data = request.get_json(silent=True) or {}
    mode = data.get("mode")

    # Accept boolean or common string variants for compatibility
    if isinstance(mode, bool):
        session["upload_mode"] = mode
        return jsonify({"success": True, "upload_mode": session["upload_mode"]})
    if isinstance(mode, str):
        low = mode.strip().lower()
        if low in ("true", "1", "on", "yes"):
            session["upload_mode"] = True
            return jsonify({"success": True, "upload_mode": session["upload_mode"]})
        if low in ("false", "0", "off", "no"):
            session["upload_mode"] = False
            return jsonify({"success": True, "upload_mode": session["upload_mode"]})

    return jsonify({"success": False, "error": "invalid mode"}), 400

# Backwards-compatible endpoint: if older clients post to /set-upload
@app.route("/set-upload", methods=["POST"])
@login_required
def set_upload_mode_compat():
    return set_upload_mode()

# --- Real-time pages (protected) ---
@app.route("/realtime/dashboard")
@login_required
def realtime_dashboard():
    # If upload mode is ON, block realtime landing and redirect to upload dashboard
    if session.get("upload_mode") is True:
        # redirect to the explicit upload html path
        return redirect("/upload/udashboard.html")
    try:
        content = safe_read_file(DASHBOARD_PATH)
    except FileNotFoundError:
        return "Realtime dashboard page not found", 404
    return Response(content, mimetype="text/html")

@app.route("/realtime/<path:filename>")
@login_required
def realtime_pages(filename):
    # If upload mode is ON, redirect to upload dashboard (single source of truth)
    if session.get("upload_mode") is True:
        return redirect("/upload/udashboard.html")
    realtime_dir = os.path.join(BASE_DIR, "realtime")
    return send_from_directory(realtime_dir, filename)

# --- Upload pages (protected) ---
# Serve explicit HTML path /upload/udashboard.html so client can be redirected there
@app.route("/upload/udashboard.html")
@login_required
def upload_udashboard_html():
    # If upload_mode is OFF, block upload landing and redirect to realtime dashboard
    if session.get("upload_mode") is not True:
        return redirect(url_for("realtime_dashboard"))
    if not os.path.exists(UPLOAD_DASHBOARD_FILE):
        return ("Upload dashboard not found at expected path: {}\n"
                "Make sure upload/udashboard.html exists and restart the server.").format(UPLOAD_DASHBOARD_FILE), 404
    # Serve the raw HTML file (no redirection) so browser shows /upload/udashboard.html
    return send_from_directory(UPLOAD_DIR, "udashboard.html")

# Keep compatibility routes: /upload/dashboard and /upload/udashboard
@app.route("/upload/dashboard")
@app.route("/upload/udashboard")
@login_required
def upload_dashboard():
    if session.get("upload_mode") is not True:
        return redirect(url_for("realtime_dashboard"))
    if not os.path.exists(UPLOAD_DASHBOARD_FILE):
        return ("Upload dashboard not found at expected path: {}\n"
                "Make sure upload/udashboard.html exists and restart the server.").format(UPLOAD_DASHBOARD_FILE), 404
    try:
        content = safe_read_file(UPLOAD_DASHBOARD_FILE)
    except FileNotFoundError:
        return "Upload dashboard not found", 404
    return Response(content, mimetype="text/html")

@app.route("/upload/<path:filename>")
@login_required
def upload_pages(filename):
    # If upload_mode is OFF, block upload resources and redirect to realtime landing
    if session.get("upload_mode") is not True:
        return redirect(url_for("realtime_dashboard"))

    normalized = filename.replace('\\', '/').lstrip('/')
    if ".." in normalized.split('/'):
        return "Invalid path", 400

    # If explicit udashboard.html requested via /upload/udashboard.html path it will be served
    # by the dedicated route above. For other common names, redirect to canonical upload dashboard route.
    if normalized.lower() in ("udashboard", "dashboard", "dashboard.html"):
        return redirect(url_for("upload_dashboard"))

    return send_from_directory(UPLOAD_DIR, normalized)

# --- Logout ---
@app.route("/logout")
def logout():
    """
    Clear server-side session and remove the session cookie, then redirect to /login.
    Uses app.config['SESSION_COOKIE_NAME'] (fallback 'session') and resp.delete_cookie
    for maximum compatibility across Flask versions.
    """
    try:
        session.clear()
        resp = redirect(url_for("login"))
        # Use the canonical config key for the session cookie name (fallback to 'session')
        cookie_name = app.config.get("SESSION_COOKIE_NAME", "session")
        # Delete cookie (clean), specify path to be safe
        resp.delete_cookie(cookie_name, path="/")
        return resp
    except Exception as e:
        # Log the exception so you can see the traceback in the server logs
        app.logger.exception("Error during logout")
        # Return a friendly error (or re-raise if you prefer to see the full traceback)
        return "Internal Server Error during logout", 500
# Serve navigation JS from realtime folder at both paths (realtime and upload)
@app.route("/realtime/navigation.js")
def navigation_js_realtime():
    nav_path = os.path.join(BASE_DIR, "realtime", "navigation.js")
    if not os.path.exists(nav_path):
        return "/* navigation.js not found */", 404
    return send_from_directory(os.path.join(BASE_DIR, "realtime"), "navigation.js")

@app.route("/upload/navigation.js")
def navigation_js_upload():
    nav_path = os.path.join(BASE_DIR, "realtime", "navigation.js")
    if not os.path.exists(nav_path):
        return "/* navigation.js not found */", 404
    return send_from_directory(os.path.join(BASE_DIR, "realtime"), "navigation.js")

# Debugging helper to show routes
@app.route("/debug/routes")
def debug_routes():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({"rule": str(rule), "endpoint": rule.endpoint, "methods": sorted(list(rule.methods))})
    return jsonify(routes)

# Ensure session cookie is sent on same-origin fetch requests
app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)

# --- API-safe auth decorator: returns 401 JSON instead of redirecting ---
def api_login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get(AUTH_KEY) is True:
            return f(*args, **kwargs)
        return jsonify({"error": "Not authenticated. Please log in."}), 401
    return decorated

# --- Upload report: in-memory log storage (keyed by session id) ---
_upload_log_store: dict = {}   # { session_id: {"logs": [...], "file_names": [...], "raw_total": int, "duplicates_removed": int} }

@app.route("/api/upload/logs", methods=["POST"])
@api_login_required
def upload_store_logs():
    """
    Frontend posts analyzed log data here so the server can generate reports.
    Body (JSON): { "logs": [...], "file_names": [...], "raw_total": int, "duplicates_removed": int }
    """
    import uuid
    # Ensure a stable store key exists in the session and is persisted
    if "report_store_id" not in session:
        session["report_store_id"] = str(uuid.uuid4())
    session.modified = True  # force Flask to save the session cookie
    store_key = session["report_store_id"]

    data = request.get_json(silent=True) or {}
    logs               = data.get("logs", [])
    file_names         = data.get("file_names", [])
    raw_total          = int(data.get("raw_total", len(logs)))
    duplicates_removed = int(data.get("duplicates_removed", 0))

    _upload_log_store[store_key] = {
        "logs": logs,
        "file_names": file_names,
        "raw_total": raw_total,
        "duplicates_removed": duplicates_removed,
    }
    app.logger.info("Stored %d logs under key %s", len(logs), store_key)
    return jsonify({"success": True, "stored": len(logs), "store_key": store_key})


def _get_stored_logs():
    """Retrieve stored logs for the current session."""
    store_key = session.get("report_store_id")
    app.logger.info("_get_stored_logs: store_key=%s, keys_in_store=%s",
                    store_key, list(_upload_log_store.keys()))
    if not store_key or store_key not in _upload_log_store:
        return None
    return _upload_log_store[store_key]


@app.route("/api/upload/report/status")
@api_login_required
def upload_report_status():
    """Return whether log data is available for the current session."""
    store_key = session.get("report_store_id")
    has_logs = bool(store_key and store_key in _upload_log_store
                   and _upload_log_store[store_key].get("logs"))
    count = len(_upload_log_store[store_key]["logs"]) if has_logs else 0
    return jsonify({"has_logs": has_logs, "log_count": count})


@app.route("/api/upload/report/pdf")
@api_login_required
def upload_report_pdf():
    """Generate and download Upload Mode PDF report."""
    try:
        from upload_report_generator import generate_upload_pdf, REPORTLAB_AVAILABLE, get_demo_logs
    except ImportError:
        return jsonify({"error": "upload_report_generator.py not found next to app.py"}), 500
    if not REPORTLAB_AVAILABLE:
        return jsonify({"error": "reportlab is not installed. Run: pip install reportlab matplotlib"}), 500

    entry = _get_stored_logs()
    is_demo = entry is None
    if is_demo:
        logs, file_names, raw_total, dupes = get_demo_logs()
    else:
        logs, file_names, raw_total, dupes = entry["logs"], entry["file_names"], entry["raw_total"], entry["duplicates_removed"]

    try:
        buf, filename = generate_upload_pdf(
            all_logs=logs, file_names=file_names,
            raw_total=raw_total, duplicates_removed=dupes,
            is_demo=is_demo,
        )
        from flask import send_file
        return send_file(buf, mimetype="application/pdf",
                         as_attachment=True, download_name=filename)
    except Exception as exc:
        app.logger.exception("PDF generation failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/upload/report/csv")
@api_login_required
def upload_report_csv():
    """Generate and download Upload Mode CSV report."""
    try:
        from upload_report_generator import generate_upload_csv, get_demo_logs
    except ImportError:
        return jsonify({"error": "CSV generator not available"}), 500

    entry = _get_stored_logs()
    is_demo = entry is None
    logs = get_demo_logs()[0] if is_demo else entry["logs"]

    try:
        buf, filename = generate_upload_csv(all_logs=logs, is_demo=is_demo)
        from flask import send_file
        return send_file(buf, mimetype="text/csv",
                         as_attachment=True, download_name=filename)
    except Exception as exc:
        app.logger.exception("CSV generation failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/upload/report/json")
@api_login_required
def upload_report_json():
    """Generate and download Upload Mode JSON report."""
    try:
        from upload_report_generator import generate_upload_json, get_demo_logs
    except ImportError:
        return jsonify({"error": "JSON generator not available"}), 500

    entry = _get_stored_logs()
    is_demo = entry is None
    if is_demo:
        logs, _, raw_total, dupes = get_demo_logs()
    else:
        logs, raw_total, dupes = entry["logs"], entry["raw_total"], entry["duplicates_removed"]

    try:
        buf, filename = generate_upload_json(
            all_logs=logs, raw_total=raw_total,
            duplicates_removed=dupes, is_demo=is_demo,
        )
        from flask import send_file
        return send_file(buf, mimetype="application/json",
                         as_attachment=True, download_name=filename)
    except Exception as exc:
        app.logger.exception("JSON generation failed")
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    logging.info("Registered routes:\n%s", "\n".join(str(r) for r in app.url_map.iter_rules()))
    app.run(host="0.0.0.0", port=5000, debug=False)
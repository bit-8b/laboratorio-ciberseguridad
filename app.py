import hmac
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from detector import detect_brute_force


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{4,20}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
SEVERITIES = {"Baja", "Media", "Alta", "Crítica"}
LOCKOUT_MINUTES = 15
FAILED_LOGIN_THRESHOLD = 3


def utc_now():
    return datetime.now(timezone.utc)


def to_timestamp(value):
    return value.astimezone(timezone.utc).isoformat()


def parse_timestamp(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            event_type TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            detail TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_security_events_user_type_time
            ON security_events (username, event_type, occurred_at);

        CREATE TABLE IF NOT EXISTS login_blocks (
            username TEXT PRIMARY KEY,
            locked_until TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            reporter_id INTEGER REFERENCES users(id),
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            response_at TEXT,
            attempts INTEGER NOT NULL DEFAULT 0,
            mttd_seconds REAL,
            mttr_seconds REAL,
            response_action TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_incidents_detected_at
            ON incidents (detected_at);
        """
    )
    db.commit()


def log_event(username, event_type, detail, occurred_at=None):
    timestamp = to_timestamp(occurred_at or utc_now())
    event = {
        "username": username,
        "event_type": event_type,
        "occurred_at": timestamp,
        "detail": detail,
    }

    db = get_db()
    db.execute(
        """
        INSERT INTO security_events (username, event_type, occurred_at, detail)
        VALUES (?, ?, ?, ?)
        """,
        (username, event_type, timestamp, detail),
    )
    db.commit()

    event_log = Path(current_app.config["EVENT_LOG"])
    event_log.parent.mkdir(parents=True, exist_ok=True)
    with event_log.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(event, ensure_ascii=False) + "\n")


def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Inicia sesión para continuar.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def valid_username(username):
    return bool(USERNAME_PATTERN.fullmatch(username))


def valid_email(email):
    return len(email) <= 254 and bool(EMAIL_PATTERN.fullmatch(email))


def valid_password(password):
    return 8 <= len(password) <= 128


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=str(Path(app.instance_path) / "security.db"),
        EVENT_LOG=str(Path(app.instance_path) / "eventos.log"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_SECURE_COOKIES") == "1",
    )
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()

    @app.before_request
    def protect_post_requests():
        if request.method == "POST":
            expected = session.get("csrf_token", "")
            supplied = request.form.get("csrf_token", "")
            if not expected or not supplied or not hmac.compare_digest(
                expected, supplied
            ):
                abort(
                    400,
                    description="Token de seguridad inválido. Recarga el formulario.",
                )

    @app.context_processor
    def inject_template_helpers():
        def csrf_token():
            token = session.get("csrf_token")
            if token is None:
                token = secrets.token_urlsafe(32)
                session["csrf_token"] = token
            return token

        return {"csrf_token": csrf_token}

    @app.route("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            if not valid_username(username):
                flash(
                    "El usuario debe tener entre 4 y 20 caracteres: letras, números, punto, guion o guion bajo.",
                    "error",
                )
                return render_template("register.html"), 400
            if not valid_email(email):
                flash("Escribe un correo electrónico válido.", "error")
                return render_template("register.html"), 400
            if not valid_password(password):
                flash("La contraseña debe tener entre 8 y 128 caracteres.", "error")
                return render_template("register.html"), 400

            db = get_db()
            try:
                db.execute(
                    """
                    INSERT INTO users (username, email, password_hash, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        username,
                        email,
                        generate_password_hash(password),
                        to_timestamp(utc_now()),
                    ),
                )
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
                flash("El usuario o el correo ya están registrados.", "error")
                return render_template("register.html"), 409

            log_event(username, "account_registered", "Cuenta registrada.")
            flash("Cuenta creada. Ya puedes iniciar sesión.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            raw_username = request.form.get("username", "").strip().lower()
            username = raw_username[:64]
            attempted_username = username or "<vacío>"
            password = request.form.get("password", "")
            db = get_db()
            now = utc_now()

            block = db.execute(
                "SELECT locked_until FROM login_blocks WHERE username = ?",
                (attempted_username,),
            ).fetchone()
            if block and parse_timestamp(block["locked_until"]) > now:
                log_event(
                    attempted_username,
                    "login_blocked",
                    "Intento durante el bloqueo.",
                )
                flash(
                    "Inicio de sesión temporalmente bloqueado por varios intentos fallidos.",
                    "error",
                )
                return redirect(url_for("login"))
            if block:
                db.execute(
                    "DELETE FROM login_blocks WHERE username = ?",
                    (attempted_username,),
                )
                db.commit()

            user = None
            if valid_username(username):
                user = db.execute(
                    "SELECT id, username, password_hash FROM users WHERE username = ?",
                    (username,),
                ).fetchone()

            if (
                user is None
                or len(password) > 128
                or not check_password_hash(user["password_hash"], password)
            ):
                log_event(
                    attempted_username,
                    "login_failed",
                    "Credenciales no válidas.",
                    now,
                )
                detection = detect_brute_force(
                    current_app.config["EVENT_LOG"],
                    attempted_username,
                    detected_at=now,
                    threshold=FAILED_LOGIN_THRESHOLD,
                )
                if detection:
                    locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
                    lock_cursor = db.execute(
                        """
                        INSERT OR IGNORE INTO login_blocks (username, locked_until)
                        VALUES (?, ?)
                        """,
                        (attempted_username, to_timestamp(locked_until)),
                    )
                    description = (
                        f"Detectados {detection['attempts']} intentos fallidos "
                        f"para la cuenta {attempted_username}."
                    )
                    if lock_cursor.rowcount:
                        response_at = to_timestamp(now)
                        db.execute(
                            """
                            INSERT INTO incidents (
                                username, description, severity, status, occurred_at,
                                detected_at, response_at, attempts, mttd_seconds,
                                mttr_seconds, response_action
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                attempted_username,
                                description,
                                "Alta",
                                "Respondido",
                                detection["first_attempt_at"],
                                detection["detected_at"],
                                response_at,
                                detection["attempts"],
                                detection["mttd_seconds"],
                                max(
                                    0.0,
                                    (
                                        now
                                        - parse_timestamp(detection["detected_at"])
                                    ).total_seconds(),
                                ),
                                f"Bloqueo temporal de {LOCKOUT_MINUTES} minutos.",
                            ),
                        )
                    db.commit()
                    if lock_cursor.rowcount:
                        log_event(
                            attempted_username,
                            "security_alert",
                            description,
                            now,
                        )
                        log_event(
                            attempted_username,
                            "account_blocked",
                            f"Bloqueo temporal hasta {to_timestamp(locked_until)}.",
                            now,
                        )
                flash("Usuario o contraseña incorrectos.", "error")
                return redirect(url_for("login"))

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            log_event(
                user["username"],
                "login_success",
                "Inicio de sesión correcto.",
                now,
            )
            flash("Inicio de sesión correcto.", "success")
            return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.post("/logout")
    @require_login
    def logout():
        username = session["username"]
        log_event(username, "logout", "Cierre de sesión.")
        session.clear()
        flash("Sesión cerrada.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @require_login
    def dashboard():
        db = get_db()
        incidents = db.execute(
            "SELECT * FROM incidents ORDER BY detected_at DESC, id DESC LIMIT 100"
        ).fetchall()
        events = db.execute(
            """
            SELECT username, event_type, occurred_at, detail
            FROM security_events
            ORDER BY occurred_at DESC, id DESC
            LIMIT 50
            """
        ).fetchall()
        metrics = db.execute(
            """
            SELECT COUNT(*) AS incident_count,
                   AVG(mttd_seconds) AS average_mttd,
                   AVG(mttr_seconds) AS average_mttr
            FROM incidents
            """
        ).fetchone()
        return render_template(
            "dashboard.html",
            incidents=incidents,
            events=events,
            metrics=metrics,
            now=utc_now().strftime("%Y-%m-%dT%H:%M"),
        )

    @app.post("/incidents")
    @require_login
    def report_incident():
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "")
        occurred_value = request.form.get("occurred_at", "")

        if not 5 <= len(description) <= 500:
            flash("La descripción debe tener entre 5 y 500 caracteres.", "error")
            return redirect(url_for("dashboard"))
        if severity not in SEVERITIES:
            flash("Selecciona una severidad válida.", "error")
            return redirect(url_for("dashboard"))
        try:
            occurred_at = parse_timestamp(occurred_value)
        except ValueError:
            flash("Indica una fecha y hora de inicio válidas.", "error")
            return redirect(url_for("dashboard"))

        detected_at = utc_now()
        if occurred_at > detected_at:
            flash("La fecha de inicio no puede estar en el futuro.", "error")
            return redirect(url_for("dashboard"))

        mttd_seconds = (detected_at - occurred_at).total_seconds()
        db = get_db()
        cursor = db.execute(
            """
            INSERT INTO incidents (
                username, reporter_id, description, severity, status,
                occurred_at, detected_at, mttd_seconds
            )
            VALUES (?, ?, ?, ?, 'Abierto', ?, ?, ?)
            """,
            (
                session["username"],
                session["user_id"],
                description,
                severity,
                to_timestamp(occurred_at),
                to_timestamp(detected_at),
                mttd_seconds,
            ),
        )
        db.commit()
        log_event(
            session["username"],
            "incident_reported",
            f"Incidente #{cursor.lastrowid} registrado.",
            detected_at,
        )
        flash("Incidente registrado.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/incidents/<int:incident_id>/respond")
    @require_login
    def respond_to_incident(incident_id):
        action = request.form.get("response_action", "").strip()
        if not 5 <= len(action) <= 250:
            flash(
                "La acción de respuesta debe tener entre 5 y 250 caracteres.",
                "error",
            )
            return redirect(url_for("dashboard"))

        db = get_db()
        incident = db.execute(
            "SELECT id, username, status, detected_at FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        if incident is None:
            abort(404)
        if incident["status"] != "Abierto":
            flash("El incidente ya tiene una respuesta registrada.", "error")
            return redirect(url_for("dashboard"))

        response_at = utc_now()
        mttr_seconds = max(
            0.0,
            (response_at - parse_timestamp(incident["detected_at"])).total_seconds(),
        )
        update = db.execute(
            """
            UPDATE incidents
            SET status = 'Respondido', response_at = ?, mttr_seconds = ?,
                response_action = ?
            WHERE id = ? AND status = 'Abierto'
            """,
            (
                to_timestamp(response_at),
                mttr_seconds,
                action,
                incident_id,
            ),
        )
        if update.rowcount == 0:
            db.rollback()
            flash("El incidente ya tiene una respuesta registrada.", "error")
            return redirect(url_for("dashboard"))
        db.commit()
        log_event(
            session["username"],
            "incident_responded",
            f"Incidente #{incident_id}: {action}",
            response_at,
        )
        flash("Respuesta del incidente registrada.", "success")
        return redirect(url_for("dashboard"))

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )

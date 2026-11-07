import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from werkzeug.security import check_password_hash

from app import create_app, to_timestamp, utc_now
from detector import detect_brute_force


class SecurityAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret",
                "DATABASE": str(root / "test.db"),
                "EVENT_LOG": str(root / "eventos.log"),
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def csrf_token(self, path="/login"):
        self.client.get(path)
        with self.client.session_transaction() as session_data:
            return session_data["csrf_token"]

    def register_user(self, username="analista", password="Segura123"):
        token = self.csrf_token("/register")
        return self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": username,
                "email": f"{username}@example.com",
                "password": password,
            },
        )

    def login(self, username="analista", password="Segura123"):
        return self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token(),
                "username": username,
                "password": password,
            },
        )

    def test_registration_hashes_password_and_prevents_duplicates(self):
        response = self.register_user()
        self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            from app import get_db

            user = get_db().execute(
                "SELECT username, password_hash FROM users WHERE username = ?",
                ("analista",),
            ).fetchone()
            self.assertTrue(check_password_hash(user["password_hash"], "Segura123"))
            self.assertNotEqual(user["password_hash"], "Segura123")

        duplicate = self.register_user()
        self.assertEqual(duplicate.status_code, 409)

    def test_registration_rejects_short_password(self):
        response = self.register_user(password="abc123")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"8 y 128", response.data)

    def test_three_failed_logins_create_alert_and_lock_account(self):
        self.register_user()
        for _ in range(3):
            self.login(password="Incorrecta123")

        with self.app.app_context():
            from app import get_db

            db = get_db()
            incident = db.execute(
                "SELECT attempts, mttd_seconds, mttr_seconds, status FROM incidents"
            ).fetchone()
            self.assertEqual(incident["attempts"], 3)
            self.assertGreaterEqual(incident["mttd_seconds"], 0)
            self.assertEqual(incident["mttr_seconds"], 0)
            self.assertEqual(incident["status"], "Respondido")

        blocked = self.login()
        self.assertEqual(blocked.status_code, 302)
        log = Path(self.app.config["EVENT_LOG"]).read_text(encoding="utf-8")
        event_types = [json.loads(line)["event_type"] for line in log.splitlines()]
        self.assertIn("security_alert", event_types)
        self.assertIn("account_blocked", event_types)

    def test_manual_incident_response_records_mttr(self):
        self.register_user()
        self.login()
        token = self.csrf_token("/dashboard")
        occurred_at = (utc_now() - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M")
        report = self.client.post(
            "/incidents",
            data={
                "csrf_token": token,
                "description": "Actividad sospechosa observada",
                "severity": "Alta",
                "occurred_at": occurred_at,
            },
        )
        self.assertEqual(report.status_code, 302)

        token = self.csrf_token("/dashboard")
        response = self.client.post(
            "/incidents/1/respond",
            data={
                "csrf_token": token,
                "response_action": "Se aisló el equipo afectado",
            },
        )
        self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            from app import get_db

            incident = get_db().execute(
                "SELECT status, mttd_seconds, mttr_seconds FROM incidents WHERE id = 1"
            ).fetchone()
            self.assertEqual(incident["status"], "Respondido")
            self.assertGreaterEqual(incident["mttd_seconds"], 0)
            self.assertGreaterEqual(incident["mttr_seconds"], 0)

    def test_detector_measures_time_from_first_failure(self):
        root = Path(self.temp_dir.name)
        event_log = root / "detector.log"
        detected_at = utc_now()
        first_attempt = detected_at - timedelta(seconds=12)
        events = [
            {
                "username": "analista",
                "event_type": "login_failed",
                "occurred_at": to_timestamp(first_attempt + timedelta(seconds=i * 3)),
            }
            for i in range(3)
        ]
        event_log.write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )

        result = detect_brute_force(event_log, "analista", detected_at=detected_at)
        self.assertEqual(result["attempts"], 3)
        self.assertEqual(result["mttd_seconds"], 12)


if __name__ == "__main__":
    unittest.main()

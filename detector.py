import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _parse_timestamp(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def detect_brute_force(
    event_log,
    username,
    detected_at=None,
    threshold=3,
    window_seconds=900,
):
    if threshold < 1:
        raise ValueError("threshold debe ser mayor que cero")
    if window_seconds < 1:
        raise ValueError("window_seconds debe ser mayor que cero")

    detection_time = detected_at or datetime.now(timezone.utc)
    if detection_time.tzinfo is None:
        detection_time = detection_time.replace(tzinfo=timezone.utc)
    detection_time = detection_time.astimezone(timezone.utc)
    window_start = detection_time - timedelta(seconds=window_seconds)

    path = Path(event_log)
    if not path.exists():
        return None

    failures = []
    with path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            event = json.loads(line)
            if (
                event.get("username") == username
                and event.get("event_type") == "login_failed"
            ):
                occurred_at = _parse_timestamp(event["occurred_at"])
                if window_start <= occurred_at <= detection_time:
                    failures.append(occurred_at)

    failures.sort()
    if len(failures) < threshold:
        return None

    relevant_failures = failures[-threshold:]
    first_attempt = relevant_failures[0]
    return {
        "attempts": len(relevant_failures),
        "first_attempt_at": first_attempt.isoformat(),
        "detected_at": detection_time.isoformat(),
        "mttd_seconds": max(0.0, (detection_time - first_attempt).total_seconds()),
    }

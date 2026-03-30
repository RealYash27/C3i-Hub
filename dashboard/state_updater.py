import json
import os
import datetime

BASE_DIR = os.path.dirname(__file__)
STATE_FILE = os.path.join(BASE_DIR, "runtime_state.json")
EVENTS_FILE = os.path.join(BASE_DIR, "events.json")
DEMO_FILE = os.path.join(BASE_DIR, "demo_mode.json")


def _load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def demo_mode_enabled():
    data = _load_json(DEMO_FILE, {})
    return bool(data.get("enabled", False))


def update_state(**kwargs):
    """
    Updates runtime crypto posture (FAIL-OPEN).
    """
    try:
        state = _load_json(STATE_FILE, {})
        state.update(kwargs)
        state["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
        _save_json(STATE_FILE, state)
    except Exception:
        pass


def log_event(category, event, result, severity="INFO"):
    """
    Logs a security-relevant event for dashboard.
    """
    try:
        events = _load_json(EVENTS_FILE, [])

        entry = {
            "time": datetime.datetime.utcnow().isoformat() + "Z",
            "category": category,
            "event": event,
            "result": result,
            "severity": severity
        }

        events.append(entry)
        _save_json(EVENTS_FILE, events)

        # Demo mode: auto-reset failures
        if demo_mode_enabled() and severity in ("HIGH", "CRITICAL"):
            update_state(status="normal", last_failure=None)

    except Exception:
        pass

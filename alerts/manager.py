from collections import deque
import threading


MAX_ALERTS = 500

alerts = deque(maxlen=MAX_ALERTS)

alerts_lock = threading.Lock()


def add_alert(alert):
    with alerts_lock:
        alerts.appendleft(alert)


def get_alerts():
    with alerts_lock:
        return list(alerts)


def clear_alerts():
    with alerts_lock:
        alerts.clear()
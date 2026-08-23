import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

OUTPUT = Path(__file__).resolve().parents[1] / "data" / "authentication_logs.csv"

USERS = [
    "admin", "daniyal", "jsmith", "achen", "mgarcia",
    "slee", "rpatel", "service_backup", "helpdesk", "finance01"
]

DEVICES = ["windows", "linux", "macos"]

# Documentation/private IP ranges so the project does not rely on real-world hosts.
NORMAL_IPS = [
    "10.0.0.12", "10.0.0.27", "10.0.1.18", "192.168.1.14",
    "192.168.1.33", "172.16.0.20", "172.16.1.44"
]

SUSPICIOUS_IPS = [
    "192.0.2.10", "192.0.2.25",
    "198.51.100.8", "198.51.100.41",
    "203.0.113.7", "203.0.113.80"
]

COUNTRIES = ["Canada", "United States", "United Kingdom", "Germany", "Japan"]

FIELDS = [
    "timestamp",
    "username",
    "source_ip",
    "country",
    "event_type",
    "status",
    "device",
    "attack_type"
]


def random_timestamp(start, end):
    total_seconds = int((end - start).total_seconds())
    return start + timedelta(seconds=random.randint(0, total_seconds))


def normal_event(start, end):
    return {
        "timestamp": random_timestamp(start, end).isoformat(sep=" "),
        "username": random.choice(USERS),
        "source_ip": random.choice(NORMAL_IPS),
        "country": "Canada",
        "event_type": "login",
        "status": random.choices(["success", "failed"], weights=[96, 4], k=1)[0],
        "device": random.choice(DEVICES),
        "attack_type": "normal"
    }


def brute_force_events(start):
    events = []
    attacker_ip = "198.51.100.41"
    target = "admin"

    for i in range(30):
        events.append({
            "timestamp": (start + timedelta(seconds=i * 8)).isoformat(sep=" "),
            "username": target,
            "source_ip": attacker_ip,
            "country": "Germany",
            "event_type": "login",
            "status": "failed",
            "device": "linux",
            "attack_type": "brute_force"
        })

    # A success after many failures creates an interesting investigation case.
    events.append({
        "timestamp": (start + timedelta(seconds=245)).isoformat(sep=" "),
        "username": target,
        "source_ip": attacker_ip,
        "country": "Germany",
        "event_type": "login",
        "status": "success",
        "device": "linux",
        "attack_type": "brute_force"
    })
    return events


def credential_stuffing_events(start):
    events = []
    attacker_ip = "203.0.113.80"

    for i, user in enumerate(USERS):
        for attempt in range(3):
            events.append({
                "timestamp": (
                    start + timedelta(seconds=(i * 30) + attempt * 4)
                ).isoformat(sep=" "),
                "username": user,
                "source_ip": attacker_ip,
                "country": "United States",
                "event_type": "login",
                "status": "failed",
                "device": "windows",
                "attack_type": "credential_stuffing"
            })
    return events


def suspicious_login_events(start):
    events = []

    cases = [
        ("finance01", "192.0.2.25", "Japan", "windows"),
        ("helpdesk", "203.0.113.7", "United Kingdom", "linux"),
        ("service_backup", "192.0.2.10", "Germany", "linux"),
    ]

    for i, (user, ip, country, device) in enumerate(cases):
        events.append({
            "timestamp": (start + timedelta(minutes=i * 13)).isoformat(sep=" "),
            "username": user,
            "source_ip": ip,
            "country": country,
            "event_type": "login",
            "status": "success",
            "device": device,
            "attack_type": "suspicious_login"
        })

    return events


def generate_logs(normal_count=50000):
    start = datetime(2026, 8, 1, 0, 0, 0)
    end = datetime(2026, 8, 20, 23, 59, 59)

    events = [normal_event(start, end) for _ in range(normal_count)]

    events += brute_force_events(datetime(2026, 8, 12, 2, 15, 0))
    events += credential_stuffing_events(datetime(2026, 8, 15, 3, 5, 0))
    events += suspicious_login_events(datetime(2026, 8, 18, 1, 30, 0))

    events.sort(key=lambda event: event["timestamp"])

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(events)

    print(f"Created {len(events):,} authentication events.")
    print(f"Saved to: {OUTPUT}")


if __name__ == "__main__":
    generate_logs()

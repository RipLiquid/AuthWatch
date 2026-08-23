import csv
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV_FILE = ROOT / "data" / "authentication_logs.csv"
DB_FILE = ROOT / "data" / "authwatch.db"

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS security_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    username TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    country TEXT NOT NULL,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL,
    device TEXT NOT NULL,
    attack_type TEXT NOT NULL
);
"""


def build_database():
    if not CSV_FILE.exists():
        raise FileNotFoundError(
            "authentication_logs.csv was not found. Run generate_logs.py first."
        )

    with sqlite3.connect(DB_FILE) as connection:
        cursor = connection.cursor()

        cursor.execute("DROP TABLE IF EXISTS security_events;")
        cursor.execute(CREATE_TABLE)

        with CSV_FILE.open("r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            rows = [
                (
                    row["timestamp"],
                    row["username"],
                    row["source_ip"],
                    row["country"],
                    row["event_type"],
                    row["status"],
                    row["device"],
                    row["attack_type"],
                )
                for row in reader
            ]

        cursor.executemany(
            """
            INSERT INTO security_events (
                timestamp,
                username,
                source_ip,
                country,
                event_type,
                status,
                device,
                attack_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            rows,
        )

        connection.commit()

        count = cursor.execute(
            "SELECT COUNT(*) FROM security_events;"
        ).fetchone()[0]

    print(f"Loaded {count:,} events into {DB_FILE}")


if __name__ == "__main__":
    build_database()

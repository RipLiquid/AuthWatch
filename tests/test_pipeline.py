import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB_FILE = ROOT / "data" / "authwatch.db"


class TestAuthWatchPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(
            [sys.executable, "src/generate_logs.py"],
            cwd=ROOT,
            check=True
        )

        subprocess.run(
            [sys.executable, "src/init_db.py"],
            cwd=ROOT,
            check=True
        )

    def test_total_event_count(self):
        with sqlite3.connect(DB_FILE) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM security_events;"
            ).fetchone()[0]

        self.assertEqual(count, 50064)

    def test_brute_force_detection(self):
        with sqlite3.connect(DB_FILE) as connection:
            result = connection.execute("""
                SELECT
                    source_ip,
                    username,
                    COUNT(*) AS failed_attempts
                FROM security_events
                WHERE status = 'failed'
                  AND timestamp >= '2026-08-12 02:00:00'
                  AND timestamp < '2026-08-12 03:00:00'
                GROUP BY source_ip, username
                HAVING COUNT(*) >= 5
                ORDER BY failed_attempts DESC
                LIMIT 1;
            """).fetchone()

        self.assertIsNotNone(result)
        self.assertEqual(result[0], "198.51.100.41")
        self.assertEqual(result[1], "admin")
        self.assertEqual(result[2], 30)

    def test_credential_stuffing_detection(self):
        with sqlite3.connect(DB_FILE) as connection:
            result = connection.execute("""
                SELECT
                    source_ip,
                    COUNT(DISTINCT username) AS targeted_accounts,
                    COUNT(*) AS failed_attempts
                FROM security_events
                WHERE status = 'failed'
                  AND timestamp >= '2026-08-15 03:00:00'
                  AND timestamp < '2026-08-15 04:00:00'
                GROUP BY source_ip
                HAVING COUNT(DISTINCT username) >= 5
                ORDER BY targeted_accounts DESC
                LIMIT 1;
            """).fetchone()

        self.assertIsNotNone(result)
        self.assertEqual(result[0], "203.0.113.80")
        self.assertEqual(result[1], 10)
        self.assertEqual(result[2], 30)

    def test_account_compromise_sequence(self):
        with sqlite3.connect(DB_FILE) as connection:
            result = connection.execute("""
                SELECT COUNT(*)
                FROM security_events
                WHERE source_ip = '198.51.100.41'
                  AND username = 'admin'
                  AND status = 'success'
                  AND timestamp = '2026-08-12 02:19:05';
            """).fetchone()[0]

        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
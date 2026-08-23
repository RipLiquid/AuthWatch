import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_FILE = ROOT / "data" / "authwatch.db"

connection = sqlite3.connect(DB_FILE)
cursor = connection.cursor()


print("\n=== AUTHWATCH SECURITY ANALYSIS ===")


# -------------------------------------------------
# Detection 1: Total events
# -------------------------------------------------

cursor.execute("""
SELECT COUNT(*)
FROM security_events;
""")

total_events = cursor.fetchone()[0]

print(f"\nTotal authentication events: {total_events:,}")


# -------------------------------------------------
# Detection 2: Brute-force attacks
# -------------------------------------------------

cursor.execute("""
SELECT
    strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_bucket,
    source_ip,
    username,
    COUNT(*) AS failed_attempts
FROM security_events
WHERE status = 'failed'
GROUP BY hour_bucket, source_ip, username
HAVING COUNT(*) >= 5
ORDER BY failed_attempts DESC;
""")

results = cursor.fetchall()

print("\n=== POSSIBLE BRUTE-FORCE ATTACKS ===")

for row in results:
    hour, ip, username, attempts = row

    print(
        f"Time: {hour} | "
        f"IP: {ip} | "
        f"User: {username} | "
        f"Failed Attempts: {attempts}"
    )


# -------------------------------------------------
# Detection 3: Credential stuffing
# -------------------------------------------------

cursor.execute("""
SELECT
    strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_bucket,
    source_ip,
    COUNT(DISTINCT username) AS targeted_accounts,
    COUNT(*) AS failed_attempts
FROM security_events
WHERE status = 'failed'
GROUP BY hour_bucket, source_ip
HAVING COUNT(DISTINCT username) >= 5
ORDER BY targeted_accounts DESC;
""")

results = cursor.fetchall()

print("\n=== POSSIBLE CREDENTIAL-STUFFING ATTACKS ===")

for row in results:
    hour, ip, accounts, attempts = row

    print(
        f"Time: {hour} | "
        f"IP: {ip} | "
        f"Accounts Targeted: {accounts} | "
        f"Failed Attempts: {attempts}"
    )


# -------------------------------------------------
# Detection 4: Failed attempts followed by success
# -------------------------------------------------

cursor.execute("""
WITH failed_groups AS (
    SELECT
        strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_bucket,
        source_ip,
        username,
        COUNT(*) AS failed_attempts,
        MAX(timestamp) AS last_failure
    FROM security_events
    WHERE status = 'failed'
    GROUP BY hour_bucket, source_ip, username
    HAVING COUNT(*) >= 5
)

SELECT
    failed_groups.hour_bucket,
    failed_groups.source_ip,
    failed_groups.username,
    failed_groups.failed_attempts,
    failed_groups.last_failure,
    MIN(security_events.timestamp) AS successful_login
FROM failed_groups

JOIN security_events
    ON security_events.source_ip = failed_groups.source_ip
    AND security_events.username = failed_groups.username
    AND security_events.status = 'success'
    AND security_events.timestamp > failed_groups.last_failure
    AND strftime(
        '%Y-%m-%d %H:00:00',
        security_events.timestamp
    ) = failed_groups.hour_bucket

GROUP BY
    failed_groups.hour_bucket,
    failed_groups.source_ip,
    failed_groups.username,
    failed_groups.failed_attempts,
    failed_groups.last_failure;
""")

results = cursor.fetchall()

print("\n=== POSSIBLE ACCOUNT COMPROMISE ===")

for row in results:
    hour, ip, username, failures, last_failure, success_time = row

    print(
        f"IP: {ip} | "
        f"User: {username} | "
        f"Failed Attempts: {failures} | "
        f"Last Failure: {last_failure} | "
        f"Successful Login: {success_time}"
    )

connection.close()
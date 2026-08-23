-- AUTHWATCH DETECTION QUERIES
-- Important: detections do NOT use the synthetic attack_type ground-truth label.

-- 1. Count all authentication events.
SELECT COUNT(*) AS total_events
FROM security_events;


-- 2. Failed logins by source IP.
SELECT
    source_ip,
    COUNT(*) AS failed_attempts
FROM security_events
WHERE status = 'failed'
GROUP BY source_ip
ORDER BY failed_attempts DESC;


-- 3. Potential brute-force activity:
-- 5+ failures against the same account, from the same IP, within one hour.
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


-- 4. Potential credential stuffing:
-- one IP fails against 5+ distinct accounts within one hour.
SELECT
    strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_bucket,
    source_ip,
    COUNT(DISTINCT username) AS targeted_accounts,
    COUNT(*) AS failed_attempts
FROM security_events
WHERE status = 'failed'
GROUP BY hour_bucket, source_ip
HAVING COUNT(DISTINCT username) >= 5
ORDER BY targeted_accounts DESC, failed_attempts DESC;


-- 5. Successful logins from outside Canada.
SELECT
    timestamp,
    username,
    source_ip,
    country,
    device
FROM security_events
WHERE status = 'success'
  AND country <> 'Canada'
ORDER BY timestamp;


-- 6. Ground-truth validation ONLY.
-- This proves which attacks were injected into our synthetic dataset.
-- Never use attack_type as part of a detection rule.
SELECT
    attack_type,
    COUNT(*) AS event_count
FROM security_events
GROUP BY attack_type
ORDER BY event_count DESC;

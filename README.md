# AuthWatch

**Security Threat Detection & SIEM Analytics Platform**

AuthWatch is a cybersecurity analytics project built with **Python, SQL, SQLite, Splunk, and SPL**. It generates synthetic authentication logs, stores and analyzes them using SQL, and ingests the events into Splunk to detect suspicious authentication behaviour and visualize security activity through a SOC-style dashboard.

The project demonstrates practical experience with **security log analysis, threat detection, event correlation, SIEM analytics, SQL querying, SPL, and security monitoring**.

---

## Dashboard

![AuthWatch SOC Dashboard](images/AuthWatch SOC Dashboard.png)

The Splunk Dashboard Studio implementation provides a centralized view of authentication activity, failed login trends, suspicious source IPs, and detected attack patterns.

---

## Features

* Generates **50,064 synthetic authentication events**
* Stores authentication data in a SQLite database
* Analyzes authentication activity using SQL
* Ingests structured authentication logs into Splunk
* Uses custom **SPL threat-detection queries**
* Detects brute-force login attempts
* Detects credential-stuffing activity
* Correlates repeated failed logins with subsequent successful authentication
* Visualizes authentication activity over time
* Identifies failed-login source IPs
* Provides a SOC-style security monitoring dashboard
* Uses behaviour-based detection instead of relying on predefined attack labels

---

## Technologies

* **Python**
* **SQL**
* **SQLite**
* **Splunk Enterprise**
* **Splunk Search Processing Language (SPL)**
* **Git**

---

## Project Architecture

```text
                 AuthWatch
                     |
              Python Generator
                     |
                     v
          authentication_logs.csv
                /           \
               /             \
              v               v
          SQLite             Splunk
             |                  |
             v                  v
            SQL                SPL
             |                  |
             v                  v
       Threat Detection    Threat Detection
               \             /
                \           /
                 v         v
              Security Analysis
                     |
                     v
              SOC Dashboard
```

---

## Project Structure

```text
AuthWatch/
├── images/
│   └── authwatch_soc_dashboard.png
├── data/
│   ├── authentication_logs.csv
│   └── authwatch.db
├── sql/
│   └── detection_queries.sql
├── src/
│   ├── generate_logs.py
│   ├── init_db.py
│   └── run_detections.py
├── .gitignore
└── README.md
```

The generated `.csv` and `.db` files are excluded from version control and can be recreated locally using the included scripts.

---

# Dataset

AuthWatch generates more than 50,000 authentication events representing a combination of normal and suspicious user activity.

Each event contains:

```text
timestamp
username
source_ip
country
event_type
status
device
attack_type
```

Example:

```text
2026-08-12 02:15:00,admin,198.51.100.41,Germany,login,failed,linux,brute_force
```

The `attack_type` field exists only as **ground truth for validating the synthetic dataset**.

The actual SQL and SPL threat-detection logic does **not** use the `attack_type` field to determine whether activity is suspicious.

This forces AuthWatch to identify attacks based on observable authentication behaviour.

---

# Threat Detection

## 1. Brute-Force Detection

AuthWatch identifies repeated failed authentication attempts against the same account from the same source IP within a one-hour period.

### Detection condition

```text
Same source IP
        +
Same username
        +
5 or more failed logins
        +
Within one hour
```

Detected simulated attack:

```text
Detection Time: 2026-08-12 02:00:00
Source IP:      198.51.100.41
Username:       admin
Failed Attempts: 30
```

### SPL

```spl
index=authwatch status="failed"
| bin _time span=1h
| stats count AS failed_attempts BY _time source_ip username
| where failed_attempts >= 5
| eval detection_time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table detection_time source_ip username failed_attempts
| sort - failed_attempts
```

---

## 2. Credential-Stuffing Detection

Credential stuffing differs from brute force because a single source attempts to authenticate against **multiple user accounts** rather than repeatedly targeting one account.

### Detection condition

```text
Same source IP
        +
5 or more distinct usernames
        +
Failed authentication attempts
        +
Within one hour
```

Detected simulated activity:

```text
Detection Time:   2026-08-15 03:00:00
Source IP:        203.0.113.80
Accounts Targeted: 10
Failed Attempts:   30
```

### SPL

```spl
index=authwatch status="failed"
| bin _time span=1h
| stats dc(username) AS targeted_accounts count AS failed_attempts BY _time source_ip
| where targeted_accounts >= 5
| eval detection_time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table detection_time source_ip targeted_accounts failed_attempts
| sort - targeted_accounts
```

---

## 3. Possible Account Compromise

AuthWatch performs event correlation to identify repeated authentication failures followed by a successful login from the same source IP against the same user account.

Detected activity:

```text
Source IP:       198.51.100.41
Username:        admin
Failed Attempts: 30

Last Failure:
2026-08-12 02:18:52

Successful Login:
2026-08-12 02:19:05
```

The successful login occurred only **13 seconds after the final failed attempt**.

This produces the behavioural sequence:

```text
30 Failed Authentication Attempts
               |
               v
       Same IP + Username
               |
               v
       Successful Login
               |
               v
   Possible Account Compromise
```

### SPL

```spl
index=authwatch
| eval event_time=_time
| bin _time span=1h
| stats
    count(eval(status="failed")) AS failed_attempts
    max(eval(if(status="failed", event_time, null()))) AS last_failure
    min(eval(if(status="success", event_time, null()))) AS first_success
    BY _time source_ip username
| where failed_attempts >= 5
    AND isnotnull(first_success)
    AND first_success > last_failure
| eval detection_time=strftime(_time,"%Y-%m-%d %H:%M:%S"),
       last_failure=strftime(last_failure,"%Y-%m-%d %H:%M:%S"),
       first_success=strftime(first_success,"%Y-%m-%d %H:%M:%S")
| table detection_time source_ip username failed_attempts last_failure first_success
| sort - failed_attempts
```

---

# SOC Dashboard

The AuthWatch SOC Dashboard was created using **Splunk Dashboard Studio**.

It contains:

### Authentication Overview

* Total authentication events: **50,064**
* Successful logins: **48,008**
* Failed logins: **2,056**

### Authentication Activity

The dashboard visualizes:

* Total authentication activity over time
* Failed authentication activity over time
* Successful versus failed authentication trends

### Failed Login Sources

A horizontal bar chart compares failed authentication volume across source IP addresses.

This demonstrates an important security-monitoring concept: a high raw event count alone does not necessarily indicate an attack.

Normal internal source IPs accumulated more failures over the full dataset than the simulated attacker IPs.

The behavioural detection rules therefore use:

* Time windows
* User correlation
* Source-IP correlation
* Distinct-account counts

to reduce false positives.

### Threat Detection Panels

The dashboard includes dedicated tables for:

* Brute-force detection
* Credential-stuffing detection
* Possible account compromise

---

# Running AuthWatch

## 1. Clone the repository

```bash
git clone https://github.com/RipLiquid/AuthWatch.git
cd AuthWatch
```

---

## 2. Generate the authentication dataset

```bash
python src/generate_logs.py
```

Expected:

```text
Created 50,064 authentication events.
```

This generates:

```text
data/authentication_logs.csv
```

---

## 3. Create the SQLite database

```bash
python src/init_db.py
```

Expected:

```text
Loaded 50,064 events into data/authwatch.db
```

---

## 4. Run the SQL threat detections

```bash
python src/run_detections.py
```

Example output:

```text
=== AUTHWATCH SECURITY ANALYSIS ===

Total authentication events: 50,064

=== POSSIBLE BRUTE-FORCE ATTACKS ===
IP: 198.51.100.41
User: admin
Failed Attempts: 30

=== POSSIBLE CREDENTIAL-STUFFING ATTACKS ===
IP: 203.0.113.80
Accounts Targeted: 10
Failed Attempts: 30

=== POSSIBLE ACCOUNT COMPROMISE ===
IP: 198.51.100.41
User: admin
Failed Attempts: 30
```

---

# Splunk Configuration

The generated CSV was ingested into Splunk using:

```text
Index:
authwatch

Source Type:
authwatch:authentication
```

Splunk automatically extracts fields including:

```text
timestamp
username
source_ip
country
event_type
status
device
attack_type
```

The event timestamp is mapped to Splunk's `_time` field, allowing time-windowed SPL detections and time-series visualization.

---

# SQL Analysis

AuthWatch also implements detection logic directly against the SQLite database.

Example brute-force query:

```sql
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
```

This allows the same authentication dataset to be analyzed through both:

```text
SQL / SQLite
     and
Splunk / SPL
```

---

# Security Concepts Demonstrated

AuthWatch demonstrates practical experience with:

* Security Information and Event Management (SIEM)
* Authentication log analysis
* Security monitoring
* Threat detection
* Threat hunting
* Brute-force detection
* Credential-stuffing detection
* Event correlation
* Behaviour-based detection
* Authentication anomaly analysis
* SQL aggregation
* SPL queries
* Time-window analysis
* Data preprocessing
* Structured log ingestion
* Security dashboards
* Incident investigation concepts
* False-positive reduction

---

# Synthetic Data and Safety

All authentication activity used by AuthWatch is synthetic and was generated specifically for educational and portfolio purposes.

No real user accounts, credentials, enterprise systems, or attack traffic are included.

The project uses private and documentation-only IP address ranges to avoid representing real-world attack infrastructure.

---

# Results

AuthWatch successfully processed:

```text
50,064 authentication events
```

and identified:

```text
Brute Force
198.51.100.41 → admin
30 failed attempts

Credential Stuffing
203.0.113.80
10 accounts targeted
30 failed attempts

Possible Account Compromise
198.51.100.41 → admin
30 failures followed by successful authentication
```

The same attack behaviours were detected using both **SQL-based analytics and Splunk SPL**.

---

# Future Improvements

Potential future enhancements include:

* Additional authentication attack scenarios
* Impossible-travel detection
* Account lockout detection
* Privileged-account monitoring
* Risk scoring
* Detection severity levels
* Live log ingestion
* Automated alerting
* Additional SOC dashboard visualizations
* Integration with additional security log sources

---

## Project Status

**Current Version: Complete Security Analytics Pipeline**

Completed:

* Synthetic authentication dataset generation
* Python preprocessing
* SQLite database integration
* SQL threat detection
* Brute-force detection
* Credential-stuffing detection
* Account-compromise correlation
* Splunk log ingestion
* SPL detection rules
* Saved Splunk detection reports
* Authentication trend visualization
* Source-IP analysis
* Splunk Dashboard Studio SOC dashboard

# AuthWatch

AuthWatch is a cybersecurity log-analysis project built with Python, SQL, and SQLite. It generates synthetic authentication data and analyzes login activity to identify suspicious behaviour such as brute-force attacks, credential stuffing, and possible account compromise.

The project is designed to demonstrate practical experience with security log analysis, threat detection, SQL querying, event correlation, and security monitoring concepts.

## Features

* Generates more than 50,000 synthetic authentication events
* Stores authentication logs in a SQLite database
* Detects brute-force login activity
* Detects credential-stuffing activity
* Correlates repeated failed logins with subsequent successful authentication
* Analyzes activity by username, source IP, country, device, and login status
* Uses behavioural detection rather than predefined attack labels
* Keeps generated datasets and databases out of version control

## Technologies

* Python
* SQL
* SQLite
* Git

## Project Structure

```text
AuthWatch/
├── data/
│   ├── authentication_logs.csv   # Generated locally
│   └── authwatch.db              # Generated locally
├── sql/
│   └── detection_queries.sql
├── src/
│   ├── generate_logs.py
│   ├── init_db.py
│   └── run_detections.py
├── .gitignore
└── README.md
```

Generated files inside the `data` directory are excluded from Git because they can be recreated using the included scripts.

## How It Works

AuthWatch follows a simple security analytics pipeline:

```text
Synthetic Authentication Events
            |
            v
    Python Log Generator
            |
            v
 authentication_logs.csv
            |
            v
        SQLite
            |
            v
      SQL Analysis
            |
            v
     Threat Detection
```

The generated dataset contains both normal authentication traffic and simulated suspicious activity.

The detection logic does not rely on the `attack_type` field to determine whether activity is malicious. Instead, AuthWatch analyzes behavioural patterns in the authentication data.

## Dataset

Each generated authentication event contains fields such as:

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

The `attack_type` field acts only as ground truth for validating the synthetic dataset. Detection queries identify suspicious activity based on observable authentication behaviour.

## Detection 1: Brute-Force Activity

AuthWatch searches for repeated failed authentication attempts against the same account from the same source IP within a one-hour period.

Detection logic:

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

The generated dataset produces a simulated attack with:

```text
Source IP: 198.51.100.41
Username: admin
Failed Attempts: 30
```

## Detection 2: Credential Stuffing

Credential stuffing differs from a traditional brute-force attack because one source attempts to authenticate against multiple accounts.

AuthWatch identifies source IP addresses generating failed authentication attempts against at least five distinct users within the same hour.

Example detection:

```text
Source IP: 203.0.113.80
Accounts Targeted: 10
Failed Attempts: 30
```

## Detection 3: Possible Account Compromise

AuthWatch also performs event correlation to identify cases where repeated authentication failures are followed by a successful login from the same source IP and against the same user account.

Example:

```text
30 failed login attempts
        |
        v
Same IP and username
        |
        v
Successful login
        |
        v
Possible Account Compromise
```

This type of correlation can help identify situations where an attacker may have eventually obtained valid credentials.

## Running the Project

### 1. Clone the repository

```bash
git clone https://github.com/RipLiquid/AuthWatch.git
cd AuthWatch
```

### 2. Generate authentication logs

```bash
python src/generate_logs.py
```

Expected output:

```text
Created 50,064 authentication events.
```

This creates:

```text
data/authentication_logs.csv
```

### 3. Create the SQLite database

```bash
python src/init_db.py
```

Expected output:

```text
Loaded 50,064 events into data/authwatch.db
```

### 4. Run the threat detections

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
User: admin
Failed Attempts: 30
Successful Login Detected
```

## Security Concepts Demonstrated

This project demonstrates several cybersecurity and data-analysis concepts:

* Authentication log analysis
* Threat detection
* Brute-force detection
* Credential-stuffing detection
* Event correlation
* Security monitoring
* Behaviour-based detection
* Structured data preprocessing
* SQL aggregation
* Time-window analysis
* Incident investigation concepts

## Synthetic Data

All authentication activity in this repository is synthetic and created specifically for educational and portfolio purposes.

Private and documentation-only IP address ranges are used so that the dataset does not represent actual hosts or real attack traffic.

## Roadmap

Future versions of AuthWatch will expand the project with:

* Splunk log ingestion
* SPL threat-detection queries
* SIEM-based event correlation
* Security dashboards and visualizations
* Threat-monitoring reports
* Additional authentication attack scenarios

## Project Status

**Current Version:** Python + SQL threat-detection pipeline

Completed:

* Synthetic authentication dataset generation
* SQLite database integration
* Brute-force detection
* Credential-stuffing detection
* Possible account-compromise detection
* Event correlation

Planned:

* Splunk integration
* SPL detection rules
* SOC-style security dashboard

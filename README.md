# User and Entity Behavior Analytics (UEBA) POC

A comprehensive proof-of-concept for User and Entity Behavior Analytics (UEBA) on Databricks, detecting anomalous user behavior through statistical analysis, machine learning, and behavioral baselining.

## Table of Contents

- [Overview](#overview)
- [What is UEBA?](#what-is-ueba)
- [Architecture](#architecture)
- [Data Sources](#data-sources)
- [Detection Techniques](#detection-techniques)
- [Models Used](#models-used)
- [Setup Instructions](#setup-instructions)
- [Execution Steps](#execution-steps)
- [Sample Outputs](#sample-outputs)
- [Anomaly Types Detected](#anomaly-types-detected)
- [Tuning and Customization](#tuning-and-customization)

---

## Overview

This UEBA POC analyzes network and process activity to detect anomalous user behavior that may indicate security threats such as:

- Data exfiltration attempts
- Lateral movement
- Privilege escalation
- Insider threats
- Account compromise
- After-hours suspicious activity

The system uses a combination of statistical methods and machine learning to establish behavioral baselines and detect deviations from normal patterns.

---

## What is UEBA?

**User and Entity Behavior Analytics (UEBA)** is a cybersecurity process that uses algorithms and machine learning to detect anomalies in the behavior of users and other entities (devices, applications, networks) on a network.

### Key Concepts

1. **Behavioral Baseline**: Understanding what "normal" looks like for each user
2. **Peer Group Analysis**: Comparing users with similar roles and behaviors
3. **Anomaly Detection**: Identifying deviations from normal patterns
4. **Risk Scoring**: Aggregating multiple indicators into a composite risk score
5. **Context-Aware Detection**: Considering time, location, and peer group context

### Why UEBA?

Traditional security tools (firewalls, antivirus, IDS) focus on **known threats** (signatures, rules). UEBA focuses on **unknown threats** by detecting unusual behavior, even if the specific attack is novel.

**Example**: A user who typically accesses 5-10 internal servers suddenly connects to 50 external IPs and transfers 10GB of data at 3 AM. Even if each individual connection is "allowed," the pattern is anomalous and worth investigating.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Data Sources                              │
├─────────────────────────────────────────────────────────────────┤
│  Network Activity          │        Process Activity             │
│  (Firewall Logs)          │        (EDR Logs)                   │
│  - Connections            │        - Process Executions          │
│  - Traffic Volumes        │        - Command Lines               │
│  - Destinations           │        - File Hashes                 │
└───────────────┬────────────┴─────────────┬───────────────────────┘
                │                          │
                ▼                          ▼
       ┌────────────────────────────────────────────┐
       │         Delta Lake Storage                  │
       │  - network_activity table                   │
       │  - process_activity table                   │
       └─────────────┬──────────────────────────────┘
                     │
                     ▼
       ┌────────────────────────────────────────────┐
       │      Feature Engineering Layer              │
       │  - Daily aggregations                       │
       │  - User-level features                      │
       │  - Temporal features                        │
       │  - Diversity metrics                        │
       └─────────────┬──────────────────────────────┘
                     │
          ┌──────────┴──────────┐
          │                     │
          ▼                     ▼
┌──────────────────┐  ┌──────────────────────┐
│ Baseline Period  │  │  Analysis Period     │
│ (21 days)        │  │  (7 days)            │
│ - Calculate avg  │  │  - Compare to        │
│ - Calculate std  │  │    baseline          │
│ - Establish norm │  │  - Calculate Z-scores│
└──────────────────┘  └───────────┬──────────┘
                                  │
                                  ▼
                     ┌────────────────────────────────────┐
                     │   Peer Group Analysis              │
                     │   (K-means Clustering)             │
                     │   - Group similar users            │
                     │   - Compare within peer groups     │
                     └─────────────┬──────────────────────┘
                                   │
                                   ▼
                     ┌────────────────────────────────────┐
                     │   Anomaly Detection                │
                     │   - Statistical (Z-scores)         │
                     │   - Distance from peer group       │
                     │   - Temporal patterns              │
                     │   - Volume spikes                  │
                     └─────────────┬──────────────────────┘
                                   │
                                   ▼
                     ┌────────────────────────────────────┐
                     │   Risk Scoring                     │
                     │   - Network risk: 60%              │
                     │   - Process risk: 40%              │
                     │   - Composite risk score           │
                     └─────────────┬──────────────────────┘
                                   │
                                   ▼
                     ┌────────────────────────────────────┐
                     │   Detection Findings               │
                     │   - Critical, High, Medium, Low    │
                     │   - Actionable alerts              │
                     │   - Evidence and context           │
                     └────────────────────────────────────┘
```

---

## Data Sources

### 1. Network Activity

**Source**: Firewall logs (Palo Alto Networks format)

**Key Fields**:
- `user`: Username performing the action
- `event_time`: Timestamp of the network connection
- `src_ip`, `dest_ip`: Source and destination IP addresses
- `dest_host`: Destination hostname/domain
- `dest_port`: Destination port
- `app_name`: Application protocol (ssl, http, ssh, etc.)
- `bytes_in`, `bytes_out`: Data transferred
- `session_duration`: Connection duration

**Behavioral Indicators**:
- Volume: Total events, bytes transferred
- Diversity: Unique destinations, ports, applications
- Temporal: Active hours, first/last activity time
- Geographic: New locations, unusual destinations

### 2. Process Activity

**Source**: Endpoint Detection and Response logs (CrowdStrike Falcon format)

**Key Fields**:
- `user`: User account executing the process
- `event_time`: Process execution timestamp
- `process_name`: Executable name
- `process_path`: Full file path
- `cmd_line`: Command line arguments
- `parent_process`: Parent process name
- `md5_hash`, `sha256_hash`: File hashes
- `host`: Hostname where process executed

**Behavioral Indicators**:
- Volume: Total process executions
- Diversity: Unique processes, paths
- Admin processes: PowerShell, cmd, sudo, ssh
- Suspicious processes: Known attack tools

---

## Detection Techniques

### 1. Baseline Establishment (21 days)

For each user, calculate **normal behavior** over a baseline period:

```python
# Example: Network baseline
- Average daily events: 150 ± 30
- Average data transfer: 500 MB ± 100 MB
- Typical work hours: 9 AM - 6 PM
- Common destinations: 10-15 unique IPs
- Typical applications: ssl, web-browsing
```

**Why 21 days?**
- Captures weekly patterns (3 weeks)
- Reduces impact of outliers
- Balances recency with stability

### 2. Peer Group Analysis (K-means Clustering)

Users are grouped into peer groups based on similar behavior patterns:

```
Peer Group 1 (Developers): High volume, diverse destinations, GitHub, npm
Peer Group 2 (Analysts): Moderate volume, business intelligence tools
Peer Group 3 (Admins): Very high volume, internal systems, SSH
Peer Group 4 (Executives): Low volume, email, office applications
Peer Group 5 (Service Accounts): Consistent patterns, automated
```

**Why Peer Groups?**
- Users in different roles have different "normal" behaviors
- Comparing an admin to a developer would generate false positives
- Peer groups provide context-aware detection

### 3. Statistical Anomaly Detection (Z-scores)

For each metric, calculate how many standard deviations the current value is from the baseline:

```python
Z-score = (Current Value - Baseline Mean) / Baseline Std Dev

# Thresholds:
Z > 2.5: Potential anomaly
Z > 3.0: Strong anomaly
Z > 4.0: Very strong anomaly
```

**Metrics Analyzed**:
- Event volume
- Data transfer (bytes)
- Unique destinations
- Active hours
- Process executions

### 4. Temporal Anomaly Detection

Detect unusual timing patterns:

```python
# After-hours anomaly
if first_activity < (typical_start - 2 hours) OR
   last_activity > (typical_end + 2 hours):
    anomaly_flag = True
```

### 5. Composite Risk Scoring

Multiple anomaly scores are combined into a single risk score:

```python
Network Risk Score = (
    event_volume_zscore * 0.2 +
    bytes_out_zscore * 0.4 +      # Data exfiltration is weighted higher
    destinations_zscore * 0.2 +
    hosts_zscore * 0.1 +
    after_hours_anomaly * 0.1
) / 3.0  # Normalize to 0-1 scale

Process Risk Score = (
    process_volume_zscore * 0.3 +
    unique_processes_zscore * 0.2 +
    admin_processes_zscore * 0.3 +
    suspicious_process_flag * 0.2
) / 3.0

Combined Risk Score = Network_Risk * 0.6 + Process_Risk * 0.4
```

**Risk Levels**:
- `CRITICAL`: Risk Score >= 0.85
- `HIGH`: Risk Score >= 0.70
- `MEDIUM`: Risk Score >= 0.50
- `LOW`: Risk Score < 0.50

---

## Models Used

### 1. K-means Clustering (Peer Groups)

**Purpose**: Group users with similar behavior patterns

**Features**:
- Average daily events
- Average daily bytes transferred
- Average unique destinations
- Average active hours
- Average process executions
- Average unique processes

**Algorithm**: scikit-learn / Spark MLlib K-means
- K = 5 (number of peer groups)
- Features are standardized (mean=0, std=1)
- Distance metric: Euclidean

**Output**: Each user is assigned to a peer group (0-4)

### 2. Statistical Outlier Detection (Z-scores)

**Purpose**: Detect values that deviate significantly from baseline

**Method**: Standard score (Z-score)
```
Z = (X - μ) / σ
where:
  X = current value
  μ = baseline mean
  σ = baseline standard deviation
```

**Advantages**:
- Simple, interpretable
- No training required
- Works well for normally distributed data
- Fast computation

**Limitations**:
- Assumes normal distribution
- Can be sensitive to outliers in baseline

### 3. Ensemble Scoring

**Purpose**: Combine multiple weak signals into a strong detection

**Method**: Weighted average of normalized anomaly scores

**Why Ensemble?**
- Single metrics may have false positives
- Multiple moderate anomalies are more suspicious than one strong anomaly
- Different attack types have different signatures

**Example**:
```
User A: High bytes (Z=3.0), normal volume, normal destinations
  → Single strong signal, could be legitimate (large file download)

User B: Moderate bytes (Z=2.1), high destinations (Z=2.3), after-hours
  → Three moderate signals, more likely malicious (data exfiltration)
```

---

## Setup Instructions

### Prerequisites

- Databricks workspace (Runtime 13.x+ recommended)
- Unity Catalog enabled
- Python 3.9+
- Spark 3.4+

### 1. Create Catalog and Schemas

```sql
-- Create catalog
CREATE CATALOG IF NOT EXISTS ueba_poc;

-- Use catalog
USE CATALOG ueba_poc;

-- Run schema creation script
-- (Execute schemas/01_create_delta_schemas.sql)
```

### 2. Configure Notebook Parameters

Edit the configuration section in `01_ueba_detection_analysis.py`:

```python
# Configuration
CATALOG = "ueba_poc"
USE_SYNTHETIC_DATA = True  # Start with synthetic data

# Analysis parameters
BASELINE_DAYS = 21  # Days to establish baseline
ANALYSIS_DAYS = 7   # Days to analyze for anomalies
CLUSTERING_K = 5    # Number of peer groups

# Anomaly thresholds
ZSCORE_THRESHOLD = 2.5
RISK_THRESHOLD_HIGH = 0.7
RISK_THRESHOLD_CRITICAL = 0.85
```

---

## Execution Steps

### Step 1: Generate Synthetic Data (for testing)

Run the synthetic data generator to create sample data:

```bash
# In Databricks
Run notebook: notebooks/00_generate_synthetic_data.py
```

**What it does**:
- Creates 50 users across 4 roles (developer, analyst, admin, executive)
- Generates 30 days of network and process activity
- Injects anomalous patterns in ~5% of events
- Creates ~10% anomalous users (for testing detection)

**Output Tables**:
- `ueba_poc.network_activity_synthetic`
- `ueba_poc.process_activity_synthetic`
- `ueba_poc.detection_finding_synthetic`

**Sample Output**:
```
Generating synthetic data for 50 users over 30 days
Generated 42,150 network events
Anomalous network events: 2,108 (5.00%)
Generated 8,430 process events
Anomalous process events: 253 (3.00%)
```

### Step 2: Run UEBA Detection Analysis

Run the main UEBA analysis notebook:

```bash
# In Databricks
Run notebook: notebooks/01_ueba_detection_analysis.py
```

**What it does**:

1. **Load Data** (Sections 1-2)
   - Load network and process activity
   - Determine analysis time periods

2. **Feature Engineering** (Sections 3-4)
   - Calculate daily aggregations
   - Create user-level features
   - Temporal and diversity metrics

3. **Baseline Establishment** (Section 3-4)
   - Calculate baseline statistics for each user
   - Average, std dev, max for each metric

4. **Peer Group Analysis** (Section 5)
   - Run K-means clustering
   - Assign users to peer groups
   - Show peer group characteristics

5. **Anomaly Detection** (Sections 6-7)
   - Calculate Z-scores for current period
   - Detect temporal anomalies (after-hours)
   - Score process anomalies
   - Identify outliers

6. **Risk Scoring** (Section 8)
   - Aggregate network and process risks
   - Calculate composite risk scores
   - Assign risk levels (CRITICAL, HIGH, MEDIUM, LOW)

7. **Generate Findings** (Section 9)
   - Create detection findings for anomalies
   - Include evidence and context
   - Recommend actions

8. **Save Results** (Section 10)
   - Save findings to `detection_finding` table
   - Persist risk scores

**Sample Output**:
```
UEBA DETECTION SYSTEM - ANALYSIS SUMMARY
========================================

Analysis Period:
  Baseline: 2025-10-20 to 2025-11-10 (21 days)
  Analysis: 2025-11-10 to 2025-11-17 (7 days)

Data Analyzed:
  Network Events: 9,845
  Process Events: 1,970
  Users Analyzed: 50
  Peer Groups: 5

Risk Distribution:
  CRITICAL: 2 users
  HIGH: 5 users
  MEDIUM: 8 users
  LOW: 35 users

Detection Findings:
  Total Findings: 23
  CRITICAL: 3
  HIGH: 8
  MEDIUM: 12

High-Risk Users: 7
  1. developer003 - Risk Score: 0.912 (CRITICAL)
  2. admin002 - Risk Score: 0.876 (CRITICAL)
  3. analyst008 - Risk Score: 0.785 (HIGH)
  ...
```

### Step 3: Review Detection Findings

Query the detection findings table:

```sql
SELECT
  event_time,
  user,
  finding_type,
  severity,
  title,
  risk_score,
  description
FROM ueba_poc.detection_finding
WHERE severity IN ('CRITICAL', 'HIGH')
ORDER BY risk_score DESC;
```

### Step 4: Investigate High-Risk Users

For each high-risk user, drill down into their activity:

```sql
-- Get detailed network activity for a high-risk user
SELECT
  event_time,
  dest_host,
  dest_ip,
  dest_port,
  bytes_out,
  session_duration
FROM ueba_poc.network_activity_synthetic
WHERE user = 'developer003'
  AND event_time >= '2025-11-10'
ORDER BY event_time DESC;

-- Get process activity
SELECT
  event_time,
  process_name,
  cmd_line,
  md5_hash
FROM ueba_poc.process_activity_synthetic
WHERE user = 'developer003'
  AND event_time >= '2025-11-10'
ORDER BY event_time DESC;
```

---

## Sample Outputs

### Example 1: Data Exfiltration

**Detection**:
```
User: developer003
Date: 2025-11-15
Finding: Anomalous Network Behavior - data_exfiltration
Severity: CRITICAL
Risk Score: 0.912

Evidence:
- Daily events: 203 (baseline: 95 ± 18) [Z-score: 6.0]
- Bytes out: 52,345,789 (baseline: 850,000 ± 120,000) [Z-score: 428.3]
- Unique destinations: 47 (baseline: 12 ± 3) [Z-score: 11.7]
- After hours: Yes (activity at 2:15 AM)

Peer Group: 0 (Developers)
Typical behavior: Moderate volume, GitHub, npm, Docker Hub

Recommended Actions:
- IMMEDIATE: Review detailed network logs
- IMMEDIATE: Verify user identity and location
- INVESTIGATE: Check for data exfiltration to external sites
- CONSIDER: Temporary access restrictions
```

**Interpretation**: This user transferred 52MB of data (61x their baseline) to 47 different destinations (4x baseline) at 2 AM. High confidence of data exfiltration or compromised account.

### Example 2: Privilege Escalation

**Detection**:
```
User: analyst008
Date: 2025-11-14
Finding: Anomalous Process Behavior - privilege_escalation
Severity: HIGH
Risk Score: 0.785

Evidence:
- Daily processes: 89 (baseline: 35 ± 8) [Z-score: 6.75]
- Admin processes: 15 (baseline: 0 ± 0) [Z-score: inf]
- Suspicious processes: 3 (mimikatz.exe, psexec.exe, nc.exe)

Peer Group: 1 (Analysts)
Typical behavior: Excel, Tableau, Chrome, PowerBI

Recommended Actions:
- IMMEDIATE: Review process execution logs
- IMMEDIATE: Verify process hashes against threat intelligence
- INVESTIGATE: Check for privilege escalation attempts
- VERIFY: User authorization for admin tools
```

**Interpretation**: An analyst (who typically uses business intelligence tools) suddenly executed 15 admin processes including known hacking tools. High confidence of account compromise or insider threat.

### Example 3: Lateral Movement

**Detection**:
```
User: executive002
Date: 2025-11-16
Finding: Anomalous Network Behavior - lateral_movement
Severity: MEDIUM
Risk Score: 0.620

Evidence:
- Daily events: 87 (baseline: 25 ± 6) [Z-score: 10.3]
- Unique internal IPs: 23 (baseline: 2 ± 1) [Z-score: 21.0]
- Unique ports: 8 (baseline: 2 ± 1) [Z-score: 6.0]
- Common ports: 445 (SMB), 3389 (RDP), 22 (SSH)

Peer Group: 3 (Executives)
Typical behavior: Low volume, email, web browsing

Recommended Actions:
- REVIEW: Internal network access patterns
- VERIFY: User location and device
- CHECK: Authorized access to internal systems
```

**Interpretation**: An executive (who typically accesses 2 internal systems) suddenly connected to 23 internal IPs using admin ports. Possible lateral movement or compromised account.

---

## Anomaly Types Detected

### 1. Volume Anomalies
- **Indicator**: Event count or data transfer significantly higher than baseline
- **Attack Types**: Data exfiltration, DDoS, brute force
- **Example**: User transfers 50GB when baseline is 500MB

### 2. Diversity Anomalies
- **Indicator**: Accessing many more destinations, processes, or resources than normal
- **Attack Types**: Reconnaissance, lateral movement, privilege escalation
- **Example**: User connects to 50 internal servers when baseline is 3

### 3. Temporal Anomalies
- **Indicator**: Activity outside normal working hours
- **Attack Types**: Insider threats, compromised accounts
- **Example**: Activity at 3 AM when user typically works 9-5

### 4. Peer Group Deviation
- **Indicator**: Behavior inconsistent with peer group
- **Attack Types**: Role abuse, privilege escalation
- **Example**: Analyst using admin tools typical of IT admins

### 5. Suspicious Resources
- **Indicator**: Accessing known malicious IPs, domains, or executables
- **Attack Types**: Malware, C2 communication, data exfiltration
- **Example**: Connections to Tor exit nodes or known malware hashes

---

## Tuning and Customization

### Adjusting Baseline Period

Longer baseline = More stable, less sensitive
Shorter baseline = More responsive to recent changes

```python
BASELINE_DAYS = 30  # More stable (recommended for mature environments)
BASELINE_DAYS = 14  # More responsive (for dynamic environments)
```

### Adjusting Z-score Thresholds

Higher threshold = Fewer false positives, may miss subtle attacks
Lower threshold = More sensitive, more false positives

```python
ZSCORE_THRESHOLD = 3.0  # More conservative (fewer alerts)
ZSCORE_THRESHOLD = 2.0  # More sensitive (more alerts)
```

### Adjusting Risk Thresholds

```python
RISK_THRESHOLD_HIGH = 0.8      # Fewer HIGH alerts
RISK_THRESHOLD_CRITICAL = 0.9   # Fewer CRITICAL alerts
```

### Adding Custom Features

Edit the feature engineering sections to add domain-specific features:

```python
# Example: Add geographic anomaly detection
daily_baseline_network = baseline_network.groupBy("user", "date").agg(
    # ... existing features ...
    countDistinct("src_country").alias("unique_countries"),
    countDistinct("dest_country").alias("dest_countries")
)
```

### Adjusting Peer Group Count

More peer groups = More granular, but requires more users

```python
CLUSTERING_K = 3   # Fewer groups (for <30 users)
CLUSTERING_K = 10  # More groups (for >100 users)
```

### Feature Weights

Adjust composite risk score weights based on your threat model:

```python
# Emphasize process anomalies more
Combined Risk Score = Network_Risk * 0.4 + Process_Risk * 0.6

# Emphasize data exfiltration more
Network Risk Score = (
    event_volume_zscore * 0.1 +
    bytes_out_zscore * 0.6 +      # Increased from 0.4
    destinations_zscore * 0.2 +
    hosts_zscore * 0.05 +
    after_hours_anomaly * 0.05
)
```

---

## Limitations and Considerations

### 1. Cold Start Problem
- New users have no baseline → Can't detect anomalies initially
- **Solution**: Use peer group baseline for new users

### 2. Slow Changes
- Gradual changes in behavior may not be detected
- **Solution**: Periodically recalculate baselines (e.g., monthly)

### 3. False Positives
- Legitimate behavior changes can trigger alerts
- **Solution**: Whitelist known legitimate anomalies, tune thresholds

### 4. Data Quality
- Missing or incorrect data degrades detection accuracy
- **Solution**: Data validation, anomaly detection on data gaps

### 5. Adversarial Evasion
- Sophisticated attackers can stay within normal bounds
- **Solution**: Combine UEBA with other detection methods (signatures, threat intelligence)

---

## Integrations

### SIEM Integration

Export findings to SIEM platforms:

```python
# Export to JSON for Splunk
findings_df.write.format("json").save("/mnt/siem/ueba_findings/")

# Export to Syslog
# (Custom code to format as CEF or LEEF)
```

### SOAR Integration

Trigger automated response actions:

```python
# Example: Create ticket in ServiceNow for CRITICAL findings
critical_findings = findings_df.filter(col("severity") == "CRITICAL")

for finding in critical_findings.collect():
    create_servicenow_ticket(
        title=finding["title"],
        description=finding["description"],
        priority="P1",
        assignment_group="Security Operations"
    )
```

### Threat Intelligence Enrichment

Enrich findings with threat intelligence:

```python
# Check hashes against VirusTotal
# Check IPs against AbuseIPDB
# Check domains against threat feeds
```

---

## Production Deployment

### 1. Schedule Execution

Run UEBA analysis daily:

```python
# Databricks Workflows
{
  "name": "UEBA Daily Analysis",
  "schedule": {
    "quartz_cron_expression": "0 0 6 * * ?",  # 6 AM daily
    "timezone_id": "America/Los_Angeles"
  },
  "tasks": [{
    "notebook_task": {
      "notebook_path": "/Workspace/ueba-poc/notebooks/01_ueba_detection_analysis",
      "base_parameters": {}
    }
  }]
}
```

### 2. Alerting

Configure email or Slack alerts for high-severity findings:

```python
# Send alert email
high_risk_count = high_risk_users.count()

if high_risk_count > 0:
    send_email(
        to="security-team@company.com",
        subject=f"UEBA Alert: {high_risk_count} High-Risk Users Detected",
        body=generate_alert_report(high_risk_users)
    )
```

### 3. Dashboard Creation

Create real-time dashboards in Databricks SQL:

```sql
-- High-risk users over time
SELECT
  DATE(event_time) as date,
  COUNT(*) as high_risk_users
FROM ueba_poc.detection_finding
WHERE severity IN ('HIGH', 'CRITICAL')
GROUP BY date
ORDER BY date DESC;

-- Findings by type
SELECT
  finding_type,
  severity,
  COUNT(*) as count
FROM ueba_poc.detection_finding
GROUP BY finding_type, severity;
```

### 4. Performance Optimization

- Enable Photon for faster queries
- Use Z-ordering on frequently filtered columns
- Partition tables by date
- Cache baseline calculations

```sql
-- Optimize tables
OPTIMIZE ueba_poc.network_activity ZORDER BY (user, event_time);
OPTIMIZE ueba_poc.process_activity ZORDER BY (user, event_time);
```

---

## Support and Contribution

For questions, issues, or contributions:

1. Review the documentation in `docs/` folder
2. Check sample outputs in `samples/` folder
3. Review the schemas in `schemas/` folder

---

## License

This is a proof-of-concept for demonstration purposes.

---

## Acknowledgments

- OCSF (Open Cybersecurity Schema Framework) for data format inspiration
- MITRE ATT&CK for threat modeling
- Databricks platform capabilities

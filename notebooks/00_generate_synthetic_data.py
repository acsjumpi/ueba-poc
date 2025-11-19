# Databricks notebook source
# MAGIC %md
# MAGIC # Synthetic UEBA Data Generator
# MAGIC
# MAGIC This notebook generates realistic synthetic data for UEBA POC including:
# MAGIC 1. **Network Activity** - Normal and anomalous network connections
# MAGIC 2. **Process Activity** - Normal and anomalous process executions
# MAGIC 3. **Detection Findings** - Simulated security detections
# MAGIC
# MAGIC **Use Cases:**
# MAGIC - Testing UEBA detection models
# MAGIC - Demonstrating anomaly detection capabilities
# MAGIC - Training and validation data
# MAGIC
# MAGIC **Anomaly Types Generated:**
# MAGIC - Data exfiltration patterns
# MAGIC - Privilege escalation
# MAGIC - Lateral movement
# MAGIC - After-hours activity
# MAGIC - Unusual process executions

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Setup and Configuration

# COMMAND ----------

from pyspark.sql.functions import *
from pyspark.sql.types import *
from datetime import datetime, timedelta
import random
import json
import uuid

# Configuration
CATALOG = "ueba_poc"
NUM_USERS = 50
NUM_DAYS = 30
ANOMALY_RATE = 0.05  # 5% of events are anomalous

# Time range
END_DATE = datetime.now()
START_DATE = END_DATE - timedelta(days=NUM_DAYS)

print(f"Generating synthetic data for {NUM_USERS} users over {NUM_DAYS} days")
print(f"Date range: {START_DATE} to {END_DATE}")
print(f"Anomaly rate: {ANOMALY_RATE * 100}%")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. User Profiles and Behavior Patterns

# COMMAND ----------

import builtins
import random

# Define user roles and normal behavior patterns
USER_ROLES = {
    "developer": {
        "count": 20,
        "normal_hours": (8, 18),
        "weekends": False,
        "common_processes": ["git.exe", "python.exe", "node.exe", "code.exe", "docker.exe"],
        "common_destinations": ["github.com", "stackoverflow.com", "npmjs.com", "docker.io"],
        "avg_daily_events": (50, 200)
    },
    "analyst": {
        "count": 15,
        "normal_hours": (9, 17),
        "weekends": False,
        "common_processes": ["excel.exe", "chrome.exe", "tableau.exe", "python.exe"],
        "common_destinations": ["tableau.com", "powerbi.com", "salesforce.com"],
        "avg_daily_events": (30, 100)
    },
    "admin": {
        "count": 10,
        "normal_hours": (7, 19),
        "weekends": True,
        "common_processes": ["powershell.exe", "cmd.exe", "ssh.exe", "rdp.exe"],
        "common_destinations": ["aws.amazon.com", "azure.microsoft.com", "jenkins.internal"],
        "avg_daily_events": (100, 300)
    },
    "executive": {
        "count": 5,
        "normal_hours": (9, 18),
        "weekends": False,
        "common_processes": ["outlook.exe", "chrome.exe", "teams.exe"],
        "common_destinations": ["office.com", "linkedin.com", "salesforce.com"],
        "avg_daily_events": (20, 60)
    }
}

# Generate user profiles
users = []
user_id = 1

for role, config in USER_ROLES.items():
    for i in range(config["count"]):
        username = f"{role}{user_id:03d}"
        users.append({
            "username": username,
            "role": role,
            "normal_hours": config["normal_hours"],
            "weekends_active": config["weekends"],
            "common_processes": config["common_processes"],
            "common_destinations": config["common_destinations"],
            "avg_daily_events": config["avg_daily_events"],
            "home_ip": f"10.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "is_anomalous": random.random() < 0.1  # 10% of users will exhibit anomalous behavior
        })
        user_id += 1

print(f"Generated {len(users)} user profiles:")
for role, config in USER_ROLES.items():
    count = builtins.sum(1 for u in users if u['role'] == role)
    print(f"  - {role}: {count} users")

anomalous_users = [u['username'] for u in users if u['is_anomalous']]
print(f"\nAnomalous users (for testing): {', '.join(anomalous_users[:5])}...")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Generate Network Activity Data

# COMMAND ----------

import builtins
print("Generating network activity data...")

network_events = []
event_id = 1

# Common internal IPs
INTERNAL_IPS = [f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(100)]

# Common external IPs (simulating cloud services, websites)
EXTERNAL_IPS = {
    "github.com": "140.82.114.4",
    "stackoverflow.com": "151.101.1.69",
    "aws.amazon.com": "54.239.28.85",
    "google.com": "142.250.80.46",
    "microsoft.com": "20.112.52.29",
    "suspicious-site.com": "185.220.101.50"  # Tor exit node
}

for user in users:
    current_date = START_DATE

    while current_date < END_DATE:
        # Skip weekends for users who don't work weekends
        if not user["weekends_active"] and current_date.weekday() >= 5:
            current_date += timedelta(days=1)
            continue

        # Determine number of events for this day
        min_events, max_events = user["avg_daily_events"]
        num_events = random.randint(min_events, max_events)

        for _ in range(num_events):
            # Generate timestamp within normal hours (with some variation)
            if random.random() < 0.9 or user["is_anomalous"]:  # 90% within normal hours
                start_hour, end_hour = user["normal_hours"]
                hour = random.randint(start_hour, end_hour)
            else:
                # Anomaly: after hours activity
                hour = random.choice(list(range(0, user["normal_hours"][0])) + list(range(user["normal_hours"][1], 24)))

            event_time = current_date.replace(
                hour=hour,
                minute=random.randint(0, 59),
                second=random.randint(0, 59)
            )

            # Determine if this is an anomalous event
            is_anomaly = user["is_anomalous"] and random.random() < ANOMALY_RATE * 2

            # Choose destination
            if is_anomaly:
                # Anomalous destinations
                dest_host = random.choice(["suspicious-site.com", "unknown-tor.net", "crypto-miner.com"])
                dest_ip = "185.220.101." + str(random.randint(1, 254))
                dest_port = random.choice([4444, 8080, 443, 22, 3389])  # Suspicious ports
            else:
                # Normal destinations
                dest_host = random.choice(user["common_destinations"])
                dest_ip = EXTERNAL_IPS.get(dest_host, f"203.0.{random.randint(1, 254)}.{random.randint(1, 254)}")
                dest_port = random.choice([443, 80, 22])

            # Traffic volume
            if is_anomaly:
                # Anomaly: large data transfer (potential exfiltration)
                bytes_out = random.randint(10_000_000, 100_000_000)  # 10-100 MB
                bytes_in = random.randint(1000, 10000)
            else:
                bytes_out = random.randint(1000, 100_000)
                bytes_in = random.randint(1000, 500_000)

            network_events.append({
                "event_id": event_id,
                "event_time": event_time,
                "user": user["username"],
                "src_ip": user["home_ip"],
                "src_port": random.randint(49152, 65535),
                "dest_ip": dest_ip,
                "dest_host": dest_host,
                "dest_port": dest_port,
                "protocol": "tcp",
                "app_name": random.choice(["ssl", "web-browsing", "ssh", "rdp"]),
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "packets_in": bytes_in // 1500,
                "packets_out": bytes_out // 1500,
                "session_duration": random.randint(1, 300),
                "action": "Allowed",
                "is_anomaly": is_anomaly,
                "anomaly_reason": "data_exfiltration" if is_anomaly and bytes_out > 5_000_000 else ("after_hours" if hour < user["normal_hours"][0] or hour > user["normal_hours"][1] else None)
            })

            event_id += 1

        current_date += timedelta(days=1)

print(f"Generated {len(network_events)} network events")
anomalous_network = builtins.sum(1 for e in network_events if e["is_anomaly"])
print(f"Anomalous network events: {anomalous_network} ({anomalous_network/len(network_events)*100:.2f}%)")

# Convert to Spark DataFrame
network_schema = StructType([
    StructField("event_id", IntegerType(), False),
    StructField("event_time", TimestampType(), False),
    StructField("user", StringType(), False),
    StructField("src_ip", StringType(), False),
    StructField("src_port", IntegerType(), False),
    StructField("dest_ip", StringType(), False),
    StructField("dest_host", StringType(), False),
    StructField("dest_port", IntegerType(), False),
    StructField("protocol", StringType(), False),
    StructField("app_name", StringType(), False),
    StructField("bytes_in", LongType(), False),
    StructField("bytes_out", LongType(), False),
    StructField("packets_in", LongType(), False),
    StructField("packets_out", LongType(), False),
    StructField("session_duration", IntegerType(), False),
    StructField("action", StringType(), False),
    StructField("is_anomaly", BooleanType(), False),
    StructField("anomaly_reason", StringType(), True)
])

network_df = spark.createDataFrame(network_events, schema=network_schema)

print("\nSample network activity data:")
display(network_df.limit(10))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. Generate Process Activity Data

# COMMAND ----------

import builtins

print("Generating process activity data...")

process_events = []
event_id = 1

# Common process names by OS
WINDOWS_PROCESSES = {
    "normal": [
        "svchost.exe", "chrome.exe", "explorer.exe", "outlook.exe",
        "teams.exe", "excel.exe", "word.exe", "powerpnt.exe", "python.exe"
    ],
    "admin": [
        "powershell.exe", "cmd.exe", "psexec.exe", "wmic.exe",
        "net.exe", "tasklist.exe", "reg.exe"
    ],
    "suspicious": [
        "mimikatz.exe", "psexec.exe", "nc.exe", "nmap.exe",
        "metasploit.exe", "cobalt.exe"
    ]
}

LINUX_PROCESSES = {
    "normal": [
        "bash", "python", "node", "java", "docker",
        "git", "vim", "curl", "wget"
    ],
    "admin": [
        "sudo", "ssh", "systemctl", "netstat", "ps",
        "top", "iptables", "useradd"
    ],
    "suspicious": [
        "ncat", "socat", "nmap", "sqlmap", "john",
        "hashcat", "metasploit"
    ]
}

for user in users:
    current_date = START_DATE

    # Determine OS based on role
    os_type = "Lin" if user["role"] == "developer" and random.random() < 0.3 else "Win"
    process_pool = LINUX_PROCESSES if os_type == "Lin" else WINDOWS_PROCESSES

    while current_date < END_DATE:
        # Skip weekends for users who don't work weekends
        if not user["weekends_active"] and current_date.weekday() >= 5:
            current_date += timedelta(days=1)
            continue

        # Process events are less frequent than network
        num_events = random.randint(5, 30)

        for _ in range(num_events):
            # Generate timestamp
            start_hour, end_hour = user["normal_hours"]
            if random.random() < 0.85:
                hour = random.randint(start_hour, end_hour)
            else:
                hour = random.choice(list(range(0, start_hour)) + list(range(end_hour, 24)))

            event_time = current_date.replace(
                hour=hour,
                minute=random.randint(0, 59),
                second=random.randint(0, 59)
            )

            # Determine if anomalous
            is_anomaly = user["is_anomalous"] and random.random() < ANOMALY_RATE * 3

            # Choose process
            if is_anomaly:
                process_type = "suspicious"
                process_name = random.choice(process_pool[process_type])
                parent_process = random.choice(process_pool["normal"])
            elif user["role"] == "admin" and random.random() < 0.4:
                process_type = "admin"
                process_name = random.choice(process_pool[process_type])
                parent_process = "explorer.exe" if os_type == "Win" else "bash"
            else:
                process_type = "normal"
                process_name = random.choice(user["common_processes"])
                parent_process = "explorer.exe" if os_type == "Win" else "bash"

            # Generate command line
            if process_name in ["powershell.exe", "cmd.exe", "bash"]:
                if is_anomaly:
                    cmd_line = f"{process_name} -encodedCommand {uuid.uuid4().hex[:32]}"
                else:
                    cmd_line = f"{process_name} -File script.ps1" if "powershell" in process_name else f"{process_name} /c dir"
            else:
                cmd_line = f"/usr/bin/{process_name}" if os_type == "Lin" else f"C:\\Program Files\\App\\{process_name}"

            # Generate hash
            md5_hash = uuid.uuid4().hex
            sha256_hash = uuid.uuid4().hex + uuid.uuid4().hex

            process_events.append({
                "event_id": event_id,
                "event_time": event_time,
                "user": user["username"],
                "host": f"{user['username']}-{os_type.lower()}-host",
                "process_name": process_name,
                "process_path": f"/usr/bin/{process_name}" if os_type == "Lin" else f"C:\\Windows\\System32\\{process_name}",
                "cmd_line": cmd_line,
                "parent_process": parent_process,
                "pid": random.randint(1000, 65535),
                "parent_pid": random.randint(1000, 65535),
                "md5_hash": md5_hash,
                "sha256_hash": sha256_hash,
                "os_platform": os_type,
                "is_anomaly": is_anomaly,
                "anomaly_reason": "suspicious_process" if is_anomaly else None
            })

            event_id += 1

        current_date += timedelta(days=1)

print(f"Generated {len(process_events)} process events")
anomalous_process = builtins.sum(1 for e in process_events if e["is_anomaly"])
print(f"Anomalous process events: {anomalous_process} ({anomalous_process/len(process_events)*100:.2f}%)")

# Convert to Spark DataFrame
process_schema = StructType([
    StructField("event_id", IntegerType(), False),
    StructField("event_time", TimestampType(), False),
    StructField("user", StringType(), False),
    StructField("host", StringType(), False),
    StructField("process_name", StringType(), False),
    StructField("process_path", StringType(), False),
    StructField("cmd_line", StringType(), False),
    StructField("parent_process", StringType(), False),
    StructField("pid", IntegerType(), False),
    StructField("parent_pid", IntegerType(), False),
    StructField("md5_hash", StringType(), False),
    StructField("sha256_hash", StringType(), False),
    StructField("os_platform", StringType(), False),
    StructField("is_anomaly", BooleanType(), False),
    StructField("anomaly_reason", StringType(), True)
])

process_df = spark.createDataFrame(process_events, schema=process_schema)

print("\nSample process activity data:")
display(process_df.limit(10))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Generate Detection Findings (Rules-Based)

# COMMAND ----------

print("Generating detection findings based on anomalous events...")

findings = []
finding_id = 1

# Analyze network events for anomalies
for event in network_events:
    if event["is_anomaly"]:
        finding = {
            "finding_id": finding_id,
            "event_time": event["event_time"],
            "user": event["user"],
            "finding_type": "network_anomaly",
            "severity": "High" if event["anomaly_reason"] == "data_exfiltration" else "Medium",
            "title": f"Anomalous Network Activity Detected - {event['anomaly_reason']}",
            "description": f"User {event['user']} exhibited unusual network behavior",
            "src_ip": event["src_ip"],
            "dest_ip": event["dest_ip"],
            "dest_host": event["dest_host"],
            "bytes_transferred": event["bytes_out"],
            "analytic_name": f"rule_network_{event['anomaly_reason']}",
            "risk_score": 0.8 if event["anomaly_reason"] == "data_exfiltration" else 0.6,
            "action_taken": "Alert Generated"
        }
        findings.append(finding)
        finding_id += 1

# Analyze process events for anomalies
for event in process_events:
    if event["is_anomaly"]:
        finding = {
            "finding_id": finding_id,
            "event_time": event["event_time"],
            "user": event["user"],
            "finding_type": "process_anomaly",
            "severity": "High",
            "title": f"Suspicious Process Execution Detected",
            "description": f"User {event['user']} executed suspicious process: {event['process_name']}",
            "host": event["host"],
            "process_name": event["process_name"],
            "cmd_line": event["cmd_line"],
            "process_hash": event["sha256_hash"],
            "analytic_name": "rule_suspicious_process",
            "risk_score": 0.9,
            "action_taken": "Alert Generated"
        }
        findings.append(finding)
        finding_id += 1

print(f"Generated {len(findings)} detection findings")

# Sample finding summary
if findings:
    severity_counts = {}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    print("\nFindings by severity:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  - {severity}: {count}")

# Convert to DataFrame
findings_schema = StructType([
    StructField("finding_id", IntegerType(), False),
    StructField("event_time", TimestampType(), False),
    StructField("user", StringType(), False),
    StructField("finding_type", StringType(), False),
    StructField("severity", StringType(), False),
    StructField("title", StringType(), False),
    StructField("description", StringType(), False),
    StructField("src_ip", StringType(), True),
    StructField("dest_ip", StringType(), True),
    StructField("dest_host", StringType(), True),
    StructField("bytes_transferred", LongType(), True),
    StructField("host", StringType(), True),
    StructField("process_name", StringType(), True),
    StructField("cmd_line", StringType(), True),
    StructField("process_hash", StringType(), True),
    StructField("analytic_name", StringType(), False),
    StructField("risk_score", DoubleType(), False),
    StructField("action_taken", StringType(), False)
])

findings_df = spark.createDataFrame(findings, schema=findings_schema)

print("\nSample detection findings:")
display(findings_df.limit(10))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6. Save to Delta Tables

# COMMAND ----------

print("Saving synthetic data to Delta tables...")

# Save network activity
network_table = f"{CATALOG}.network_activity_synthetic"
print(f"\nSaving {network_df.count()} network events to {network_table}...")
network_df.write.format("delta").mode("overwrite").saveAsTable(network_table)
print(f"✓ Network activity saved")

# Save process activity
process_table = f"{CATALOG}.process_activity_synthetic"
print(f"\nSaving {process_df.count()} process events to {process_table}...")
process_df.write.format("delta").mode("overwrite").saveAsTable(process_table)
print(f"✓ Process activity saved")

# Save detection findings
findings_table = f"{CATALOG}.detection_finding_synthetic"
print(f"\nSaving {findings_df.count()} findings to {findings_table}...")
findings_df.write.format("delta").mode("overwrite").saveAsTable(findings_table)
print(f"✓ Detection findings saved")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 7. Data Quality Summary

# COMMAND ----------

import builtins
print("="*70)
print(" SYNTHETIC DATA GENERATION SUMMARY")
print("="*70)

print(f"\nTime Period: {START_DATE.strftime('%Y-%m-%d')} to {END_DATE.strftime('%Y-%m-%d')} ({NUM_DAYS} days)")
print(f"Number of Users: {NUM_USERS}")

print(f"\nNetwork Activity:")
print(f"  Total Events: {len(network_events):,}")
print(f"  Anomalous Events: {anomalous_network:,} ({anomalous_network/len(network_events)*100:.2f}%)")
print(f"  Unique Users: {network_df.select('user').distinct().count()}")
print(f"  Unique Destinations: {network_df.select('dest_host').distinct().count()}")

print(f"\nProcess Activity:")
print(f"  Total Events: {len(process_events):,}")
print(f"  Anomalous Events: {anomalous_process:,} ({anomalous_process/len(process_events)*100:.2f}%)")
print(f"  Unique Users: {process_df.select('user').distinct().count()}")
print(f"  Unique Processes: {process_df.select('process_name').distinct().count()}")

print(f"\nDetection Findings:")
print(f"  Total Findings: {len(findings):,}")
print(f"  Unique Users with Findings: {findings_df.select('user').distinct().count()}")

if findings:
    print(f"\n  Findings by Type:")
    for finding_type in findings_df.select("finding_type").distinct().collect():
        count = builtins.sum(1 for f in findings if f["finding_type"] == finding_type.finding_type)
        print(f"    - {finding_type.finding_type}: {count}")

print(f"\nTables Created:")
print(f"  - {network_table}")
print(f"  - {process_table}")
print(f"  - {findings_table}")

print("\n" + "="*70)
print(" Data generation complete! Ready for UEBA analysis.")
print("="*70)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 8. Visualization of Generated Data

# COMMAND ----------

# User activity distribution
print("User Activity Distribution:")
user_activity = network_df.groupBy("user").count().orderBy(desc("count"))
display(user_activity.limit(20))

# Hourly activity pattern
print("\nHourly Activity Pattern:")
from pyspark.sql.functions import hour
hourly_pattern = network_df.withColumn("hour", hour("event_time")).groupBy("hour").count().orderBy("hour")
display(hourly_pattern)

# Anomalous users
print("\nUsers with Anomalous Behavior:")
from pyspark.sql.functions import col, count, collect_set, desc
anomalous_summary = network_df.filter(col("is_anomaly")).groupBy("user").agg(
    count("*").alias("anomalous_events"),
    collect_set("anomaly_reason").alias("anomaly_types")
).orderBy(desc("anomalous_events"))
display(anomalous_summary)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Next Steps
# MAGIC
# MAGIC 1. Run the main UEBA notebook: `01_ueba_detection_analysis.py`
# MAGIC 2. Analyze the generated synthetic data
# MAGIC 3. Test detection rules and scoring algorithms
# MAGIC 4. Tune anomaly detection thresholds
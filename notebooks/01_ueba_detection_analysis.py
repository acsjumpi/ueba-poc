# Databricks notebook source
# MAGIC %md
# MAGIC # User and Entity Behavior Analytics (UEBA) Detection System
# MAGIC
# MAGIC This notebook implements a comprehensive UEBA detection system that analyzes:
# MAGIC 1. **Network Activity** - Connection patterns, data transfers, destinations
# MAGIC 2. **Process Activity** - Process executions, command lines, file hashes
# MAGIC
# MAGIC **Detection Techniques:**
# MAGIC - Peer Group Analysis
# MAGIC - Behavioral Baselines
# MAGIC - Anomaly Scoring (Statistical + ML)
# MAGIC - Risk Aggregation
# MAGIC - Detection Finding Generation
# MAGIC
# MAGIC **Anomaly Types Detected:**
# MAGIC - Data exfiltration attempts
# MAGIC - Lateral movement
# MAGIC - Privilege escalation
# MAGIC - After-hours activity
# MAGIC - Unusual process executions
# MAGIC - Geographic anomalies

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Setup and Configuration

# COMMAND ----------

from pyspark.sql.functions import *
from pyspark.sql.types import *
from pyspark.sql.window import Window
from pyspark.ml.feature import VectorAssembler, StandardScaler
from pyspark.ml.clustering import KMeans
from datetime import datetime, timedelta
import json

# Configuration
CATALOG = "ueba_poc"
USE_SYNTHETIC_DATA = True  # Set to False to use real data

# Table names
if USE_SYNTHETIC_DATA:
    NETWORK_TABLE = f"{CATALOG}.network_activity_synthetic"
    PROCESS_TABLE = f"{CATALOG}.process_activity_synthetic"
else:
    NETWORK_TABLE = f"{CATALOG}.network_activity"
    PROCESS_TABLE = f"{CATALOG}.process_activity"

OUTPUT_TABLE = f"{CATALOG}.detection_finding"

# Analysis parameters
BASELINE_DAYS = 21  # Days to establish baseline
ANALYSIS_DAYS = 7   # Days to analyze for anomalies
CLUSTERING_K = 5    # Number of peer groups

# Anomaly thresholds
ZSCORE_THRESHOLD = 2.5  # Standard deviations for outlier
RISK_THRESHOLD_HIGH = 0.7
RISK_THRESHOLD_CRITICAL = 0.85

print(f"UEBA Detection System Configuration:")
print(f"  Data source: {'Synthetic' if USE_SYNTHETIC_DATA else 'Production'}")
print(f"  Network table: {NETWORK_TABLE}")
print(f"  Process table: {PROCESS_TABLE}")
print(f"  Baseline period: {BASELINE_DAYS} days")
print(f"  Analysis period: {ANALYSIS_DAYS} days")
print(f"  Peer groups (K): {CLUSTERING_K}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Data Loading and Preprocessing

# COMMAND ----------

print("Loading data...")

# Load network activity
try:
    network_raw = spark.table(NETWORK_TABLE)
    print(f"Loaded {network_raw.count():,} network events")
except Exception as e:
    print(f"Error loading network table: {e}")
    print("Please run 00_generate_synthetic_data.py first to create synthetic data")
    dbutils.notebook.exit("Network table not found")

# Load process activity
try:
    process_raw = spark.table(PROCESS_TABLE)
    print(f"Loaded {process_raw.count():,} process events")
except Exception as e:
    print(f"Error loading process table: {e}")
    process_raw = None

# Determine time range
max_date = network_raw.select(max("event_time")).collect()[0][0]
analysis_start = max_date - timedelta(days=ANALYSIS_DAYS)
baseline_start = analysis_start - timedelta(days=BASELINE_DAYS)

print(f"\nTime Periods:")
print(f"  Baseline: {baseline_start} to {analysis_start}")
print(f"  Analysis: {analysis_start} to {max_date}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Feature Engineering - Network Activity

# COMMAND ----------

print("Engineering network activity features...")

# Create daily aggregations for baseline period
baseline_network = network_raw.filter(
    (col("event_time") >= baseline_start) &
    (col("event_time") < analysis_start)
).withColumn("date", to_date("event_time"))

# Calculate baseline metrics per user per day
daily_baseline_network = baseline_network.groupBy("user", "date").agg(
    # Volume metrics
    count("*").alias("daily_events"),
    sum("bytes_out").alias("daily_bytes_out"),
    sum("bytes_in").alias("daily_bytes_in"),
    sum("packets_out").alias("daily_packets_out"),
    sum("packets_in").alias("daily_packets_in"),

    # Diversity metrics
    countDistinct("dest_ip").alias("unique_destinations"),
    countDistinct("dest_host").alias("unique_hosts"),
    countDistinct("dest_port").alias("unique_ports"),
    countDistinct("app_name").alias("unique_apps"),

    # Temporal metrics
    countDistinct(hour("event_time")).alias("active_hours"),
    min(hour("event_time")).alias("first_activity_hour"),
    max(hour("event_time")).alias("last_activity_hour"),

    # Session metrics
    avg("session_duration").alias("avg_session_duration"),
    max("session_duration").alias("max_session_duration")
)

# Calculate user baselines (averages over baseline period)
user_baseline_network = daily_baseline_network.groupBy("user").agg(
    # Average daily volumes
    avg("daily_events").alias("baseline_avg_events"),
    stddev("daily_events").alias("baseline_std_events"),
    max("daily_events").alias("baseline_max_events"),

    # Average daily data transfer
    avg("daily_bytes_out").alias("baseline_avg_bytes_out"),
    stddev("daily_bytes_out").alias("baseline_std_bytes_out"),
    max("daily_bytes_out").alias("baseline_max_bytes_out"),

    # Average diversity
    avg("unique_destinations").alias("baseline_avg_destinations"),
    stddev("unique_destinations").alias("baseline_std_destinations"),

    avg("unique_hosts").alias("baseline_avg_hosts"),
    stddev("unique_hosts").alias("baseline_std_hosts"),

    # Temporal patterns
    avg("active_hours").alias("baseline_avg_active_hours"),
    avg("first_activity_hour").alias("baseline_typical_start_hour"),
    avg("last_activity_hour").alias("baseline_typical_end_hour"),

    # Active days in baseline
    countDistinct("date").alias("baseline_active_days")
)

print(f"Created baselines for {user_baseline_network.count()} users")
display(user_baseline_network.limit(5))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. Feature Engineering - Process Activity

# COMMAND ----------

if process_raw:
    print("Engineering process activity features...")

    # Baseline period
    baseline_process = process_raw.filter(
        (col("event_time") >= baseline_start) &
        (col("event_time") < analysis_start)
    ).withColumn("date", to_date("event_time"))

    # Daily process metrics
    daily_baseline_process = baseline_process.groupBy("user", "date").agg(
        count("*").alias("daily_processes"),
        countDistinct("process_name").alias("unique_processes"),
        countDistinct("process_path").alias("unique_paths"),
        countDistinct("host").alias("unique_hosts"),
        countDistinct("parent_process").alias("unique_parents"),

        # Count admin-like processes
        sum(when(col("process_name").isin(
            "powershell.exe", "cmd.exe", "bash", "sudo", "ssh"
        ), 1).otherwise(0)).alias("admin_process_count")
    )

    # User process baselines
    user_baseline_process = daily_baseline_process.groupBy("user").agg(
        avg("daily_processes").alias("baseline_avg_processes"),
        stddev("daily_processes").alias("baseline_std_processes"),

        avg("unique_processes").alias("baseline_avg_unique_processes"),
        stddev("unique_processes").alias("baseline_std_unique_processes"),

        avg("admin_process_count").alias("baseline_avg_admin_processes"),
        stddev("admin_process_count").alias("baseline_std_admin_processes"),

        countDistinct("date").alias("baseline_process_active_days")
    )

    print(f"Created process baselines for {user_baseline_process.count()} users")
    display(user_baseline_process.limit(5))
else:
    user_baseline_process = None
    print("Process activity data not available")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Peer Group Analysis (Clustering)

# COMMAND ----------

print("Performing peer group analysis using K-means clustering...")

# Prepare features for clustering (reduce to 2 most important features)
clustering_features = user_baseline_network.select(
    "user",
    "baseline_avg_events",
    "baseline_avg_bytes_out"
).na.fill(0)

# Only use 2 features to keep model small
feature_cols = [
    "baseline_avg_events", "baseline_avg_bytes_out"
]

user_count = clustering_features.count()
print(f"Clustering {user_count} users")

# Manual normalization to avoid StandardScaler model size issues
# Calculate min/max for each feature
stats = clustering_features.agg(
    min("baseline_avg_events").alias("min_events"),
    max("baseline_avg_events").alias("max_events"),
    min("baseline_avg_bytes_out").alias("min_bytes"),
    max("baseline_avg_bytes_out").alias("max_bytes")
).collect()[0]

# Normalize features to [0, 1] range
clustering_normalized = clustering_features.withColumn(
    "norm_events",
    when(lit(stats.max_events - stats.min_events) > 0,
         (col("baseline_avg_events") - lit(stats.min_events)) / lit(stats.max_events - stats.min_events)
    ).otherwise(0.0)
).withColumn(
    "norm_bytes",
    when(lit(stats.max_bytes - stats.min_bytes) > 0,
         (col("baseline_avg_bytes_out") - lit(stats.min_bytes)) / lit(stats.max_bytes - stats.min_bytes)
    ).otherwise(0.0)
)

# Create feature vector from normalized features
assembler = VectorAssembler(inputCols=["norm_events", "norm_bytes"], outputCol="features")
df_assembled = assembler.transform(clustering_normalized)

# Train K-means (no StandardScaler needed)
kmeans = KMeans(k=CLUSTERING_K, seed=42, featuresCol="features", predictionCol="peer_group")
kmeans_model = kmeans.fit(df_assembled)
user_peer_groups = kmeans_model.transform(df_assembled).select("user", "peer_group")

print(f"✓ Assigned users to {CLUSTERING_K} peer groups")

# Show peer group distribution
peer_group_stats = user_peer_groups.groupBy("peer_group").agg(
    count("*").alias("user_count")
).join(
    user_baseline_network,
    user_peer_groups["user"] == user_baseline_network["user"]
).groupBy("peer_group").agg(
    count("*").alias("users"),
    avg("baseline_avg_events").alias("avg_events"),
    avg("baseline_avg_bytes_out").alias("avg_bytes_out")
).orderBy("peer_group")

print("\nPeer Group Characteristics:")
display(peer_group_stats)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6. Analyze Current Period and Detect Anomalies

# COMMAND ----------

print("Analyzing current period for anomalies...")

# Get current period data
analysis_network = network_raw.filter(
    (col("event_time") >= analysis_start) &
    (col("event_time") <= max_date)
).withColumn("date", to_date("event_time"))

# Daily metrics for analysis period
daily_analysis_network = analysis_network.groupBy("user", "date").agg(
    count("*").alias("daily_events"),
    sum("bytes_out").alias("daily_bytes_out"),
    sum("bytes_in").alias("daily_bytes_in"),
    countDistinct("dest_ip").alias("unique_destinations"),
    countDistinct("dest_host").alias("unique_hosts"),
    countDistinct(hour("event_time")).alias("active_hours"),
    min(hour("event_time")).alias("first_activity_hour"),
    max(hour("event_time")).alias("last_activity_hour"),

    # Anomaly indicators
    # sum(when(col("is_anomaly") == True, 1).otherwise(0)).alias("known_anomalies")
)

# Join with baselines
network_with_baseline = daily_analysis_network.join(
    user_baseline_network,
    "user",
    "left"
).join(
    user_peer_groups,
    "user",
    "left"
)

# Calculate Z-scores for anomaly detection
network_anomalies = network_with_baseline.withColumn(
    "events_zscore",
    when(col("baseline_std_events") > 0,
         abs(col("daily_events") - col("baseline_avg_events")) / col("baseline_std_events")
    ).otherwise(0)
).withColumn(
    "bytes_out_zscore",
    when(col("baseline_std_bytes_out") > 0,
         abs(col("daily_bytes_out") - col("baseline_avg_bytes_out")) / col("baseline_std_bytes_out")
    ).otherwise(0)
).withColumn(
    "destinations_zscore",
    when(col("baseline_std_destinations") > 0,
         abs(col("unique_destinations") - col("baseline_avg_destinations")) / col("baseline_std_destinations")
    ).otherwise(0)
).withColumn(
    "hosts_zscore",
    when(col("baseline_std_hosts") > 0,
         abs(col("unique_hosts") - col("baseline_avg_hosts")) / col("baseline_std_hosts")
    ).otherwise(0)
)

# Temporal anomalies (after hours)
network_anomalies = network_anomalies.withColumn(
    "after_hours_anomaly",
    when(
        (col("first_activity_hour") < col("baseline_typical_start_hour") - 2) |
        (col("last_activity_hour") > col("baseline_typical_end_hour") + 2),
        1.0
    ).otherwise(0.0)
)

# Calculate composite anomaly score
network_anomalies = network_anomalies.withColumn(
    "network_anomaly_score",
    (
        least(col("events_zscore") / 3.0, lit(1.0)) * 0.2 +
        least(col("bytes_out_zscore") / 3.0, lit(1.0)) * 0.4 +
        least(col("destinations_zscore") / 3.0, lit(1.0)) * 0.2 +
        least(col("hosts_zscore") / 3.0, lit(1.0)) * 0.1 +
        col("after_hours_anomaly") * 0.1
    )
).withColumn(
    "network_anomaly_level",
    when(col("network_anomaly_score") >= RISK_THRESHOLD_CRITICAL, "CRITICAL")
    .when(col("network_anomaly_score") >= RISK_THRESHOLD_HIGH, "HIGH")
    .when(col("network_anomaly_score") >= 0.5, "MEDIUM")
    .otherwise("LOW")
)

print(f"Analyzed {network_anomalies.count()} user-days")

# Show top anomalies
print("\nTop Network Anomalies:")
top_network_anomalies = network_anomalies.filter(
    col("network_anomaly_score") >= 0.5
).select(
    "user", "date", "peer_group",
    "daily_events", "baseline_avg_events", "events_zscore",
    "daily_bytes_out", "baseline_avg_bytes_out", "bytes_out_zscore",
    "network_anomaly_score", "network_anomaly_level"
).orderBy(desc("network_anomaly_score"))

display(top_network_anomalies.limit(20))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 7. Process Activity Anomaly Detection

# COMMAND ----------

if process_raw:
    print("Analyzing process activity for anomalies...")

    # Get current period process data
    analysis_process = process_raw.filter(
        (col("event_time") >= analysis_start) &
        (col("event_time") <= max_date)
    ).withColumn("date", to_date("event_time"))

    # Daily process metrics
    daily_analysis_process = analysis_process.groupBy("user", "date").agg(
        count("*").alias("daily_processes"),
        countDistinct("process_name").alias("unique_processes"),
        countDistinct("host").alias("unique_hosts"),

        # Admin process count
        sum(when(col("process_name").isin(
            "powershell.exe", "cmd.exe", "bash", "sudo", "ssh"
        ), 1).otherwise(0)).alias("admin_process_count"),

        # Suspicious process indicator
        # sum(when(col("is_anomaly") == True, 1).otherwise(0)).alias("suspicious_process_count")
    )

    # Join with baselines
    process_with_baseline = daily_analysis_process.join(
        user_baseline_process,
        "user",
        "left"
    )

    # Calculate Z-scores
    process_anomalies = process_with_baseline.withColumn(
        "processes_zscore",
        when(col("baseline_std_processes") > 0,
             abs(col("daily_processes") - col("baseline_avg_processes")) / col("baseline_std_processes")
        ).otherwise(0)
    ).withColumn(
        "unique_processes_zscore",
        when(col("baseline_std_unique_processes") > 0,
             abs(col("unique_processes") - col("baseline_avg_unique_processes")) / col("baseline_std_unique_processes")
        ).otherwise(0)
    ).withColumn(
        "admin_processes_zscore",
        when(col("baseline_std_admin_processes") > 0,
             abs(col("admin_process_count") - col("baseline_avg_admin_processes")) / col("baseline_std_admin_processes")
        ).otherwise(0)
    )

    # Composite process anomaly score
    process_anomalies = process_anomalies.withColumn(
        "process_anomaly_score",
        (
            least(col("processes_zscore") / 3.0, lit(1.0)) * 0.3 +
            least(col("unique_processes_zscore") / 3.0, lit(1.0)) * 0.2 +
            least(col("admin_processes_zscore") / 3.0, lit(1.0)) * 0.3 +
            when(col("suspicious_process_count") > 0, 1.0).otherwise(0.0) * 0.2
        )
    ).withColumn(
        "process_anomaly_level",
        when(col("process_anomaly_score") >= RISK_THRESHOLD_CRITICAL, "CRITICAL")
        .when(col("process_anomaly_score") >= RISK_THRESHOLD_HIGH, "HIGH")
        .when(col("process_anomaly_score") >= 0.5, "MEDIUM")
        .otherwise("LOW")
    )

    print(f"Analyzed {process_anomalies.count()} user-days for process anomalies")

    # Show top process anomalies
    print("\nTop Process Anomalies:")
    top_process_anomalies = process_anomalies.filter(
        col("process_anomaly_score") >= 0.5
    ).select(
        "user", "date",
        "daily_processes", "baseline_avg_processes", "processes_zscore",
        "suspicious_process_count",
        "process_anomaly_score", "process_anomaly_level"
    ).orderBy(desc("process_anomaly_score"))

    display(top_process_anomalies.limit(20))
else:
    process_anomalies = None
    print("⚠ Process anomaly detection skipped (no process data)")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 8. Aggregate Risk Scores Per User

# COMMAND ----------

print("Aggregating risk scores per user...")

# Get max risk score per user from network anomalies
user_network_risk = network_anomalies.groupBy("user").agg(
    max("network_anomaly_score").alias("max_network_risk"),
    count(when(col("network_anomaly_score") >= 0.5, 1)).alias("medium_high_network_days"),
    sum("daily_events").alias("total_events"),
    sum("daily_bytes_out").alias("total_bytes_out"),
    collect_set("date").alias("anomalous_dates")
)

# Combine with process risk if available
if process_anomalies:
    user_process_risk = process_anomalies.groupBy("user").agg(
        max("process_anomaly_score").alias("max_process_risk"),
        count(when(col("process_anomaly_score") >= 0.5, 1)).alias("medium_high_process_days"),
        sum("suspicious_process_count").alias("total_suspicious_processes")
    )

    user_combined_risk = user_network_risk.join(
        user_process_risk,
        "user",
        "full_outer"
    ).na.fill(0)

    # Combined risk score (weighted average)
    user_combined_risk = user_combined_risk.withColumn(
        "combined_risk_score",
        (coalesce(col("max_network_risk"), lit(0.0)) * 0.6 +
         coalesce(col("max_process_risk"), lit(0.0)) * 0.4)
    )
else:
    user_combined_risk = user_network_risk.withColumn(
        "combined_risk_score",
        col("max_network_risk")
    )

# Add peer group information
user_combined_risk = user_combined_risk.join(
    user_peer_groups,
    "user",
    "left"
)

# Final risk level
user_combined_risk = user_combined_risk.withColumn(
    "final_risk_level",
    when(col("combined_risk_score") >= RISK_THRESHOLD_CRITICAL, "CRITICAL")
    .when(col("combined_risk_score") >= RISK_THRESHOLD_HIGH, "HIGH")
    .when(col("combined_risk_score") >= 0.5, "MEDIUM")
    .otherwise("LOW")
).withColumn(
    "analysis_timestamp",
    current_timestamp()
)

print(f"Aggregated risk scores for {user_combined_risk.count()} users")

# Risk level distribution
risk_distribution = user_combined_risk.groupBy("final_risk_level").count().orderBy(desc("count"))
print("\nRisk Level Distribution:")
display(risk_distribution)

# High-risk users
high_risk_users = user_combined_risk.filter(
    col("combined_risk_score") >= RISK_THRESHOLD_HIGH
).orderBy(desc("combined_risk_score"))

print(f"\nHigh-Risk Users: {high_risk_users.count()}")
display(high_risk_users)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 9. Generate Detection Findings

# COMMAND ----------

import uuid
print("Generating detection findings...")


findings = []

# Network anomaly findings
network_findings = network_anomalies.filter(
    col("network_anomaly_score") >= 0.5
).join(
    user_combined_risk.select("user", "peer_group", "final_risk_level"),
    "user"
)

# Create findings for each anomalous user-day
for row in network_findings.collect():
    finding = {
        "finding_id": str(uuid.uuid4()),
        "event_time": row["date"],
        "user": row["user"],
        "finding_type": "network_anomaly",
        "severity": row["network_anomaly_level"],
        "title": f"Anomalous Network Behavior Detected - {row['user']}",
        "description": f"User {row['user']} (Peer Group {row['peer_group']}) exhibited unusual network activity on {row['date']}",
        "risk_score": float(row["network_anomaly_score"]),
        "risk_level": row["final_risk_level"],
        "analytic_name": "ueba_network_anomaly_detection",
        "analytic_type": "statistical_ml",

        # Evidence
        "daily_events": int(row["daily_events"]),
        "baseline_avg_events": float(row["baseline_avg_events"]) if row["baseline_avg_events"] else 0.0,
        "events_zscore": float(row["events_zscore"]),
        "daily_bytes_out": int(row["daily_bytes_out"]) if row["daily_bytes_out"] else 0,
        "bytes_out_zscore": float(row["bytes_out_zscore"]),
        "unique_destinations": int(row["unique_destinations"]),
        "after_hours": bool(row["after_hours_anomaly"]),

        # Context
        "peer_group": int(row["peer_group"]) if row["peer_group"] else -1,
        "analysis_period_start": str(analysis_start),
        "analysis_period_end": str(max_date),
        "baseline_period_start": str(baseline_start),
        "baseline_period_end": str(analysis_start),

        # Actions
        "recommended_actions": [
            "Review detailed network logs for this user",
            "Verify user identity and location",
            "Check for data exfiltration indicators" if row["bytes_out_zscore"] > 2.0 else "Monitor ongoing activity"
        ]
    }

    findings.append(finding)

# Process anomaly findings
if process_anomalies:
    process_findings = process_anomalies.filter(
        col("process_anomaly_score") >= 0.5
    ).join(
        user_combined_risk.select("user", "peer_group", "final_risk_level"),
        "user"
    )

    for row in process_findings.collect():
        finding = {
            "finding_id": str(uuid.uuid4()),
            "event_time": row["date"],
            "user": row["user"],
            "finding_type": "process_anomaly",
            "severity": row["process_anomaly_level"],
            "title": f"Anomalous Process Activity Detected - {row['user']}",
            "description": f"User {row['user']} executed unusual processes on {row['date']}",
            "risk_score": float(row["process_anomaly_score"]),
            "risk_level": row["final_risk_level"],
            "analytic_name": "ueba_process_anomaly_detection",
            "analytic_type": "statistical_ml",

            # Evidence
            "daily_processes": int(row["daily_processes"]),
            "baseline_avg_processes": float(row["baseline_avg_processes"]) if row["baseline_avg_processes"] else 0.0,
            "suspicious_process_count": int(row["suspicious_process_count"]) if row["suspicious_process_count"] else 0,

            # Context
            "peer_group": int(row["peer_group"]) if row["peer_group"] else -1,

            # Actions
            "recommended_actions": [
                "Review process execution logs",
                "Verify process hashes against threat intelligence",
                "Check for privilege escalation attempts"
            ]
        }

        findings.append(finding)

print(f"✓ Generated {len(findings)} detection findings")

# Findings summary
if findings:
    severity_counts = {}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    print("\nFindings by Severity:")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(severity, 0)
        print(f"  {severity}: {count}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 10. Save Detection Findings

# COMMAND ----------

from datetime import datetime, date

if findings:
    print(f"Saving {len(findings)} findings to {OUTPUT_TABLE}...")

    # Convert findings to DataFrame
    findings_schema = StructType([
        StructField("finding_id", StringType(), False),
        StructField("EVENT_TIME", TimestampType(), False),  # Changed to TimestampType to match existing table
        StructField("user", StringType(), False),
        StructField("finding_type", StringType(), False),
        StructField("severity", StringType(), False),
        StructField("title", StringType(), False),
        StructField("description", StringType(), False),
        StructField("risk_score", DoubleType(), False),
        StructField("risk_level", StringType(), False),
        StructField("analytic_name", StringType(), False),
        StructField("analytic_type", StringType(), False),
        StructField("peer_group", IntegerType(), True),
        StructField("recommended_actions", ArrayType(StringType()), True)
    ])

    # Create DataFrame with core fields
    findings_rows = [(
        f["finding_id"],
        datetime.combine(f["event_time"], datetime.min.time()) if isinstance(f["event_time"], date) else f["event_time"],  # Convert date to datetime
        f["user"],
        f["finding_type"],
        f["severity"],
        f["title"],
        f["description"],
        f["risk_score"],
        f["risk_level"],
        f["analytic_name"],
        f["analytic_type"],
        f["peer_group"],
        f["recommended_actions"]
    ) for f in findings]

    findings_df = spark.createDataFrame(findings_rows, schema=findings_schema)

    # Add metadata
    findings_df = findings_df.withColumn("load_timestamp", current_timestamp()) \
                             .withColumn("analysis_version", lit("1.0"))

    # Save to Delta
    findings_df.write.format("delta").mode("append").option("mergeSchema", "true").saveAsTable(OUTPUT_TABLE)

    print(f"✓ Findings saved to {OUTPUT_TABLE}")
else:
    print("⚠ No findings to save")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 11. UEBA Summary Report

# COMMAND ----------

import builtins

print("="*80)
print(" UEBA DETECTION SYSTEM - ANALYSIS SUMMARY")
print("="*80)

print(f"\nAnalysis Period:")
print(f"  Baseline: {baseline_start} to {analysis_start} ({BASELINE_DAYS} days)")
print(f"  Analysis: {analysis_start} to {max_date} ({ANALYSIS_DAYS} days)")

print(f"\nData Analyzed:")
print(f"  Network Events: {network_raw.filter((col('event_time') >= analysis_start) & (col('event_time') <= max_date)).count():,}")
if process_raw:
    print(f"  Process Events: {process_raw.filter((col('event_time') >= analysis_start) & (col('event_time') <= max_date)).count():,}")
print(f"  Users Analyzed: {user_combined_risk.count()}")
print(f"  Peer Groups: {CLUSTERING_K}")

print(f"\nRisk Distribution:")
for row in risk_distribution.collect():
    print(f"  {row['final_risk_level']}: {row['count']} users")

print(f"\nDetection Findings:")
print(f"  Total Findings: {len(findings)}")
if findings:
    for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
        count = builtins.sum(1 for f in findings if f['severity'] == severity)
        print(f"  {severity}: {count}")

print(f"\nHigh-Risk Users: {high_risk_users.count()}")
if high_risk_users.count() > 0:
    print("\nTop 5 Highest Risk Users:")
    for idx, row in enumerate(high_risk_users.limit(5).collect(), 1):
        print(f"  {idx}. {row['user']} - Risk Score: {row['combined_risk_score']:.3f} ({row['final_risk_level']})")

print(f"\nOutput Tables:")
print(f"  {OUTPUT_TABLE}")

print("\n" + "="*80)
print(" Analysis Complete")
print("="*80)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Next Steps
# MAGIC
# MAGIC 1. Review high-risk users and findings
# MAGIC 2. Tune anomaly thresholds based on results
# MAGIC 3. Integrate with SIEM/SOAR platforms
# MAGIC 4. Schedule notebook for regular execution
# MAGIC 5. Create dashboards for monitoring
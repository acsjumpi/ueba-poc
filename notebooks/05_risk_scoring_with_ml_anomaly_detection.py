# Databricks notebook source
# MAGIC %md
# MAGIC # CloudTrail Anomaly Detection Demo
# MAGIC
# MAGIC This notebook demonstrates basic anomaly detection techniques on AWS CloudTrail data:
# MAGIC 1. **K-means Clustering** - to identify unusual user behavior patterns
# MAGIC 2. **Time-series Outlier Detection** - to find sudden spikes or changes in activity
# MAGIC
# MAGIC **Key Features:**
# MAGIC - Real-time anomaly scoring
# MAGIC - Visual anomaly detection
# MAGIC - Simple alerting logic
# MAGIC

# COMMAND ----------

# MAGIC %pip install seaborn
# MAGIC %restart_python

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Setup and Data Loading

# COMMAND ----------

from pyspark.sql.functions import *
from pyspark.sql.types import *
from pyspark.ml.feature import VectorAssembler, StandardScaler
from pyspark.ml.clustering import KMeans
from pyspark.sql.window import Window
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# Configuration
SOURCE_TABLE = 'acs.risk_scoring.cloudtrail_gold'  # Update with your table name
DAYS_TO_ANALYZE = 7  # Last 7 days
CLUSTERING_K = 4  # Number of user behavior clusters

# COMMAND ----------

# Load CloudTrail data
df = spark.table(SOURCE_TABLE)

# Filter to recent data for demo
latest_date = df.select(max("event_date")).collect()[0][0]
start_date = latest_date - timedelta(days=DAYS_TO_ANALYZE)

recent_df = df.filter(
    (col("event_date") >= start_date) & 
    (col("event_date") <= latest_date)
)

print(f"Analyzing {recent_df.count():,} CloudTrail events from {start_date} to {latest_date}")
print(f"Total users: {recent_df.select('user_name').distinct().count()}")

# Show sample data
display(recent_df.limit(5))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Feature Engineering for Anomaly Detection

# COMMAND ----------

# Create user-level features for clustering
print("Creating user behavior features...")

user_features = recent_df.filter(col("user_name").isNotNull()).groupBy("user_name").agg(
    # Activity volume features
    count("*").alias("total_events"),
    countDistinct("event_date").alias("active_days"),
    (count("*") / countDistinct("event_date")).alias("avg_daily_events"),
    
    # Diversity features
    countDistinct("source_ip").alias("unique_ips"),
    countDistinct("aws_region").alias("unique_regions"),
    countDistinct("_event_name").alias("unique_actions"),  # Fixed: using _event_name
    
    # Temporal features
    countDistinct("event_hour").alias("unique_hours"),  # Fixed: using event_hour
    countDistinct(dayofweek(col("event_date"))).alias("unique_weekdays"),  # Fixed: using event_date
    
    # Security features (using existing pre-calculated rates)
    avg(coalesce(col("time_error_rate"), lit(0.0))).alias("avg_error_rate"),
    max(coalesce(col("time_error_rate"), lit(0.0))).alias("max_error_rate"),
    avg(coalesce(col("time_mfa_rate"), lit(0.8))).alias("avg_mfa_rate"),
    
    # Additional features from your schema
    avg(col("user_activity_count")).alias("avg_user_activity"),
    avg(col("user_unique_actions")).alias("avg_user_unique_actions"),
    avg(col("user_regions_accessed")).alias("avg_regions_accessed"),
    avg(col("user_unique_ips")).alias("avg_user_unique_ips")
).filter(col("total_events") >= 10)  # Filter out users with very low activity

print(f"Created features for {user_features.count()} users with sufficient activity")

# Show feature statistics
display(user_features.describe())

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. K-Means Clustering for User Behavior Analysis

# COMMAND ----------

print("Running K-means clustering to identify user behavior patterns...")

# Prepare features for clustering
feature_cols = [
    "total_events", "unique_ips", "unique_regions", "unique_actions",
    "avg_daily_events", "unique_hours", "avg_error_rate", "avg_user_activity"
]

# Create feature vector
assembler = VectorAssembler(inputCols=feature_cols, outputCol="features_raw")
df_assembled = assembler.transform(user_features)

# Scale features (important for clustering)
scaler = StandardScaler(inputCol="features_raw", outputCol="features", withStd=True, withMean=True)
scaler_model = scaler.fit(df_assembled)
df_scaled = scaler_model.transform(df_assembled)

# Train K-means model
kmeans = KMeans(k=CLUSTERING_K, seed=42, featuresCol="features", predictionCol="cluster")
kmeans_model = kmeans.fit(df_scaled)
df_clustered = kmeans_model.transform(df_scaled)

# Calculate distance to cluster center (anomaly indicator)
centers = kmeans_model.clusterCenters()

def calculate_distance(features, cluster):
    center = centers[cluster]
    return float(np.linalg.norm(features.toArray() - center))

distance_udf = udf(calculate_distance, FloatType())
df_with_distance = df_clustered.withColumn(
    "distance_to_center",
    distance_udf(col("features"), col("cluster"))
)

print("K-means clustering completed!")

# Show cluster distribution
print("\n Cluster Distribution:")
cluster_stats = df_with_distance.groupBy("cluster").agg(
    count("*").alias("user_count"),
    avg("total_events").alias("avg_events"),
    avg("unique_ips").alias("avg_ips"),
    avg("distance_to_center").alias("avg_distance")
).orderBy("cluster")

display(cluster_stats)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. Identify Clustering Anomalies

# COMMAND ----------

print("Identifying clustering-based anomalies...")

# Calculate distance percentiles for anomaly thresholds
distance_percentiles = df_with_distance.select(
    expr("percentile(distance_to_center, 0.90)").alias("p90"),
    expr("percentile(distance_to_center, 0.95)").alias("p95"),
    expr("percentile(distance_to_center, 0.99)").alias("p99")
).collect()[0]

print(f"Distance Percentiles: P90={distance_percentiles['p90']:.3f}, P95={distance_percentiles['p95']:.3f}, P99={distance_percentiles['p99']:.3f}")

# Add clustering anomaly scores
df_clustering_anomalies = df_with_distance.withColumn(
    "clustering_anomaly_score",
    when(col("distance_to_center") >= distance_percentiles['p99'], 1.0)
    .when(col("distance_to_center") >= distance_percentiles['p95'], 0.8)
    .when(col("distance_to_center") >= distance_percentiles['p90'], 0.6)
    .otherwise(col("distance_to_center") / distance_percentiles['p90'])
).withColumn(
    "clustering_anomaly_level",
    when(col("clustering_anomaly_score") >= 0.8, "HIGH")
    .when(col("clustering_anomaly_score") >= 0.6, "MEDIUM")
    .otherwise("LOW")
)

print("Top clustering anomalies (users with unusual behavior patterns):")
clustering_anomalies = df_clustering_anomalies.filter(col("clustering_anomaly_score") >= 0.6) \
    .select("user_name", "cluster", "distance_to_center", "clustering_anomaly_score", 
            "clustering_anomaly_level", "total_events", "unique_ips", "avg_error_rate") \
    .orderBy(desc("clustering_anomaly_score"))

display(clustering_anomalies)

print(f"Found {clustering_anomalies.count()} users with medium/high clustering anomalies")


# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Time-Series Anomaly Detection

# COMMAND ----------

print("Analyzing time-series patterns for outlier detection...")

# Create daily activity aggregations
daily_activity = recent_df.filter(col("user_name").isNotNull()).groupBy("user_name", "event_date").agg(
    count("*").alias("daily_events"),
    countDistinct("source_ip").alias("daily_unique_ips"),
    countDistinct("_event_name").alias("daily_unique_actions"),  # Fixed: using _event_name
    avg(coalesce(col("time_error_rate"), lit(0.0))).alias("daily_error_rate")
)

print(f"Created daily activity data: {daily_activity.count()} user-days")

# Calculate rolling statistics for each user
window_spec = Window.partitionBy("user_name").orderBy("event_date")
rolling_window = window_spec.rowsBetween(-3, 0)  # 4-day rolling window

daily_with_stats = daily_activity.withColumn(
    "rolling_avg_events",
    avg("daily_events").over(rolling_window)
).withColumn(
    "rolling_std_events", 
    expr("stddev(daily_events) OVER (PARTITION BY user_name ORDER BY event_date ROWS BETWEEN 3 PRECEDING AND CURRENT ROW)")
).withColumn(
    "rolling_avg_ips",
    avg("daily_unique_ips").over(rolling_window)
)

# Calculate Z-scores for anomaly detection
timeseries_anomalies = daily_with_stats.withColumn(
    "events_zscore",
    when(col("rolling_std_events") > 0, 
         abs(col("daily_events") - col("rolling_avg_events")) / col("rolling_std_events")
    ).otherwise(0)
).withColumn(
    "ips_zscore",
    when(col("rolling_avg_ips") > 0,
         abs(col("daily_unique_ips") - col("rolling_avg_ips")) / col("rolling_avg_ips")
    ).otherwise(0)
).withColumn(
    "timeseries_anomaly_score",
    when(col("events_zscore") >= 3.0, 1.0)  # 3-sigma rule
    .when(col("events_zscore") >= 2.0, 0.7)  # 2-sigma
    .otherwise(least(col("events_zscore") / 2.0, lit(1.0)))
).withColumn(
    "timeseries_anomaly_level",
    when(col("timeseries_anomaly_score") >= 0.7, "HIGH")
    .when(col("timeseries_anomaly_score") >= 0.4, "MEDIUM")
    .otherwise("LOW")
)

print("Top time-series anomalies (unusual daily activity patterns):")
ts_anomalies = timeseries_anomalies.filter(col("timeseries_anomaly_score") >= 0.4) \
    .select("user_name", "event_date", "daily_events", "rolling_avg_events", 
            "events_zscore", "timeseries_anomaly_score", "timeseries_anomaly_level") \
    .orderBy(desc("timeseries_anomaly_score"))

display(ts_anomalies.limit(20))

print(f"Found {ts_anomalies.count()} user-days with medium/high time-series anomalies")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6. Combined Anomaly Scoring

# COMMAND ----------

print("Combining clustering and time-series anomalies for final scoring...")

# Get latest time-series scores per user
latest_ts_scores = timeseries_anomalies.withColumn(
    "rank", 
    row_number().over(Window.partitionBy("user_name").orderBy(desc("event_date")))
).filter(col("rank") == 1).select(
    "user_name", 
    col("timeseries_anomaly_score").alias("latest_ts_score"),
    col("timeseries_anomaly_level").alias("latest_ts_level")
)

# Combine clustering and time-series scores
combined_scores = df_clustering_anomalies.join(latest_ts_scores, "user_name", "left").withColumn(
    "composite_anomaly_score",
    (coalesce(col("clustering_anomaly_score"), lit(0.0)) * 0.6 + 
     coalesce(col("latest_ts_score"), lit(0.0)) * 0.4)
).withColumn(
    "final_risk_level",
    when(col("composite_anomaly_score") >= 0.8, "CRITICAL")
    .when(col("composite_anomaly_score") >= 0.6, "HIGH")
    .when(col("composite_anomaly_score") >= 0.4, "MEDIUM")
    .otherwise("LOW")
).withColumn(
    "analysis_timestamp", current_timestamp()
)

print("Final Anomaly Results:")
final_anomalies = combined_scores.filter(col("composite_anomaly_score") >= 0.4) \
    .select("user_name", "clustering_anomaly_score", "latest_ts_score", 
            "composite_anomaly_score", "final_risk_level", "cluster",
            "total_events", "unique_ips", "avg_error_rate") \
    .orderBy(desc("composite_anomaly_score"))

display(final_anomalies)

# Print summary statistics
total_user_count = combined_scores.count()
risk_distribution = combined_scores.groupBy("final_risk_level").count().collect()
risk_dict = {row.final_risk_level: row['count'] for row in risk_distribution}

print(f"\nRisk Distribution Summary (Total Users: {total_user_count}):")
for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    level_count = risk_dict.get(level, 0)
    percentage = (level_count / total_user_count) * 100
    print(f"  {level}: {level_count} users ({percentage:.1f}%)")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 7. Visualization of Anomalies

# COMMAND ----------

print("Creating anomaly visualizations...")

# Try to import plotting libraries
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    plotting_available = True
except ImportError:
    print("Matplotlib/Seaborn not available, skipping visualizations")
    plotting_available = False

if plotting_available:
    # Convert to Pandas for plotting
    plot_data = combined_scores.select(
        "clustering_anomaly_score", "latest_ts_score", "composite_anomaly_score", 
        "final_risk_level", "total_events", "unique_ips"
    ).toPandas()

    # Create subplots
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))

# 1. Clustering vs Time-series scores
scatter = axes[0,0].scatter(plot_data['clustering_anomaly_score'], 
                           plot_data['latest_ts_score'], 
                           c=plot_data['composite_anomaly_score'], 
                           cmap='Reds', alpha=0.7)
axes[0,0].set_xlabel('Clustering Anomaly Score')
axes[0,0].set_ylabel('Time-series Anomaly Score')
axes[0,0].set_title('Clustering vs Time-series Anomalies')
plt.colorbar(scatter, ax=axes[0,0], label='Composite Score')

# 2. Risk level distribution
risk_counts = plot_data['final_risk_level'].value_counts()
axes[0,1].bar(risk_counts.index, risk_counts.values, color=['red', 'orange', 'yellow', 'green'])
axes[0,1].set_title('Risk Level Distribution')
axes[0,1].set_ylabel('Number of Users')

# 3. Composite anomaly score distribution
axes[1,0].hist(plot_data['composite_anomaly_score'], bins=20, alpha=0.7, color='skyblue', edgecolor='black')
axes[1,0].axvline(0.4, color='yellow', linestyle='--', label='Medium Risk')
axes[1,0].axvline(0.6, color='orange', linestyle='--', label='High Risk')
axes[1,0].axvline(0.8, color='red', linestyle='--', label='Critical Risk')
axes[1,0].set_title('Composite Anomaly Score Distribution')
axes[1,0].set_xlabel('Anomaly Score')
axes[1,0].set_ylabel('Count')
axes[1,0].legend()

# 4. Activity vs Anomaly Score
axes[1,1].scatter(plot_data['total_events'], plot_data['composite_anomaly_score'], 
                  alpha=0.6, color='purple')
axes[1,1].set_xlabel('Total Events')
axes[1,1].set_ylabel('Composite Anomaly Score')
axes[1,1].set_title('Activity Volume vs Anomaly Score')
axes[1,1].set_xscale('log')

plt.tight_layout()
plt.show()

# COMMAND ----------

# MAGIC %md
# MAGIC ## 8. Simple Alerting Logic

# COMMAND ----------

print("Generating alerts for high-risk users...")

# Define alert thresholds
CRITICAL_THRESHOLD = 0.8
HIGH_THRESHOLD = 0.6

try:
    # Select columns and convert to pandas
    pandas_df = combined_scores.select(
        "user_name",
        "composite_anomaly_score", 
        "clustering_anomaly_score",
        "latest_ts_score",
        "final_risk_level",
        "total_events",
        "unique_ips",
        "unique_regions", 
        "cluster"
    ).toPandas()

    # Filter high-risk users
    high_risk_users = pandas_df[pandas_df['composite_anomaly_score'] >= HIGH_THRESHOLD]
    print(f"Found {len(high_risk_users)} high-risk users")
    
except Exception as e:
    print(f"Error in pandas conversion: {e}")
    import traceback
    traceback.print_exc()
    high_risk_users = pd.DataFrame()
# Step 2: Process alerts 
print("Step 2: Processing alerts for high-risk users...")
alerts = []

if not high_risk_users.empty:
    for index, row in high_risk_users.iterrows():
        try:
            user_name = str(row['user_name'])
            composite_score = float(row['composite_anomaly_score'])
            clustering_score = float(row['clustering_anomaly_score'])
            timeseries_score = float(row['latest_ts_score'])
            risk_level = str(row['final_risk_level'])
            total_events = int(row['total_events'])
            unique_ips = int(row['unique_ips'])
            unique_regions = int(row['unique_regions'])
            cluster = int(row['cluster'])
            
            # Create alert dictionary
            alert = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "user_name": user_name,
                "risk_level": risk_level,
                "anomaly_score": int(composite_score * 1000) / 1000,
                "clustering_score": int(clustering_score * 1000) / 1000,
                "timeseries_score": int(timeseries_score * 1000) / 1000,
                "total_events": total_events,
                "unique_ips": unique_ips,
                "unique_regions": unique_regions,
                "cluster": cluster,
                "recommended_actions": []
            }
            
            # Add recommendations based
            if composite_score >= CRITICAL_THRESHOLD:
                alert["recommended_actions"].extend([
                    "IMMEDIATE: Review user activity logs",
                    "CONSIDER: Temporary access restrictions",
                    "INVESTIGATE: Potential security incident"
                ])
            elif composite_score >= HIGH_THRESHOLD:
                alert["recommended_actions"].extend([
                    "REVIEW: User behavior patterns within 24 hours",
                    "VERIFY: User location and access patterns"
                ])
            
            if unique_ips > 5:
                alert["recommended_actions"].append("CHECK: Multiple IP address usage")
            
            alerts.append(alert)
            print(f"Processed alert for user: {user_name}")
            
        except Exception as e:
            print(f"Error processing row {index}: {e}")
            print(f"Row data: {row.to_dict()}")
            import traceback
            traceback.print_exc()
            continue

print(f"\n Successfully generated {len(alerts)} alerts!")

# Display alerts
if alerts:
    print("\n" + "="*70)
    print(" SECURITY ALERTS GENERATED")
    print("="*70)
    
    for i, alert in enumerate(alerts, 1):
        print(f"\n ALERT #{i} - {alert['risk_level']} RISK")
        print("-" * 50)
        print(f" User: {alert['user_name']}")
        print(f" Anomaly Score: {alert['anomaly_score']}")
        print(f" Clustering Score: {alert['clustering_score']}")
        print(f" Time-series Score: {alert['timeseries_score']}")
        print(f" Activity: {alert['total_events']} events from {alert['unique_ips']} IPs")
        print(f"  Behavior Cluster: {alert['cluster']}")
        print(f" Timestamp: {alert['timestamp']}")
        
        if alert['recommended_actions']:
            print(" Recommended Actions:")
            for action in alert['recommended_actions']:
                print(f"   • {action}")
        else:
            print(" No specific actions recommended")
        
        print()
else:
    print("\nℹ No alerts generated - all users below alert threshold")

# Summary statistics
if alerts:
    print(" Alert Summary:")
    risk_counts = {}
    for alert in alerts:
        level = alert['risk_level']
        risk_counts[level] = risk_counts.get(level, 0) + 1
    
    for level, count in risk_counts.items():
        print(f"   {level}: {count} alerts")
    
    print(f"\n Total alerts: {len(alerts)}")
    #avg_score = sum([float(a['anomaly_score']) for a in alerts]) / len(alerts)
    #print(f" Average anomaly score: {round(avg_score, 3)}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 9. Save Results (Optional)

# COMMAND ----------

# Optionally save anomaly results to a table for further analysis
RESULTS_TABLE = "acs.risk_scoring.anomaly_detection_results"

print(f"Saving anomaly detection results to {RESULTS_TABLE}...")

try:
    # Save the combined scores with additional metadata
    results_to_save = combined_scores.select(
        "user_name",
        "clustering_anomaly_score", 
        "latest_ts_score",
        "composite_anomaly_score",
        "final_risk_level",
        "cluster",
        "total_events",
        "unique_ips", 
        "unique_regions",
        "avg_error_rate",
        "analysis_timestamp"
    ).withColumn("analysis_period_start", lit(start_date)) \
     .withColumn("analysis_period_end", lit(latest_date)) \
     .withColumn("detection_method", lit("clustering_timeseries"))

    # Write to Delta table
    results_to_save.write.format("delta") \
        .mode("overwrite") \
        .option("overwriteSchema", "true") \
        .saveAsTable(RESULTS_TABLE)
    
    print(f"Results saved to {RESULTS_TABLE}")
    
    # Show table info
    print(f"Saved {results_to_save.count()} user risk scores")
    
except Exception as e:
    print(f"Could not save to table (table may not exist): {str(e)}")
    print("Results are available in the current session for further analysis")
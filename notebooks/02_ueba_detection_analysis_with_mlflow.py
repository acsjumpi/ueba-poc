# Databricks notebook source
# MAGIC %md
# MAGIC # User and Entity Behavior Analytics (UEBA) Detection System with MLflow
# MAGIC
# MAGIC This notebook implements a comprehensive UEBA detection system with full MLflow integration:
# MAGIC - **MLflow Experiment Tracking** - Parameters, metrics, and artifacts
# MAGIC - **Model Registry** - Unity Catalog registration
# MAGIC - **Model Serving** - Endpoint deployment for real-time scoring
# MAGIC - **Custom PyFunc** - Production-ready inference wrapper
# MAGIC
# MAGIC **Detection Techniques:**
# MAGIC - Peer Group Analysis (K-Means clustering)
# MAGIC - Behavioral Baselines
# MAGIC - Anomaly Scoring (Statistical + ML)
# MAGIC - Risk Aggregation
# MAGIC - Detection Finding Generation

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

# MLflow imports
import mlflow
import mlflow.sklearn
import mlflow.pyfunc
from mlflow.models.signature import infer_signature
from mlflow.tracking import MlflowClient

# ML imports
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler as SklearnStandardScaler
import pickle

# Configuration
CATALOG = "main.ueba_poc"
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

# MLflow configuration
current_user = spark.sql("SELECT current_user() as user").collect()[0]["user"]
EXPERIMENT_NAME = f"/Users/{current_user}/UEBA_Detection_MLflow"
MODEL_NAME = f"{CATALOG}.ueba_anomaly_detector"  # Unity Catalog format
ENDPOINT_NAME = "ueba-anomaly-scoring"

print(f"UEBA Detection System Configuration:")
print(f"  Data source: {'Synthetic' if USE_SYNTHETIC_DATA else 'Production'}")
print(f"  Network table: {NETWORK_TABLE}")
print(f"  Process table: {PROCESS_TABLE}")
print(f"  MLflow Experiment: {EXPERIMENT_NAME}")
print(f"  Model Name: {MODEL_NAME}")
print(f"  Endpoint Name: {ENDPOINT_NAME}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Initialize MLflow

# COMMAND ----------

# Set up MLflow
mlflow.set_experiment(EXPERIMENT_NAME)
mlflow.set_registry_uri("databricks-uc")  # Use Unity Catalog
client = MlflowClient()

print(f"MLflow Tracking URI: {mlflow.get_tracking_uri()}")
print(f"MLflow Registry URI: {mlflow.get_registry_uri()}")
print(f"Experiment: {EXPERIMENT_NAME}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Data Loading and Preprocessing

# COMMAND ----------

# Start main MLflow run
with mlflow.start_run(run_name="UEBA_Full_Pipeline") as main_run:

    # Log configuration parameters
    mlflow.log_param("baseline_days", BASELINE_DAYS)
    mlflow.log_param("analysis_days", ANALYSIS_DAYS)
    mlflow.log_param("clustering_k", CLUSTERING_K)
    mlflow.log_param("zscore_threshold", ZSCORE_THRESHOLD)
    mlflow.log_param("risk_threshold_high", RISK_THRESHOLD_HIGH)
    mlflow.log_param("risk_threshold_critical", RISK_THRESHOLD_CRITICAL)
    mlflow.log_param("use_synthetic_data", USE_SYNTHETIC_DATA)

    print("Loading data...")

    # Load network activity
    try:
        network_raw = spark.table(NETWORK_TABLE)
        n_network_events = network_raw.count()
        mlflow.log_metric("network_events_loaded", n_network_events)
        print(f"Loaded {n_network_events:,} network events")
    except Exception as e:
        print(f"Error loading network table: {e}")
        print("Please run 00_generate_synthetic_data.py first")
        dbutils.notebook.exit("Network table not found")

    # Load process activity
    try:
        process_raw = spark.table(PROCESS_TABLE)
        n_process_events = process_raw.count()
        mlflow.log_metric("process_events_loaded", n_process_events)
        print(f"Loaded {n_process_events:,} process events")
    except Exception as e:
        print(f"Error loading process table: {e}")
        process_raw = None

    # Determine time range
    max_date = network_raw.select(max("event_time")).collect()[0][0]
    analysis_start = max_date - timedelta(days=ANALYSIS_DAYS)
    baseline_start = analysis_start - timedelta(days=BASELINE_DAYS)

    mlflow.log_param("baseline_start", str(baseline_start))
    mlflow.log_param("analysis_start", str(analysis_start))
    mlflow.log_param("max_date", str(max_date))

    print(f"\nTime Periods:")
    print(f"  Baseline: {baseline_start} to {analysis_start}")
    print(f"  Analysis: {analysis_start} to {max_date}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. Feature Engineering - Network Activity

# COMMAND ----------

with mlflow.start_run(run_name="UEBA_Feature_Engineering", nested=True):

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

        # Diversity metrics
        countDistinct("dest_ip").alias("unique_destinations"),
        countDistinct("dest_host").alias("unique_hosts"),
        countDistinct("dest_port").alias("unique_ports"),

        # Temporal metrics
        countDistinct(hour("event_time")).alias("active_hours"),
        min(hour("event_time")).alias("first_activity_hour"),
        max(hour("event_time")).alias("last_activity_hour")
    )

    # Calculate user baselines (averages over baseline period)
    user_baseline_network = daily_baseline_network.groupBy("user").agg(
        # Average daily volumes
        avg("daily_events").alias("baseline_avg_events"),
        stddev("daily_events").alias("baseline_std_events"),

        # Average daily data transfer
        avg("daily_bytes_out").alias("baseline_avg_bytes_out"),
        stddev("daily_bytes_out").alias("baseline_std_bytes_out"),

        # Average diversity
        avg("unique_destinations").alias("baseline_avg_destinations"),
        stddev("unique_destinations").alias("baseline_std_destinations"),

        # Temporal patterns
        avg("first_activity_hour").alias("baseline_typical_start_hour"),
        avg("last_activity_hour").alias("baseline_typical_end_hour"),

        # Active days in baseline
        countDistinct("date").alias("baseline_active_days")
    )

    n_users = user_baseline_network.count()
    mlflow.log_metric("n_users_baseline", n_users)
    print(f"Created baselines for {n_users} users")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Peer Group Analysis with MLflow

# COMMAND ----------

with mlflow.start_run(run_name="UEBA_Clustering", nested=True):

    print("Performing peer group analysis using K-means...")

    # Prepare features for clustering
    clustering_features = user_baseline_network.select(
        "user",
        "baseline_avg_events",
        "baseline_avg_bytes_out"
    ).na.fill(0)

    # Manual normalization
    stats = clustering_features.agg(
        min("baseline_avg_events").alias("min_events"),
        max("baseline_avg_events").alias("max_events"),
        min("baseline_avg_bytes_out").alias("min_bytes"),
        max("baseline_avg_bytes_out").alias("max_bytes")
    ).collect()[0]

    # Log normalization stats
    mlflow.log_metric("feature_min_events", float(stats.min_events))
    mlflow.log_metric("feature_max_events", float(stats.max_events))
    mlflow.log_metric("feature_min_bytes", float(stats.min_bytes))
    mlflow.log_metric("feature_max_bytes", float(stats.max_bytes))

    # Normalize features
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

    # Create feature vector
    assembler = VectorAssembler(inputCols=["norm_events", "norm_bytes"], outputCol="features")
    df_assembled = assembler.transform(clustering_normalized)

    # Train K-means
    kmeans = KMeans(k=CLUSTERING_K, seed=42, featuresCol="features", predictionCol="peer_group")
    kmeans_model = kmeans.fit(df_assembled)
    user_peer_groups = kmeans_model.transform(df_assembled).select("user", "peer_group")

    # Log clustering metrics
    mlflow.log_metric("kmeans_k", CLUSTERING_K)
    mlflow.log_metric("kmeans_iterations", kmeans_model.summary.numIter)
    mlflow.log_metric("kmeans_cost", kmeans_model.summary.trainingCost)

    # Save normalization params for later use
    norm_params = {
        "min_events": float(stats.min_events),
        "max_events": float(stats.max_events),
        "min_bytes": float(stats.min_bytes),
        "max_bytes": float(stats.max_bytes)
    }

    mlflow.log_dict(norm_params, "normalization_params.json")

    print(f"✓ Assigned users to {CLUSTERING_K} peer groups")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6. Analyze Current Period and Detect Anomalies

# COMMAND ----------

with mlflow.start_run(run_name="UEBA_Anomaly_Detection", nested=True):

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
        countDistinct("dest_ip").alias("unique_destinations"),
        countDistinct("dest_host").alias("unique_hosts"),
        min(hour("event_time")).alias("first_activity_hour"),
        max(hour("event_time")).alias("last_activity_hour")
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
    )

    # Temporal anomalies
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
            col("after_hours_anomaly") * 0.2
        )
    ).withColumn(
        "network_anomaly_level",
        when(col("network_anomaly_score") >= RISK_THRESHOLD_CRITICAL, "CRITICAL")
        .when(col("network_anomaly_score") >= RISK_THRESHOLD_HIGH, "HIGH")
        .when(col("network_anomaly_score") >= 0.5, "MEDIUM")
        .otherwise("LOW")
    )

    # Log anomaly statistics
    anomaly_count = network_anomalies.filter(col("network_anomaly_score") >= 0.5).count()
    critical_count = network_anomalies.filter(col("network_anomaly_score") >= RISK_THRESHOLD_CRITICAL).count()
    high_count = network_anomalies.filter(
        (col("network_anomaly_score") >= RISK_THRESHOLD_HIGH) &
        (col("network_anomaly_score") < RISK_THRESHOLD_CRITICAL)
    ).count()

    mlflow.log_metric("total_anomalies", anomaly_count)
    mlflow.log_metric("critical_anomalies", critical_count)
    mlflow.log_metric("high_anomalies", high_count)

    print(f"Detected {anomaly_count} anomalies ({critical_count} critical, {high_count} high)")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 7. Aggregate Risk Scores Per User

# COMMAND ----------

with mlflow.start_run(run_name="UEBA_Risk_Aggregation", nested=True):

    print("Aggregating risk scores per user...")

    # Get max risk score per user from network anomalies
    user_network_risk = network_anomalies.groupBy("user").agg(
        max("network_anomaly_score").alias("max_network_risk"),
        count(when(col("network_anomaly_score") >= 0.5, 1)).alias("medium_high_network_days"),
        sum("daily_events").alias("total_events"),
        sum("daily_bytes_out").alias("total_bytes_out")
    )

    # For this implementation, we'll focus on network risk
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

    # Log risk distribution
    risk_dist = user_combined_risk.groupBy("final_risk_level").count().collect()
    for row in risk_dist:
        mlflow.log_metric(f"users_{row.final_risk_level.lower()}", row['count'])

    print(f"Aggregated risk scores for {user_combined_risk.count()} users")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 8. Prepare Training Data for ML Model

# COMMAND ----------

print("Preparing features for ML model...")

# Create comprehensive feature set for each user
ml_features = user_baseline_network.join(
    user_peer_groups,
    "user"
).join(
    user_combined_risk.select("user", "combined_risk_score", "final_risk_level"),
    "user"
).na.fill(0)

# Convert to Pandas for sklearn
ml_features_pd = ml_features.select(
    "user",
    "baseline_avg_events",
    "baseline_std_events",
    "baseline_avg_bytes_out",
    "baseline_std_bytes_out",
    "baseline_avg_destinations",
    "baseline_std_destinations",
    "baseline_typical_start_hour",
    "baseline_typical_end_hour",
    "peer_group",
    "combined_risk_score",
    "final_risk_level"
).toPandas()

# Features for training (exclude user and labels)
feature_cols = [
    "baseline_avg_events",
    "baseline_std_events",
    "baseline_avg_bytes_out",
    "baseline_std_bytes_out",
    "baseline_avg_destinations",
    "baseline_std_destinations",
    "baseline_typical_start_hour",
    "baseline_typical_end_hour",
    "peer_group"
]

X = ml_features_pd[feature_cols].fillna(0)
y = (ml_features_pd['combined_risk_score'] >= RISK_THRESHOLD_HIGH).astype(int)

print(f"Training data: {len(X)} samples, {len(feature_cols)} features")
print(f"High-risk ratio: {y.mean():.2%}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 9. Train ML Model with MLflow Logging

# COMMAND ----------

with mlflow.start_run(run_name="UEBA_IsolationForest_Model", nested=True) as ml_run:

    print("Training Isolation Forest model...")

    # Scale features
    scaler = SklearnStandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train Isolation Forest
    contamination = np.minimum(0.1, y.mean() * 2)  # Adaptive contamination
    iso_forest = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100,
        max_samples='auto',
        n_jobs=-1
    )

    iso_forest.fit(X_scaled)

    # Get predictions and scores
    predictions = iso_forest.predict(X_scaled)
    anomaly_scores = iso_forest.score_samples(X_scaled)

    # Add to dataframe
    ml_features_pd['ml_anomaly'] = predictions
    ml_features_pd['ml_anomaly_score'] = anomaly_scores
    ml_features_pd['is_ml_anomaly'] = (predictions == -1).astype(int)

    # Calculate metrics
    n_ml_anomalies = (predictions == -1).sum()

    mlflow.log_param("contamination", contamination)
    mlflow.log_param("n_estimators", 100)
    mlflow.log_param("max_samples", "auto")
    mlflow.log_metric("n_ml_anomalies", n_ml_anomalies)
    mlflow.log_metric("ml_anomaly_rate", n_ml_anomalies / len(predictions))

    # Log feature names
    mlflow.log_param("feature_columns", ",".join(feature_cols))

    print(f"✓ Detected {n_ml_anomalies} ML anomalies ({n_ml_anomalies/len(predictions)*100:.2f}%)")

    # Create model signature
    signature = infer_signature(X_scaled, predictions)

    # Log scaler as artifact
    with open("/tmp/scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    mlflow.log_artifact("/tmp/scaler.pkl")

    # Log feature names as artifact
    with open("/tmp/feature_cols.json", "w") as f:
        json.dump({"features": feature_cols}, f)
    mlflow.log_artifact("/tmp/feature_cols.json")

    # Save model to MLflow
    mlflow.sklearn.log_model(
        iso_forest,
        "isolation_forest",
        signature=signature
    )

    print(f"✓ Model logged to MLflow")

    # Save run ID for later use
    ml_run_id = ml_run.info.run_id

# COMMAND ----------

# MAGIC %md
# MAGIC ## 10. Create Custom PyFunc Model for Endpoint

# COMMAND ----------

import mlflow.pyfunc

class UEBAAnomalyDetector(mlflow.pyfunc.PythonModel):
    """
    Custom MLflow PyFunc model for UEBA anomaly detection.
    Wraps Isolation Forest model with preprocessing and scoring logic.
    """

    def load_context(self, context):
        """Load model and preprocessing artifacts"""
        import pickle
        import json

        # Load scaler
        with open(context.artifacts["scaler"], "rb") as f:
            self.scaler = pickle.load(f)

        # Load feature columns
        with open(context.artifacts["feature_cols"], "r") as f:
            self.feature_cols = json.load(f)["features"]

        # Load Isolation Forest model
        self.iso_forest = mlflow.sklearn.load_model(context.artifacts["model"])

        # Load normalization parameters
        with open(context.artifacts["norm_params"], "r") as f:
            self.norm_params = json.load(f)

    def predict(self, context, model_input):
        """
        Predict anomaly scores for input data.

        Input: DataFrame or dict with user behavior features
        Output: DataFrame with anomaly predictions and risk scores
        """
        import pandas as pd
        import numpy as np

        # Convert input to DataFrame if needed
        if isinstance(model_input, dict):
            model_input = pd.DataFrame([model_input])

        # Ensure all required features are present
        for col in self.feature_cols:
            if col not in model_input.columns:
                model_input[col] = 0

        # Select and order features
        X = model_input[self.feature_cols].fillna(0)

        # Scale features
        X_scaled = self.scaler.transform(X)

        # Get predictions
        predictions = self.iso_forest.predict(X_scaled)
        anomaly_scores = self.iso_forest.score_samples(X_scaled)

        # Convert to risk scores (0-1 scale)
        # Normalize anomaly scores to [0, 1]
        min_score = anomaly_scores.min()
        max_score = anomaly_scores.max()

        if max_score > min_score:
            risk_scores = 1 - (anomaly_scores - min_score) / (max_score - min_score)
        else:
            risk_scores = np.ones_like(anomaly_scores) * 0.5

        # Determine risk levels
        risk_levels = []
        for score in risk_scores:
            if score >= 0.85:
                risk_levels.append("CRITICAL")
            elif score >= 0.7:
                risk_levels.append("HIGH")
            elif score >= 0.5:
                risk_levels.append("MEDIUM")
            else:
                risk_levels.append("LOW")

        # Create output DataFrame
        output = pd.DataFrame({
            "user": model_input.get("user", ["unknown"] * len(predictions)),
            "is_anomaly": (predictions == -1).astype(int),
            "anomaly_score": anomaly_scores,
            "risk_score": risk_scores,
            "risk_level": risk_levels,
            "peer_group": model_input.get("peer_group", [-1] * len(predictions))
        })

        return output

# COMMAND ----------

# MAGIC %md
# MAGIC ## 11. Register Custom Model to MLflow

# COMMAND ----------

with mlflow.start_run(run_name="UEBA_Custom_PyFunc_Model", nested=True) as pyfunc_run:

    print("Registering custom PyFunc model...")

    # Define artifacts needed by the model
    artifacts = {
        "model": f"runs:/{ml_run_id}/isolation_forest",
        "scaler": "/tmp/scaler.pkl",
        "feature_cols": "/tmp/feature_cols.json",
        "norm_params": "/dbfs/tmp/normalization_params.json"
    }

    # Save norm_params to DBFS
    import json
    with open("/dbfs/tmp/normalization_params.json", "w") as f:
        json.dump(norm_params, f)

    # Create example input for signature
    example_input = ml_features_pd[feature_cols].head(1)

    # Log custom model
    model_info = mlflow.pyfunc.log_model(
        artifact_path="ueba_pyfunc_model",
        python_model=UEBAAnomalyDetector(),
        artifacts=artifacts,
        input_example=example_input,
        registered_model_name=MODEL_NAME,
        pip_requirements=[
            "scikit-learn==1.3.0",
            "pandas>=1.5.3,<3.0.0",
            "numpy<2.0.0"
            "cloudpickle==2.2.1"
        ]
    )

    print(f"✓ Custom PyFunc model registered as {MODEL_NAME}")
    pyfunc_run_id = pyfunc_run.info.run_id

# COMMAND ----------

model_info.registered_model_version

# COMMAND ----------

# MAGIC %md
# MAGIC ## 12. Deploy Model to Serving Endpoint

# COMMAND ----------

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.serving import (
    ServedEntityInput,
    EndpointCoreConfigInput,
    AutoCaptureConfigInput
)

w = WorkspaceClient()

print(f"Deploying model {MODEL_NAME} to endpoint {ENDPOINT_NAME}...")

try:
    # Get latest model version
    model_version = model_info.registered_model_version

    # Check if endpoint exists
    try:
        existing_endpoint = w.serving_endpoints.get(ENDPOINT_NAME)
        print(f"Endpoint {ENDPOINT_NAME} already exists, updating...")

        # Update endpoint
        w.serving_endpoints.update_config(
            name=ENDPOINT_NAME,
            served_entities=[
                ServedEntityInput(
                    entity_name=MODEL_NAME,
                    entity_version=model_version,
                    scale_to_zero_enabled=True,
                    workload_size="Small"
                )
            ]
        )
        print(f"✓ Endpoint updated")

    except Exception:
        # Create new endpoint
        print(f"Creating new endpoint {ENDPOINT_NAME}...")

        w.serving_endpoints.create(
            name=ENDPOINT_NAME,
            config=EndpointCoreConfigInput(
                served_entities=[
                    ServedEntityInput(
                        entity_name=MODEL_NAME,
                        entity_version=model_version,
                        scale_to_zero_enabled=True,
                        workload_size="Small"
                    )
                ],
                auto_capture_config=AutoCaptureConfigInput(
                    catalog_name=CATALOG.split(".")[0] if "." in CATALOG else CATALOG,
                    schema_name=CATALOG.split(".")[1] if "." in CATALOG else "default",
                    enabled=True
                )
            )
        )
        print(f"✓ Endpoint created")

    # Wait for endpoint to be ready
    print("Waiting for endpoint to be ready...")
    w.serving_endpoints.wait_get_serving_endpoint_not_updating(ENDPOINT_NAME)

    print(f"✓ Endpoint {ENDPOINT_NAME} is ready!")
    print(f"\nEndpoint URL: https://{w.config.host}/serving-endpoints/{ENDPOINT_NAME}/invocations")

except Exception as e:
    print(f"Error deploying endpoint: {e}")
    print("You can manually deploy via Databricks UI: Machine Learning > Serving")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 13. Test Model Endpoint

# COMMAND ----------

print("Testing model endpoint...")

# Prepare test data
test_user = ml_features_pd.iloc[0][feature_cols].to_dict()

try:
    # Call endpoint
    response = w.serving_endpoints.query(
        name=ENDPOINT_NAME,
        dataframe_records=[test_user]
    )

    print("✓ Endpoint test successful!")
    print("\nSample prediction:")
    print(response)

except Exception as e:
    print(f"Endpoint not ready yet or error: {e}")
    print("Wait a few minutes for endpoint to fully initialize, then test again")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 14. Generate Detection Findings

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
for row in network_findings.limit(100).collect():  # Limit for performance
    finding = {
        "finding_id": str(uuid.uuid4()),
        "event_time": row["date"],
        "user": row["user"],
        "finding_type": "network_anomaly",
        "severity": row["network_anomaly_level"],
        "title": f"Anomalous Network Behavior - {row['user']}",
        "description": f"User {row['user']} (Peer Group {row['peer_group']}) exhibited unusual network activity",
        "risk_score": float(row["network_anomaly_score"]),
        "risk_level": row["final_risk_level"],
        "analytic_name": "ueba_network_anomaly_detection_mlflow",
        "analytic_type": "statistical_ml",
        "recommended_actions": [
            "Review detailed network logs for this user",
            "Verify user identity and location",
            "Check for data exfiltration indicators" if row["bytes_out_zscore"] > 2.0 else "Monitor ongoing activity"
        ],
        "model_version": pyfunc_run_id
    }
    findings.append(finding)

print(f"✓ Generated {len(findings)} detection findings")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 15. Save Results and Findings

# COMMAND ----------

from datetime import datetime, date

if findings:
    print(f"Saving {len(findings)} findings to {OUTPUT_TABLE}...")

    # Convert findings to DataFrame
    findings_schema = StructType([
        StructField("finding_id", StringType(), False),
        StructField("EVENT_TIME", TimestampType(), False),
        StructField("user", StringType(), False),
        StructField("finding_type", StringType(), False),
        StructField("severity", StringType(), False),
        StructField("title", StringType(), False),
        StructField("description", StringType(), False),
        StructField("risk_score", DoubleType(), False),
        StructField("risk_level", StringType(), False),
        StructField("analytic_name", StringType(), False),
        StructField("analytic_type", StringType(), False),
        StructField("model_version", StringType(), True),
        StructField("recommended_actions", ArrayType(StringType()), True)
    ])

    # Create DataFrame
    findings_rows = [(
        f["finding_id"],
        datetime.combine(f["event_time"], datetime.min.time()) if isinstance(f["event_time"], date) else f["event_time"],
        f["user"],
        f["finding_type"],
        f["severity"],
        f["title"],
        f["description"],
        f["risk_score"],
        f["risk_level"],
        f["analytic_name"],
        f["analytic_type"],
        f.get("model_version", "unknown"),
        f["recommended_actions"]
    ) for f in findings]

    findings_df = spark.createDataFrame(findings_rows, schema=findings_schema)

    # Add metadata
    findings_df = findings_df.withColumn("load_timestamp", current_timestamp()) \
                             .withColumn("analysis_version", lit("2.0_mlflow"))

    # Save to Delta
    findings_df.write.format("delta").mode("append").option("mergeSchema", "true").saveAsTable(OUTPUT_TABLE)

    print(f"✓ Findings saved to {OUTPUT_TABLE}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 16. Summary Report with MLflow Links

# COMMAND ----------

print("="*80)
print(" UEBA DETECTION SYSTEM - SUMMARY")
print("="*80)

print(f"\nMLflow Tracking:")
print(f"  Experiment: {EXPERIMENT_NAME}")
print(f"  Main Run ID: {main_run.info.run_id}")
print(f"  Model Run ID: {ml_run_id}")
print(f"  PyFunc Run ID: {pyfunc_run_id}")
print(f"  Experiment URL: {mlflow.get_tracking_uri()}/#/experiments/{mlflow.get_experiment_by_name(EXPERIMENT_NAME).experiment_id}")

print(f"\nModel Registry:")
print(f"  Model Name: {MODEL_NAME}")
print(f"  Registry: Unity Catalog")
try:
    latest_version = client.get_latest_versions(MODEL_NAME, stages=["None"])[0]
    print(f"  Latest Version: {latest_version.version}")
    print(f"  Status: {latest_version.status}")
except:
    print(f"  Status: Registering...")

print(f"\nModel Serving:")
print(f"  Endpoint Name: {ENDPOINT_NAME}")
print(f"  Endpoint URL: https://{w.config.host}/serving-endpoints/{ENDPOINT_NAME}/invocations")
print(f"  Workload: Small (scale-to-zero)")

print(f"\nData Analysis:")
print(f"  Users Analyzed: {n_users}")
print(f"  Total Anomalies: {anomaly_count}")
print(f"  Critical: {critical_count}")
print(f"  High: {high_count}")
print(f"  ML Anomalies: {n_ml_anomalies}")

print(f"\nOutput Tables:")
print(f"  Findings: {OUTPUT_TABLE}")

print(f"\nNext Steps:")
print(f"  1. Test endpoint: w.serving_endpoints.query(name='{ENDPOINT_NAME}', ...)")
print(f"  2. Monitor endpoint metrics in Databricks UI")
print(f"  3. Set up automated retraining schedule")
print(f"  4. Integrate with SIEM/SOAR platforms")
print(f"  5. Create alerting on critical findings")

print("\n" + "="*80)
print(" Analysis Complete - Model Deployed and Ready for Scoring")
print("="*80)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 17. Example: Score New Data via Endpoint

# COMMAND ----------

# Example function to score new user behavior
def score_user_behavior(user_data):
    """
    Score user behavior for anomalies using deployed endpoint.

    Args:
        user_data: dict with keys matching feature_cols

    Returns:
        dict with anomaly prediction and risk score
    """
    try:
        response = w.serving_endpoints.query(
            name=ENDPOINT_NAME,
            dataframe_records=[user_data]
        )
        return response
    except Exception as e:
        return {"error": str(e)}

# Example usage
print("Example: Scoring a user's behavior...")
print("\nInput features:")
example_user = {
    "user": "test_user",
    "baseline_avg_events": 150.0,
    "baseline_std_events": 25.0,
    "baseline_avg_bytes_out": 500000.0,
    "baseline_std_bytes_out": 100000.0,
    "baseline_avg_destinations": 10.0,
    "baseline_std_destinations": 3.0,
    "baseline_typical_start_hour": 9.0,
    "baseline_typical_end_hour": 17.0,
    "peer_group": 2
}
print(json.dumps(example_user, indent=2))

print("\nScoring...")
result = score_user_behavior(example_user)
print("\nPrediction:")
print(json.dumps(result, indent=2, default=str))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Documentation: Using the UEBA Model Endpoint
# MAGIC
# MAGIC ### REST API Usage
# MAGIC
# MAGIC ```python
# MAGIC import requests
# MAGIC import os
# MAGIC
# MAGIC # Get Databricks token
# MAGIC token = dbutils.notebook.entry_point.getDbutils().notebook().getContext().apiToken().get()
# MAGIC host = spark.conf.get("spark.databricks.workspaceUrl")
# MAGIC
# MAGIC # Endpoint URL
# MAGIC url = f"https://{host}/serving-endpoints/{ENDPOINT_NAME}/invocations"
# MAGIC
# MAGIC # Prepare request
# MAGIC headers = {
# MAGIC     "Authorization": f"Bearer {token}",
# MAGIC     "Content-Type": "application/json"
# MAGIC }
# MAGIC
# MAGIC data = {
# MAGIC     "dataframe_records": [
# MAGIC         {
# MAGIC             "baseline_avg_events": 150.0,
# MAGIC             "baseline_std_events": 25.0,
# MAGIC             "baseline_avg_bytes_out": 500000.0,
# MAGIC             "baseline_std_bytes_out": 100000.0,
# MAGIC             "baseline_avg_destinations": 10.0,
# MAGIC             "baseline_std_destinations": 3.0,
# MAGIC             "baseline_typical_start_hour": 9.0,
# MAGIC             "baseline_typical_end_hour": 17.0,
# MAGIC             "peer_group": 2
# MAGIC         }
# MAGIC     ]
# MAGIC }
# MAGIC
# MAGIC # Call endpoint
# MAGIC response = requests.post(url, json=data, headers=headers)
# MAGIC predictions = response.json()
# MAGIC ```
# MAGIC
# MAGIC ### Batch Scoring
# MAGIC
# MAGIC ```python
# MAGIC # Load new data
# MAGIC new_data = spark.table("new_user_behaviors")
# MAGIC
# MAGIC # Convert to format expected by model
# MAGIC features_df = new_data.select(feature_cols)
# MAGIC
# MAGIC # Score using MLflow
# MAGIC model_uri = f"models:/{MODEL_NAME}/latest"
# MAGIC loaded_model = mlflow.pyfunc.load_model(model_uri)
# MAGIC
# MAGIC predictions = loaded_model.predict(features_df.toPandas())
# MAGIC ```
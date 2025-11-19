-- ================================================================
-- UEBA POC - Delta Lake Table Schemas
-- ================================================================
-- This script creates the Delta Lake tables for the UEBA POC
-- Tables: network_activity, process_activity, detection_finding
-- ================================================================

-- ================================================================
-- 1. NETWORK ACTIVITY TABLE
-- Source: Firewall logs (Palo Alto Networks)
-- Purpose: Track network connections, traffic patterns, and user network behavior
-- ================================================================

CREATE TABLE IF NOT EXISTS ueba_poc.network_activity (
  -- Activity identifiers
  ACTIVITY_NAME STRING COMMENT 'Type of network activity (e.g., Traffic)',
  ACTIVITY_ID INT COMMENT 'Numeric identifier for activity type',

  -- Application and categorization
  APP_NAME STRING COMMENT 'Application name (e.g., ssl, web-browsing)',
  CATEGORY_NAME STRING COMMENT 'Activity category',
  CATEGORY_UID INT COMMENT 'Category unique identifier',
  CLASS_NAME STRING COMMENT 'Class name (e.g., Network Activity)',
  CLASS_UID INT COMMENT 'Class unique identifier',

  -- Connection details
  CONNECTION_INFO STRING COMMENT 'JSON containing direction, protocol, session info',

  -- Destination endpoint
  DST_ENDPOINT STRING COMMENT 'JSON containing destination IP, port, zone, interface',

  -- Timing
  DURATION LONG COMMENT 'Connection duration in seconds',
  END_TIME TIMESTAMP COMMENT 'Connection end time',
  START_TIME TIMESTAMP COMMENT 'Connection start time',
  EVENT_TIME TIMESTAMP COMMENT 'Event timestamp',

  -- Enrichments and metadata
  ENRICHMENTS STRING COMMENT 'Additional enrichment data',
  MESSAGE STRING COMMENT 'Log message',
  METADATA STRING COMMENT 'JSON containing log metadata, product info, version',
  OBSERVABLES STRING COMMENT 'Observable indicators',

  -- Severity
  SEVERITY STRING COMMENT 'Severity level (e.g., Informational)',
  SEVERITY_ID INT COMMENT 'Numeric severity identifier',

  -- Source endpoint
  SRC_ENDPOINT STRING COMMENT 'JSON containing source IP, port, zone, interface, owner',

  -- Status
  STATUS_CODE STRING COMMENT 'Status code',
  STATUS_DETAIL STRING COMMENT 'Status details',
  STATUS_ID INT COMMENT 'Status identifier',
  _STATUS STRING COMMENT 'Processing status',

  -- TLS and traffic
  TLS STRING COMMENT 'TLS information',
  TIMEZONE_OFFSET INT COMMENT 'Timezone offset',
  TRAFFIC STRING COMMENT 'JSON containing bytes, packets in/out',

  -- Type information
  TYPE_UID INT COMMENT 'Type unique identifier',
  TYPE_NAME STRING COMMENT 'Type name',
  URL STRING COMMENT 'URL accessed',
  UNMAPPED STRING COMMENT 'Unmapped fields from source',

  -- File tracking
  FILE_NAME STRING COMMENT 'Source file name',
  S3_FILE_TS TIMESTAMP COMMENT 'S3 file timestamp',
  LOAD_TS TIMESTAMP COMMENT 'Load timestamp into system',

  -- Counts and times
  _COUNT INT COMMENT 'Event count',
  _TIME TIMESTAMP COMMENT 'Event time',

  -- Event details
  EVENT_SIMPLENAME STRING COMMENT 'Simple event name',
  SOURCE STRING COMMENT 'Data source (e.g., pan:traffic)',
  _HOST STRING COMMENT 'Source host',
  DEST_HOST STRING COMMENT 'Destination host',

  -- Action
  _ACTION STRING COMMENT 'Action taken (e.g., Traffic, Allowed)',
  ACTION_ID INT COMMENT 'Action identifier',

  -- Network details
  DEST_PORT INT COMMENT 'Destination port number',
  SRC_IP STRING COMMENT 'Source IP address',
  DEST_IP STRING COMMENT 'Destination IP address',
  PROXY STRING COMMENT 'Proxy information',

  -- Additional fields
  EPOCH_TIME LONG COMMENT 'Unix epoch timestamp',
  FIREWALL_RULE STRING COMMENT 'JSON containing firewall rule details',
  API STRING COMMENT 'API information',
  CLOUD STRING COMMENT 'Cloud provider information',
  ACTOR STRING COMMENT 'Actor/user performing action',
  DEVICE STRING COMMENT 'JSON containing device information',

  -- Proxy details
  PROXY_CONNECTION_INFO STRING COMMENT 'Proxy connection details',
  PROXY_ENDPOINT STRING COMMENT 'Proxy endpoint information',
  PROXY_HTTP_REQUEST STRING COMMENT 'HTTP request through proxy',
  PROXY_HTTP_RESPONSE STRING COMMENT 'HTTP response through proxy',
  PROXY_TLS STRING COMMENT 'TLS through proxy',
  PROXY_TRAFFIC STRING COMMENT 'Traffic through proxy',

  -- Security
  AUTHORIZATIONS STRING COMMENT 'Authorization information',
  DISPOSITION STRING COMMENT 'Disposition of event',
  DISPOSITION_ID INT COMMENT 'Disposition identifier',
  ATTACKS STRING COMMENT 'Attack patterns detected',
  MALWARE STRING COMMENT 'Malware information',

  -- Infrastructure
  LOAD_BALANCER STRING COMMENT 'Load balancer information',
  CONTAINER STRING COMMENT 'Container information',
  NAMESPACE_PID STRING COMMENT 'Namespace PID',
  DATA_CLASSIFICATION STRING COMMENT 'Data classification level',

  -- Device identifiers
  AID STRING COMMENT 'Agent ID',
  AIP STRING COMMENT 'Agent IP',
  _USER STRING COMMENT 'User associated with activity'
)
USING DELTA
COMMENT 'Network activity events from firewall logs tracking connections, traffic, and user network behavior';


-- ================================================================
-- 2. PROCESS ACTIVITY TABLE
-- Source: Endpoint Detection and Response (CrowdStrike Falcon)
-- Purpose: Track process executions, command lines, and user process behavior
-- ================================================================

CREATE TABLE IF NOT EXISTS ueba_poc.process_activity (
  -- Activity identifiers
  ACTIVITY_NAME STRING COMMENT 'Type of process activity (e.g., Launch)',
  ACTIVITY_ID INT COMMENT 'Numeric identifier for activity type',

  -- Actor information
  ACTOR STRING COMMENT 'JSON containing process and user info performing action',

  -- Permissions
  ACTUAL_PERMISSIONS STRING COMMENT 'Actual permissions granted',
  REQUESTED_PERMISSIONS STRING COMMENT 'Requested permissions',

  -- Categorization
  CATEGORY_NAME STRING COMMENT 'Activity category (e.g., System Activity)',
  CATEGORY_UID INT COMMENT 'Category unique identifier',
  CLASS_NAME STRING COMMENT 'Class name (e.g., Process Activity)',
  CLASS_UID INT COMMENT 'Class unique identifier',

  -- Device information
  DEVICE STRING COMMENT 'JSON containing agent, domain, IP, network interfaces, OS',

  -- Timing
  DURATION LONG COMMENT 'Process duration',
  END_TIME TIMESTAMP COMMENT 'Process end time',
  START_TIME TIMESTAMP COMMENT 'Process start time',
  EVENT_TIME TIMESTAMP COMMENT 'Event timestamp',
  BIN_TIME TIMESTAMP COMMENT 'Binary file time',

  -- Enrichments and metadata
  ENRICHMENTS STRING COMMENT 'Additional enrichment data',
  EXIT_CODE INT COMMENT 'Process exit code',
  INJECTION_TYPE STRING COMMENT 'Code injection type',
  INJECTION_TYPE_ID INT COMMENT 'Injection type identifier',
  MESSAGE STRING COMMENT 'Log message',
  METADATA STRING COMMENT 'JSON containing log metadata, product info',
  MODULE STRING COMMENT 'Module information',
  OBSERVABLES STRING COMMENT 'Observable indicators',

  -- Process information
  PROCESS STRING COMMENT 'JSON containing cmd_line, created_time, file hashes, name, parent_process, pid',
  PROCESS_CMD_LINE STRING COMMENT 'Process command line',
  PROCESS_PATH STRING COMMENT 'Process file path',
  PROCESS_NAME STRING COMMENT 'Process executable name',
  PROCESS_HASH STRING COMMENT 'Process file hashes (JSON array)',
  PROCESS_TREE STRING COMMENT 'Process tree information',
  PARENT_PROCESS_NAME STRING COMMENT 'Parent process name',

  -- Severity
  SEVERITY STRING COMMENT 'Severity level',
  SEVERITY_ID INT COMMENT 'Numeric severity identifier',

  -- Status
  STATUS_CODE STRING COMMENT 'Status code',
  STATUS_DETAIL STRING COMMENT 'Status details',
  STATUS_ID INT COMMENT 'Status identifier',
  _STATUS STRING COMMENT 'Processing status',

  -- Type information
  TIMEZONE_OFFSET INT COMMENT 'Timezone offset',
  TYPE_UID INT COMMENT 'Type unique identifier',
  TYPE_NAME STRING COMMENT 'Type name',
  UNMAPPED STRING COMMENT 'Unmapped fields from source',

  -- File tracking
  FILE_NAME STRING COMMENT 'Source file name',
  S3_FILE_TS TIMESTAMP COMMENT 'S3 file timestamp',
  LOAD_TS TIMESTAMP COMMENT 'Load timestamp into system',

  -- Counts and times
  _COUNT INT COMMENT 'Event count',
  _TIME TIMESTAMP COMMENT 'Event time',

  -- Event details
  EVENT_SIMPLENAME STRING COMMENT 'Simple event name (e.g., ProcessRollup2)',
  EVENT_PLATFORM STRING COMMENT 'Platform (Win, Lin)',
  EPOCH_TIME LONG COMMENT 'Unix epoch timestamp',
  SOURCE STRING COMMENT 'Data source',

  -- Host and user
  _HOST STRING COMMENT 'Hostname where process executed',
  _USER STRING COMMENT 'User account',
  USER_ID STRING COMMENT 'User ID (SID on Windows)',

  -- Hashes
  MD5_HASH STRING COMMENT 'MD5 hash of process binary',
  SHA256_HASH STRING COMMENT 'SHA256 hash of process binary',
  IMPHASH STRING COMMENT 'Import hash',

  -- Additional fields
  API STRING COMMENT 'API information',
  CLOUD STRING COMMENT 'Cloud provider information',
  _ACTION STRING COMMENT 'Action taken (e.g., Launch)',
  ACTION_ID INT COMMENT 'Action identifier',

  -- Security
  AUTHORIZATIONS STRING COMMENT 'Authorization information',
  DISPOSITION STRING COMMENT 'Disposition of event',
  DISPOSITION_ID INT COMMENT 'Disposition identifier',
  FIREWALL_RULE STRING COMMENT 'Related firewall rule',
  ATTACKS STRING COMMENT 'Attack patterns detected',
  MALWARE STRING COMMENT 'Malware information',

  -- Infrastructure
  DATA_CLASSIFICATION STRING COMMENT 'Data classification level',
  CONTAINER STRING COMMENT 'Container information',
  NAMESPACE_PID STRING COMMENT 'Namespace PID'
)
USING DELTA
COMMENT 'Process execution events from EDR tracking launches, command lines, and user process behavior';


-- ================================================================
-- 3. DETECTION FINDING TABLE
-- Purpose: Store security detections and findings from UEBA analysis
-- ================================================================

CREATE TABLE IF NOT EXISTS ueba_poc.detection_finding (
  -- Activity identifiers
  ACTIVITY_NAME STRING COMMENT 'Detection activity name (e.g., Create)',
  ACTIVITY_ID INT COMMENT 'Numeric identifier for activity type',

  -- Resources and categorization
  RESOURCES STRING COMMENT 'Resources involved',
  CATEGORY_NAME STRING COMMENT 'Finding category',
  CATEGORY_UID INT COMMENT 'Category unique identifier',
  CLASS_NAME STRING COMMENT 'Class name (e.g., Detection Finding)',
  CLASS_UID INT COMMENT 'Class unique identifier',

  -- Finding details
  COMMENT STRING COMMENT 'Additional comments',
  CONFIDENCE STRING COMMENT 'Confidence level of detection',
  CONFIDENCE_ID INT COMMENT 'Confidence identifier',
  CONFIDENCE_CORE DOUBLE COMMENT 'Core confidence score',

  -- Timing
  DURATION LONG COMMENT 'Duration of activity',
  END_TIME TIMESTAMP COMMENT 'Activity end time',
  START_TIME TIMESTAMP COMMENT 'Activity start time',
  EVENT_TIME TIMESTAMP COMMENT 'Event timestamp',

  -- Enrichments and evidence
  ENRICHMENTS STRING COMMENT 'Additional enrichment data',
  EVIDENCES STRING COMMENT 'JSON containing evidence (actor, connection_info, endpoints, file, protocol, url)',
  FINDING_INFO STRING COMMENT 'JSON containing analytic name/type, first_seen_time, title, type, uid',

  -- Risk assessment
  IMPACT_SCORE DOUBLE COMMENT 'Impact score',
  IMPACT STRING COMMENT 'Impact description',
  IMPACT_ID INT COMMENT 'Impact identifier',
  RISK_DETAILS STRING COMMENT 'Detailed risk information',
  RISK_LEVEL STRING COMMENT 'Risk level (e.g., Informational, Low, Medium, High, Critical)',
  RISK_LEVEL_ID INT COMMENT 'Risk level identifier',
  RISK_SCORE DOUBLE COMMENT 'Calculated risk score',

  -- Severity
  SEVERITY STRING COMMENT 'Severity level',
  SEVERITY_ID INT COMMENT 'Numeric severity identifier',

  -- Message and metadata
  MESSAGE STRING COMMENT 'Detection message',
  METADATA STRING COMMENT 'JSON containing event_code, log_provider, product, version',
  OBSERVABLES STRING COMMENT 'Observable indicators',

  -- Remediation
  REMEDIATION STRING COMMENT 'Recommended remediation actions',

  -- Status
  STATUS_CODE STRING COMMENT 'Status code',
  STATUS_DETAIL STRING COMMENT 'Status details',
  STATUS_ID INT COMMENT 'Status identifier',
  _STATUS STRING COMMENT 'Processing status',

  -- Type information
  TIMEZONE_OFFSET INT COMMENT 'Timezone offset',
  TYPE_UID INT COMMENT 'Type unique identifier',
  TYPE_NAME STRING COMMENT 'Type name',
  UNMAPPED STRING COMMENT 'Unmapped fields from source',
  VULNERABILITIES STRING COMMENT 'Related vulnerabilities',

  -- File tracking
  FILE_NAME STRING COMMENT 'Source file name',
  S3_FILE_TS TIMESTAMP COMMENT 'S3 file timestamp',
  LOAD_TS TIMESTAMP COMMENT 'Load timestamp into system',

  -- Counts and times
  _COUNT INT COMMENT 'Event count',
  _TIME TIMESTAMP COMMENT 'Event time',

  -- Additional fields
  API STRING COMMENT 'API information',
  CLOUD STRING COMMENT 'Cloud provider information',
  ACTOR STRING COMMENT 'Actor/user involved in finding',
  DEVICE STRING COMMENT 'JSON containing device information',

  -- Action
  ACTION STRING COMMENT 'Action taken (e.g., Allowed, Blocked)',
  ACTION_ID INT COMMENT 'Action identifier',

  -- Security
  AUTHORIZATIONS STRING COMMENT 'Authorization information',
  DISPOSITION STRING COMMENT 'Disposition of finding',
  DISPOSITION_ID INT COMMENT 'Disposition identifier',
  FIREWALL_RULE STRING COMMENT 'Related firewall rule',
  ATTACKS STRING COMMENT 'Attack patterns detected',
  MALWARE STRING COMMENT 'Malware information',

  -- Infrastructure
  DATA_CLASSIFICATION STRING COMMENT 'Data classification level',
  CONTAINER STRING COMMENT 'Container information',
  NAMESPACE_PID STRING COMMENT 'Namespace PID'
)
USING DELTA
COMMENT 'Security detections and findings from UEBA analysis identifying anomalous behavior';


-- ================================================================
-- OPTIMIZATION COMMANDS
-- ================================================================

-- Optimize tables for better query performance
OPTIMIZE ueba_poc.network_activity;
OPTIMIZE ueba_poc.process_activity;
OPTIMIZE ueba_poc.detection_finding;

-- Analyze tables to update statistics
ANALYZE TABLE ueba_poc.network_activity COMPUTE STATISTICS;
ANALYZE TABLE ueba_poc.process_activity COMPUTE STATISTICS;
ANALYZE TABLE ueba_poc.detection_finding COMPUTE STATISTICS;

-- ================================================================
-- VERIFICATION
-- ================================================================

-- Show table information
DESCRIBE EXTENDED ueba_poc.network_activity;
DESCRIBE EXTENDED ueba_poc.process_activity;
DESCRIBE EXTENDED ueba_poc.detection_finding;
# Configuration settings for LiveSec AI
import os
from dotenv import load_dotenv

load_dotenv()

# OpenAI API Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "gpt-3.5-turbo"

# Data paths
DATA_DIR = "data"
LOGIN_LOGS_FILE = f"{DATA_DIR}/login_logs.csv"
NETWORK_LOGS_FILE = f"{DATA_DIR}/network_logs.csv"
FILE_TRANSFER_LOGS_FILE = f"{DATA_DIR}/file_transfer_logs.csv"
ANOMALIES_FILE = f"{DATA_DIR}/anomalies.csv"

# Anomaly detection thresholds
LOGIN_ANOMALY_THRESHOLDS = {
    "unusual_hour_start": 22,  # 10 PM
    "unusual_hour_end": 6,     # 6 AM
    "failed_login_threshold": 5,
    "geo_distance_threshold": 1000  # km
}

NETWORK_ANOMALY_THRESHOLDS = {
    "traffic_spike_multiplier": 3.0,
    "connection_threshold": 100,
    "data_volume_threshold": 1000000  # bytes
}

FILE_TRANSFER_ANOMALY_THRESHOLDS = {
    "large_file_threshold": 100000000,  # 100MB
    "unusual_hour_start": 22,
    "unusual_hour_end": 6,
    "access_frequency_threshold": 10
}

# Severity scoring
SEVERITY_SCORES = {
    "low": {"min": 0, "max": 3},
    "medium": {"min": 4, "max": 7},
    "high": {"min": 8, "max": 10}
}

# Dashboard settings
DASHBOARD_REFRESH_INTERVAL = 2  # seconds
MAX_DISPLAYED_LOGS = 100
MAX_DISPLAYED_ANOMALIES = 50

# Streaming settings
LOG_GENERATION_INTERVAL = 1  # seconds
PATHWAY_REFRESH_RATE = 1000  # milliseconds
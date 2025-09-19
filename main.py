"""
Main streaming pipeline for LiveSec AI
Continuously ingests logs, detects anomalies, and generates AI explanations
"""
import pandas as pd
import json
import time
from datetime import datetime
import os
import sys
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add src directory to path
sys.path.append('src')

from anomaly_detector import AnomalyDetector
from llm_explainer import LLMExplainer
from config import (
    LOGIN_LOGS_FILE, NETWORK_LOGS_FILE, FILE_TRANSFER_LOGS_FILE, 
    ANOMALIES_FILE, DATA_DIR
)

class LogFileHandler(FileSystemEventHandler):
    """Handle file system events for log files"""
    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.last_positions = {}
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        filename = os.path.basename(event.src_path)
        if filename in ['login_logs.csv', 'network_logs.csv', 'file_transfer_logs.csv']:
            self.pipeline.process_new_log_entries(event.src_path)

class LiveSecPipeline:
    def __init__(self):
        self.detector = AnomalyDetector()
        self.explainer = LLMExplainer()
        self.processed_count = 0
        self.anomaly_count = 0
        self.file_positions = {}
        
        # Ensure data directory exists
        os.makedirs(DATA_DIR, exist_ok=True)
        
        # Initialize anomalies CSV file
        self._init_anomalies_file()
        
        # Initialize file positions
        self._init_file_positions()
        
        print("LiveSec AI Pipeline Initialized")
        print(f"Monitoring: {LOGIN_LOGS_FILE}, {NETWORK_LOGS_FILE}, {FILE_TRANSFER_LOGS_FILE}")
        print(f"Anomalies output: {ANOMALIES_FILE}")
    
    def _init_anomalies_file(self):
        """Initialize the anomalies CSV file with headers"""
        if not os.path.exists(ANOMALIES_FILE):
            with open(ANOMALIES_FILE, 'w') as f:
                headers = [
                    'timestamp', 'type', 'severity', 'severity_score', 'description',
                    'log_type', 'ai_explanation', 'details'
                ]
                f.write(','.join(headers) + '\n')
    
    def _init_file_positions(self):
        """Initialize file positions to track what we've already processed"""
        for file_path in [LOGIN_LOGS_FILE, NETWORK_LOGS_FILE, FILE_TRANSFER_LOGS_FILE]:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    # Get current file size to start monitoring from end
                    f.seek(0, 2)  # Seek to end
                    self.file_positions[file_path] = f.tell()
            else:
                self.file_positions[file_path] = 0
    
    def process_new_log_entries(self, file_path):
        """Process new entries in a log file"""
        try:
            # Read new lines from the file
            with open(file_path, 'r') as f:
                f.seek(self.file_positions.get(file_path, 0))
                new_lines = f.readlines()
                self.file_positions[file_path] = f.tell()
            
            if not new_lines:
                return
            
            # Determine log type
            if 'login' in file_path:
                log_type = 'login'
                self._process_login_entries(new_lines)
            elif 'network' in file_path:
                log_type = 'network'
                self._process_network_entries(new_lines)
            elif 'file_transfer' in file_path:
                log_type = 'file_transfer'
                self._process_file_entries(new_lines)
                
        except Exception as e:
            print(f"[WARNING] Error processing {file_path}: {str(e)}")
    
    def _process_login_entries(self, lines):
        """Process new login log entries"""
        for line in lines:
            if line.strip() and not line.startswith('timestamp'):
                try:
                    parts = line.strip().split(',')
                    if len(parts) >= 6:
                        log_entry = {
                            'timestamp': parts[0],
                            'username': parts[1],
                            'ip_address': parts[2],
                            'country': parts[3],
                            'success': parts[4].lower() == 'true',
                            'user_agent': ','.join(parts[5:])  # Join in case user agent has commas
                        }
                        self._detect_and_process_anomalies('login', log_entry)
                except Exception as e:
                    print(f"[WARNING] Error parsing login entry: {str(e)}")
    
    def _process_network_entries(self, lines):
        """Process new network log entries"""
        for line in lines:
            if line.strip() and not line.startswith('timestamp'):
                try:
                    parts = line.strip().split(',')
                    if len(parts) >= 8:
                        log_entry = {
                            'timestamp': parts[0],
                            'source_ip': parts[1],
                            'dest_ip': parts[2],
                            'port': int(parts[3]),
                            'protocol': parts[4],
                            'bytes_sent': int(parts[5]),
                            'bytes_received': int(parts[6]),
                            'connections': int(parts[7])
                        }
                        self._detect_and_process_anomalies('network', log_entry)
                except Exception as e:
                    print(f"[WARNING] Error parsing network entry: {str(e)}")
    
    def _process_file_entries(self, lines):
        """Process new file transfer log entries"""
        for line in lines:
            if line.strip() and not line.startswith('timestamp'):
                try:
                    parts = line.strip().split(',')
                    if len(parts) >= 6:
                        log_entry = {
                            'timestamp': parts[0],
                            'username': parts[1],
                            'filename': parts[2],
                            'file_size': int(parts[3]),
                            'action': parts[4],
                            'destination': parts[5]
                        }
                        self._detect_and_process_anomalies('file_transfer', log_entry)
                except Exception as e:
                    print(f"[WARNING] Error parsing file entry: {str(e)}")
    
    def _detect_and_process_anomalies(self, log_type, log_entry):
        """Detect anomalies and process them"""
        try:
            anomalies = self.detector.detect_anomalies(log_type, log_entry)
            
            for anomaly in anomalies:
                # Generate AI explanation
                explained_anomaly = self.explainer.explain_anomaly(anomaly)
                
                # Save to file
                self.save_anomaly(explained_anomaly)
                
                # Print alert
                self.print_alert(explained_anomaly)
                
                self.anomaly_count += 1
            
            self.processed_count += 1
            
        except Exception as e:
            print(f"[WARNING] Error processing {log_type} anomaly: {str(e)}")
    
    def save_anomaly(self, anomaly: dict):
        """Save anomaly to CSV file"""
        try:
            with open(ANOMALIES_FILE, 'a') as f:
                details_str = json.dumps(anomaly.get('details', {})).replace(',', ';')
                row = [
                    anomaly.get('timestamp', ''),
                    anomaly.get('type', ''),
                    anomaly.get('severity', ''),
                    str(anomaly.get('severity_score', '')),
                    anomaly.get('description', '').replace(',', ';'),
                    anomaly.get('log_type', ''),
                    anomaly.get('ai_explanation', '').replace(',', ';'),
                    details_str
                ]
                f.write(','.join(f'"{item}"' for item in row) + '\n')
                f.flush()
        except Exception as e:
            print(f"Error saving anomaly: {str(e)}")
    
    def print_alert(self, anomaly: dict):
        """Print formatted alert to console"""
        severity = anomaly.get('severity', 'Unknown')
        timestamp = anomaly.get('timestamp', '')
        anomaly_type = anomaly.get('type', '')
        description = anomaly.get('description', '')
        explanation = anomaly.get('ai_explanation', '')
        
        # Color coding based on severity
        if severity == 'High':
            color = '\033[91m'  # Red
            icon = '[HIGH]'
        elif severity == 'Medium':
            color = '\033[93m'  # Yellow
            icon = '[MEDIUM]'
        else:
            color = '\033[94m'  # Blue
            icon = '[LOW]'
        
        reset_color = '\033[0m'
        
        print(f"\n{color}{icon} {severity.upper()} SEVERITY ANOMALY{reset_color}")
        print(f"   Time: {timestamp}")
        print(f"   Type: {anomaly_type}")
        print(f"   Alert: {description}")
        print(f"   Analysis: {explanation}")
        print("-" * 80)
    
    def update_baselines_periodically(self):
        """Update baseline statistics from existing logs"""
        try:
            # Read existing logs to update baselines
            login_df = pd.DataFrame()
            network_df = pd.DataFrame()
            file_df = pd.DataFrame()
            
            if os.path.exists(LOGIN_LOGS_FILE):
                login_df = pd.read_csv(LOGIN_LOGS_FILE)
                if not login_df.empty:
                    login_df['timestamp'] = pd.to_datetime(login_df['timestamp'])
            
            if os.path.exists(NETWORK_LOGS_FILE):
                network_df = pd.read_csv(NETWORK_LOGS_FILE)
                if not network_df.empty:
                    network_df['timestamp'] = pd.to_datetime(network_df['timestamp'])
            
            if os.path.exists(FILE_TRANSFER_LOGS_FILE):
                file_df = pd.read_csv(FILE_TRANSFER_LOGS_FILE)
                if not file_df.empty:
                    file_df['timestamp'] = pd.to_datetime(file_df['timestamp'])
            
            self.detector.update_baseline_stats(login_df, network_df, file_df)
            print(f"Updated baseline statistics (Processed: {self.processed_count}, Anomalies: {self.anomaly_count})")
            
        except Exception as e:
            print(f"Error updating baselines: {str(e)}")
    
    def process_existing_logs(self):
        """Process existing logs on startup"""
        print("Processing existing logs...")
        
        # Process existing logs to establish baselines
        for file_path in [LOGIN_LOGS_FILE, NETWORK_LOGS_FILE, FILE_TRANSFER_LOGS_FILE]:
            if os.path.exists(file_path):
                self.process_new_log_entries(file_path)
        
        print(f"Processed existing logs (Entries: {self.processed_count}, Anomalies: {self.anomaly_count})")
    
    def run(self):
        """Run the main streaming pipeline using file watching"""
        print("Starting LiveSec AI real-time monitoring...")
        
        # Check if log files exist
        required_files = [LOGIN_LOGS_FILE, NETWORK_LOGS_FILE, FILE_TRANSFER_LOGS_FILE]
        missing_files = [f for f in required_files if not os.path.exists(f)]
        
        if missing_files:
            print("Missing log files:")
            for file in missing_files:
                print(f"   - {file}")
            print("\nRun 'python demo.py' first to generate sample logs.")
            return
        
        # Update baselines from existing data
        self.update_baselines_periodically()
        
        # Process existing logs
        self.process_existing_logs()
        
        # Set up file watcher
        event_handler = LogFileHandler(self)
        observer = Observer()
        observer.schedule(event_handler, DATA_DIR, recursive=False)
        observer.start()
        
        print("File watcher started - monitoring for new log entries...")
        print("Dashboard: streamlit run dashboard.py")
        print("Press Ctrl+C to stop")
        
        # Periodic baseline updates
        last_baseline_update = time.time()
        baseline_update_interval = 30  # Update every 30 seconds
        
        try:
            while True:
                time.sleep(1)
                
                # Update baselines periodically
                if time.time() - last_baseline_update > baseline_update_interval:
                    self.update_baselines_periodically()
                    last_baseline_update = time.time()
                    
        except KeyboardInterrupt:
            print(f"\nPipeline stopped by user")
            print(f"Final stats - Processed: {self.processed_count}, Anomalies detected: {self.anomaly_count}")
            observer.stop()
        except Exception as e:
            print(f"Pipeline error: {str(e)}")
            observer.stop()
        
        observer.join()

def main():
    """Main function to run the LiveSec AI pipeline"""
    print("=" * 80)
    print("LiveSec AI - Real-Time Cybersecurity Co-Pilot")
    print("=" * 80)
    
    # Check if log files exist
    required_files = [LOGIN_LOGS_FILE, NETWORK_LOGS_FILE, FILE_TRANSFER_LOGS_FILE]
    missing_files = [f for f in required_files if not os.path.exists(f)]
    
    if missing_files:
        print("Missing log files:")
        for file in missing_files:
            print(f"   - {file}")
        print("\nRun 'python demo.py' first to generate sample logs.")
        return
    
    pipeline = LiveSecPipeline()
    pipeline.run()

if __name__ == "__main__":
    main()
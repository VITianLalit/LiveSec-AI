"""
Anomaly detection engine for LiveSec AI
Detects login, network traffic, and data exfiltration anomalies using statistical baselines and rules
"""
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import math
from config import (
    LOGIN_ANOMALY_THRESHOLDS, NETWORK_ANOMALY_THRESHOLDS, 
    FILE_TRANSFER_ANOMALY_THRESHOLDS, SEVERITY_SCORES
)

class AnomalyDetector:
    def __init__(self):
        self.baseline_stats = {}
        self.geo_locations = {
            'USA': (39.8283, -98.5795),
            'Canada': (56.1304, -106.3468),
            'UK': (55.3781, -3.4360),
            'Germany': (51.1657, 10.4515),
            'France': (46.6034, 1.8883),
            'Japan': (36.2048, 138.2529),
            'Australia': (-25.2744, 133.7751),
            'Brazil': (-14.2350, -51.9253),
            'Russia': (61.5240, 105.3188),
            'China': (35.8617, 104.1954),
            'North Korea': (40.3399, 127.5101),
            'Iran': (32.4279, 53.6880)
        }
    
    def calculate_distance(self, country1: str, country2: str) -> float:
        """Calculate distance between two countries in kilometers"""
        if country1 not in self.geo_locations or country2 not in self.geo_locations:
            return 0
        
        lat1, lon1 = self.geo_locations[country1]
        lat2, lon2 = self.geo_locations[country2]
        
        # Haversine formula
        R = 6371  # Earth's radius in kilometers
        
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)
        
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        
        return R * c
    
    def is_unusual_hour(self, timestamp: str) -> bool:
        """Check if the timestamp is outside normal business hours"""
        try:
            dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
            hour = dt.hour
            
            # Unusual if between 10 PM and 6 AM
            return (hour >= LOGIN_ANOMALY_THRESHOLDS['unusual_hour_start'] or 
                   hour <= LOGIN_ANOMALY_THRESHOLDS['unusual_hour_end'])
        except:
            return False
    
    def update_baseline_stats(self, login_logs: pd.DataFrame, network_logs: pd.DataFrame, file_logs: pd.DataFrame):
        """Update baseline statistics for anomaly detection"""
        self.baseline_stats = {}
        
        # Login baseline stats
        if not login_logs.empty:
            self.baseline_stats['login'] = {
                'avg_logins_per_hour': len(login_logs) / max(1, len(login_logs['timestamp'].dt.hour.unique())),
                'common_countries': login_logs['country'].value_counts().to_dict(),
                'failed_login_rate': (login_logs['success'] == False).mean(),
                'user_login_patterns': login_logs.groupby('username')['country'].apply(list).to_dict()
            }
        
        # Network baseline stats
        if not network_logs.empty:
            self.baseline_stats['network'] = {
                'avg_bytes_sent': network_logs['bytes_sent'].mean(),
                'avg_bytes_received': network_logs['bytes_received'].mean(),
                'avg_connections': network_logs['connections'].mean(),
                'std_bytes_sent': network_logs['bytes_sent'].std(),
                'std_bytes_received': network_logs['bytes_received'].std(),
                'std_connections': network_logs['connections'].std(),
                'common_ports': network_logs['port'].value_counts().to_dict()
            }
        
        # File transfer baseline stats
        if not file_logs.empty:
            self.baseline_stats['file_transfer'] = {
                'avg_file_size': file_logs['file_size'].mean(),
                'std_file_size': file_logs['file_size'].std(),
                'common_actions': file_logs['action'].value_counts().to_dict(),
                'common_destinations': file_logs['destination'].value_counts().to_dict(),
                'user_file_patterns': file_logs.groupby('username')['file_size'].mean().to_dict()
            }
    
    def detect_login_anomalies(self, log_entry: Dict) -> List[Dict]:
        """Detect login-related anomalies"""
        anomalies = []
        timestamp = log_entry['timestamp']
        username = log_entry['username']
        country = log_entry['country']
        success = log_entry['success']
        
        # Anomaly 1: Unusual login time
        if self.is_unusual_hour(timestamp):
            anomalies.append({
                'type': 'unusual_login_time',
                'description': f"Login outside normal hours: {timestamp}",
                'severity_score': 6,
                'details': {
                    'username': username,
                    'timestamp': timestamp,
                    'country': country
                }
            })
        
        # Anomaly 2: Suspicious country
        suspicious_countries = ['Russia', 'China', 'North Korea', 'Iran']
        if country in suspicious_countries:
            anomalies.append({
                'type': 'suspicious_geo_location',
                'description': f"Login from suspicious country: {country}",
                'severity_score': 8,
                'details': {
                    'username': username,
                    'country': country,
                    'timestamp': timestamp
                }
            })
        
        # Anomaly 3: Failed login (potential brute force)
        if not success:
            anomalies.append({
                'type': 'failed_login',
                'description': f"Failed login attempt for user: {username}",
                'severity_score': 4,
                'details': {
                    'username': username,
                    'country': country,
                    'timestamp': timestamp
                }
            })
        
        # Anomaly 4: Geographic inconsistency (if we have baseline data)
        if 'login' in self.baseline_stats and username in self.baseline_stats['login']['user_login_patterns']:
            user_countries = self.baseline_stats['login']['user_login_patterns'][username]
            if user_countries and country not in user_countries:
                # Check if this is a significant geographic jump
                min_distance = float('inf')
                for prev_country in set(user_countries):
                    distance = self.calculate_distance(country, prev_country)
                    min_distance = min(min_distance, distance)
                
                if min_distance > LOGIN_ANOMALY_THRESHOLDS['geo_distance_threshold']:
                    anomalies.append({
                        'type': 'geo_inconsistency',
                        'description': f"Unusual geographic login: {country} (>{min_distance:.0f}km from usual locations)",
                        'severity_score': 7,
                        'details': {
                            'username': username,
                            'new_country': country,
                            'usual_countries': list(set(user_countries)),
                            'distance': min_distance
                        }
                    })
        
        return anomalies
    
    def detect_network_anomalies(self, log_entry: Dict) -> List[Dict]:
        """Detect network traffic anomalies"""
        anomalies = []
        bytes_sent = log_entry['bytes_sent']
        bytes_received = log_entry['bytes_received']
        connections = log_entry['connections']
        port = log_entry['port']
        
        # Anomaly 1: Traffic spike
        if 'network' in self.baseline_stats:
            baseline = self.baseline_stats['network']
            
            # Check for bytes sent spike
            if bytes_sent > baseline['avg_bytes_sent'] * NETWORK_ANOMALY_THRESHOLDS['traffic_spike_multiplier']:
                anomalies.append({
                    'type': 'traffic_spike_sent',
                    'description': f"Unusual outbound traffic: {bytes_sent:,} bytes (avg: {baseline['avg_bytes_sent']:,.0f})",
                    'severity_score': 7,
                    'details': {
                        'bytes_sent': bytes_sent,
                        'avg_baseline': baseline['avg_bytes_sent'],
                        'multiplier': bytes_sent / baseline['avg_bytes_sent']
                    }
                })
            
            # Check for bytes received spike
            if bytes_received > baseline['avg_bytes_received'] * NETWORK_ANOMALY_THRESHOLDS['traffic_spike_multiplier']:
                anomalies.append({
                    'type': 'traffic_spike_received',
                    'description': f"Unusual inbound traffic: {bytes_received:,} bytes (avg: {baseline['avg_bytes_received']:,.0f})",
                    'severity_score': 6,
                    'details': {
                        'bytes_received': bytes_received,
                        'avg_baseline': baseline['avg_bytes_received'],
                        'multiplier': bytes_received / baseline['avg_bytes_received']
                    }
                })
        
        # Anomaly 2: Suspicious ports
        suspicious_ports = [1337, 4444, 6666, 31337, 1234, 12345]
        if port in suspicious_ports:
            anomalies.append({
                'type': 'suspicious_port',
                'description': f"Connection to suspicious port: {port}",
                'severity_score': 8,
                'details': {
                    'port': port,
                    'bytes_sent': bytes_sent,
                    'bytes_received': bytes_received
                }
            })
        
        # Anomaly 3: High connection count
        if connections > NETWORK_ANOMALY_THRESHOLDS['connection_threshold']:
            anomalies.append({
                'type': 'high_connection_count',
                'description': f"High number of connections: {connections}",
                'severity_score': 6,
                'details': {
                    'connections': connections,
                    'threshold': NETWORK_ANOMALY_THRESHOLDS['connection_threshold']
                }
            })
        
        return anomalies
    
    def detect_file_transfer_anomalies(self, log_entry: Dict) -> List[Dict]:
        """Detect file transfer and data exfiltration anomalies"""
        anomalies = []
        username = log_entry['username']
        filename = log_entry['filename']
        file_size = log_entry['file_size']
        action = log_entry['action']
        destination = log_entry['destination']
        timestamp = log_entry['timestamp']
        
        # Anomaly 1: Large file transfer
        if file_size > FILE_TRANSFER_ANOMALY_THRESHOLDS['large_file_threshold']:
            anomalies.append({
                'type': 'large_file_transfer',
                'description': f"Large file transfer: {filename} ({file_size:,} bytes)",
                'severity_score': 7,
                'details': {
                    'filename': filename,
                    'file_size': file_size,
                    'action': action,
                    'destination': destination,
                    'username': username
                }
            })
        
        # Anomaly 2: Sensitive file patterns
        sensitive_keywords = ['password', 'key', 'secret', 'confidential', 'customer', 'financial', 'security']
        if any(keyword in filename.lower() for keyword in sensitive_keywords):
            anomalies.append({
                'type': 'sensitive_file_access',
                'description': f"Access to sensitive file: {filename}",
                'severity_score': 8,
                'details': {
                    'filename': filename,
                    'action': action,
                    'destination': destination,
                    'username': username,
                    'file_size': file_size
                }
            })
        
        # Anomaly 3: Unusual time for file transfer
        if self.is_unusual_hour(timestamp):
            anomalies.append({
                'type': 'unusual_time_file_transfer',
                'description': f"File transfer outside normal hours: {filename}",
                'severity_score': 6,
                'details': {
                    'filename': filename,
                    'timestamp': timestamp,
                    'action': action,
                    'username': username
                }
            })
        
        # Anomaly 4: External destination for large files
        external_destinations = ['external_drive', 'cloud_storage', 'email', 'ftp_server']
        if destination in external_destinations and file_size > 10000000:  # 10MB
            anomalies.append({
                'type': 'potential_data_exfiltration',
                'description': f"Large file sent to external destination: {filename} to {destination}",
                'severity_score': 9,
                'details': {
                    'filename': filename,
                    'destination': destination,
                    'file_size': file_size,
                    'action': action,
                    'username': username
                }
            })
        
        return anomalies
    
    def categorize_severity(self, score: int) -> str:
        """Categorize severity score into Low/Medium/High"""
        if score <= SEVERITY_SCORES['low']['max']:
            return 'Low'
        elif score <= SEVERITY_SCORES['medium']['max']:
            return 'Medium'
        else:
            return 'High'
    
    def detect_anomalies(self, log_type: str, log_entry: Dict) -> List[Dict]:
        """Main method to detect anomalies based on log type"""
        anomalies = []
        
        try:
            if log_type == 'login':
                anomalies = self.detect_login_anomalies(log_entry)
            elif log_type == 'network':
                anomalies = self.detect_network_anomalies(log_entry)
            elif log_type == 'file_transfer':
                anomalies = self.detect_file_transfer_anomalies(log_entry)
            
            # Add severity category to each anomaly
            for anomaly in anomalies:
                anomaly['severity'] = self.categorize_severity(anomaly['severity_score'])
                anomaly['log_type'] = log_type
                anomaly['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        except Exception as e:
            print(f"Error detecting anomalies for {log_type}: {str(e)}")
        
        return anomalies
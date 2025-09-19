"""
Demo script to generate realistic cybersecurity logs for LiveSec AI
Generates login logs, network traffic logs, and file transfer logs with some anomalies
"""
import csv
import random
import time
from datetime import datetime, timedelta
from faker import Faker
import threading
import os
from config import (
    LOGIN_LOGS_FILE, NETWORK_LOGS_FILE, FILE_TRANSFER_LOGS_FILE, 
    LOG_GENERATION_INTERVAL, DATA_DIR
)

fake = Faker()

class LogGenerator:
    def __init__(self):
        self.countries = ['USA', 'Canada', 'UK', 'Germany', 'France', 'Japan', 'Australia', 'Brazil']
        self.suspicious_countries = ['Russia', 'China', 'North Korea', 'Iran']
        self.normal_users = ['alice.smith', 'bob.jones', 'carol.white', 'david.brown', 'eve.davis']
        self.admin_users = ['admin', 'root', 'sysadmin', 'security_admin']
        self.file_types = ['.pdf', '.docx', '.xlsx', '.txt', '.csv', '.sql', '.config']
        self.sensitive_files = ['customer_data.csv', 'financial_report.xlsx', 'security_keys.txt', 'user_passwords.sql']
        
        # Ensure data directory exists
        os.makedirs(DATA_DIR, exist_ok=True)
        
        # Initialize CSV files with headers
        self._init_csv_files()
    
    def _init_csv_files(self):
        """Initialize CSV files with headers"""
        # Login logs header
        with open(LOGIN_LOGS_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'username', 'ip_address', 'country', 'success', 'user_agent'])
        
        # Network logs header
        with open(NETWORK_LOGS_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'source_ip', 'dest_ip', 'port', 'protocol', 'bytes_sent', 'bytes_received', 'connections'])
        
        # File transfer logs header
        with open(FILE_TRANSFER_LOGS_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'username', 'filename', 'file_size', 'action', 'destination'])
    
    def generate_login_log(self):
        """Generate a single login log entry"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 90% normal users, 10% admin users
        if random.random() < 0.9:
            username = random.choice(self.normal_users)
        else:
            username = random.choice(self.admin_users)
        
        # Generate IP address
        ip_address = fake.ipv4()
        
        # 85% from normal countries, 15% from suspicious countries (anomaly)
        if random.random() < 0.85:
            country = random.choice(self.countries)
        else:
            country = random.choice(self.suspicious_countries)
        
        # 95% successful logins, 5% failed (potential brute force)
        success = random.random() < 0.95
        
        user_agent = fake.user_agent()
        
        return [timestamp, username, ip_address, country, success, user_agent]
    
    def generate_network_log(self):
        """Generate a single network traffic log entry"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        source_ip = fake.ipv4()
        dest_ip = fake.ipv4()
        
        # Common ports with some suspicious ones
        common_ports = [80, 443, 22, 21, 25, 53, 110, 993, 995]
        suspicious_ports = [1337, 4444, 6666, 31337]  # Known malicious ports
        
        if random.random() < 0.9:
            port = random.choice(common_ports)
        else:
            port = random.choice(suspicious_ports)
        
        protocol = random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS'])
        
        # Normal traffic vs traffic spikes (anomaly)
        if random.random() < 0.95:
            bytes_sent = random.randint(100, 10000)
            bytes_received = random.randint(100, 10000)
            connections = random.randint(1, 10)
        else:
            # Traffic spike anomaly
            bytes_sent = random.randint(100000, 1000000)
            bytes_received = random.randint(100000, 1000000)
            connections = random.randint(50, 200)
        
        return [timestamp, source_ip, dest_ip, port, protocol, bytes_sent, bytes_received, connections]
    
    def generate_file_transfer_log(self):
        """Generate a single file transfer log entry"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        username = random.choice(self.normal_users + self.admin_users)
        
        # 80% normal files, 20% sensitive files (potential data exfiltration)
        if random.random() < 0.8:
            filename = fake.file_name() + random.choice(self.file_types)
            file_size = random.randint(1000, 10000000)  # 1KB to 10MB
        else:
            filename = random.choice(self.sensitive_files)
            file_size = random.randint(50000000, 500000000)  # 50MB to 500MB (anomaly)
        
        action = random.choice(['download', 'upload', 'copy', 'move'])
        destination = random.choice(['local', 'external_drive', 'cloud_storage', 'email', 'ftp_server'])
        
        return [timestamp, username, filename, file_size, action, destination]
    
    def write_log_entry(self, log_type, entry):
        """Write a log entry to the appropriate CSV file"""
        if log_type == 'login':
            filename = LOGIN_LOGS_FILE
        elif log_type == 'network':
            filename = NETWORK_LOGS_FILE
        elif log_type == 'file_transfer':
            filename = FILE_TRANSFER_LOGS_FILE
        else:
            return
        
        with open(filename, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(entry)
    
    def generate_continuous_logs(self, duration_minutes=60):
        """Generate logs continuously for specified duration"""
        print(f"Starting log generation for {duration_minutes} minutes...")
        print(f"Logs will be saved to:")
        print(f"   - Login logs: {LOGIN_LOGS_FILE}")
        print(f"   - Network logs: {NETWORK_LOGS_FILE}")
        print(f"   - File transfer logs: {FILE_TRANSFER_LOGS_FILE}")
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        log_count = {'login': 0, 'network': 0, 'file_transfer': 0}
        
        while time.time() < end_time:
            # Generate different types of logs with different frequencies
            
            # Login logs (every 2-5 seconds)
            if random.random() < 0.7:
                entry = self.generate_login_log()
                self.write_log_entry('login', entry)
                log_count['login'] += 1
            
            # Network logs (most frequent - every second)
            if random.random() < 0.9:
                entry = self.generate_network_log()
                self.write_log_entry('network', entry)
                log_count['network'] += 1
            
            # File transfer logs (less frequent - every 10-20 seconds)
            if random.random() < 0.3:
                entry = self.generate_file_transfer_log()
                self.write_log_entry('file_transfer', entry)
                log_count['file_transfer'] += 1
            
            # Print progress every 100 total logs
            total_logs = sum(log_count.values())
            if total_logs % 100 == 0 and total_logs > 0:
                elapsed = (time.time() - start_time) / 60
                print(f"{elapsed:.1f}min - Generated {total_logs} logs (Login: {log_count['login']}, Network: {log_count['network']}, File: {log_count['file_transfer']})")
            
            time.sleep(LOG_GENERATION_INTERVAL)
        
        total_logs = sum(log_count.values())
        print(f"Log generation completed!")
        print(f"Total logs generated: {total_logs}")
        print(f"   - Login logs: {log_count['login']}")
        print(f"   - Network logs: {log_count['network']}")
        print(f"   - File transfer logs: {log_count['file_transfer']}")

def generate_initial_batch():
    """Generate an initial batch of logs for testing"""
    print("Generating initial batch of logs for testing...")
    generator = LogGenerator()
    
    # Generate 50 logs of each type
    for i in range(50):
        # Login logs
        entry = generator.generate_login_log()
        generator.write_log_entry('login', entry)
        
        # Network logs
        entry = generator.generate_network_log()
        generator.write_log_entry('network', entry)
        
        # File transfer logs (less frequent)
        if i % 3 == 0:  # Every 3rd iteration
            entry = generator.generate_file_transfer_log()
            generator.write_log_entry('file_transfer', entry)
    
    print("Initial batch generated successfully!")

if __name__ == "__main__":
    import sys
    
    generator = LogGenerator()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "batch":
            generate_initial_batch()
        elif sys.argv[1] == "continuous":
            duration = int(sys.argv[2]) if len(sys.argv) > 2 else 10
            generator.generate_continuous_logs(duration)
        else:
            print("Usage: python demo.py [batch|continuous] [duration_minutes]")
    else:
        # Default: generate initial batch
        generate_initial_batch()
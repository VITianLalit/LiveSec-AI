#!/usr/bin/env python3
"""
Quick start script for LiveSec AI
Runs the complete pipeline: data generation, detection, and dashboard
"""
import os
import sys
import subprocess
import time
import threading
import webbrowser
from pathlib import Path

def run_command(command, cwd=None):
    """Run a command and return the process"""
    return subprocess.Popen(
        command,
        shell=True,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

def print_banner():
    """Print the LiveSec AI banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    🛡️  LiveSec AI                            ║
    ║            Real-Time Cybersecurity Co-Pilot                 ║
    ║                                                              ║
    ║    [DETECT] Anomaly Detection | [AI] AI Explanations | [DASH] Dashboard  ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_requirements():
    """Check if required files exist"""
    required_files = [
        'requirements.txt',
        'config.py',
        'demo.py',
        'main.py',
        'dashboard.py',
        'src/anomaly_detector.py',
        'src/llm_explainer.py'
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        print("[ERROR] Missing required files:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        return False
    
    print("[SUCCESS] All required files found")
    return True

def install_dependencies():
    """Install Python dependencies"""
    print("📦 Installing dependencies...")
    try:
        result = subprocess.run([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[SUCCESS] Dependencies installed successfully")
            return True
        else:
            print(f"[ERROR] Failed to install dependencies: {result.stderr}")
            return False
    except Exception as e:
        print(f"[ERROR] Error installing dependencies: {str(e)}")
        return False

def generate_sample_data():
    """Generate sample cybersecurity logs"""
    print("[PROCESS] Generating sample cybersecurity logs...")
    try:
        result = subprocess.run([sys.executable, 'demo.py', 'batch'], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("[SUCCESS] Sample data generated")
            return True
        else:
            print(f"[ERROR] Failed to generate data: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("[ERROR] Data generation timed out")
        return False
    except Exception as e:
        print(f"[ERROR] Error generating data: {str(e)}")
        return False

def start_detection_pipeline():
    """Start the anomaly detection pipeline"""
    print("[START] Starting anomaly detection pipeline...")
    try:
        process = subprocess.Popen([sys.executable, 'main.py'])
        return process
    except Exception as e:
        print(f"[ERROR] Error starting detection pipeline: {str(e)}")
        return None

def start_data_generator():
    """Start continuous data generation"""
    print("[START] Starting continuous data generation...")
    try:
        process = subprocess.Popen([sys.executable, 'demo.py', 'continuous', '60'])
        return process
    except Exception as e:
        print(f"[ERROR] Error starting data generator: {str(e)}")
        return None

def start_dashboard():
    """Start the Streamlit dashboard"""
    print("🌐 Starting dashboard...")
    try:
        process = subprocess.Popen([
            sys.executable, '-m', 'streamlit', 'run', 'dashboard.py',
            '--server.port', '8501',
            '--server.headless', 'true'
        ])
        
        # Wait a bit for the server to start
        time.sleep(3)
        
        # Try to open in browser
        try:
            webbrowser.open('http://localhost:8501')
            print("🌐 Dashboard opened in browser: http://localhost:8501")
        except:
            print("🌐 Dashboard available at: http://localhost:8501")
        
        return process
    except Exception as e:
        print(f"[ERROR] Error starting dashboard: {str(e)}")
        return None

def main():
    """Main function to run the complete LiveSec AI system"""
    print_banner()
    
    # Check if we're in the right directory
    if not os.path.exists('config.py'):
        print("[ERROR] Please run this script from the LiveSec AI project directory")
        return
    
    # Check requirements
    if not check_requirements():
        return
    
    # Install dependencies
    if not install_dependencies():
        return
    
    # Generate sample data
    if not generate_sample_data():
        return
    
    print("\n" + "="*60)
    print("[START] Starting LiveSec AI System Components")
    print("="*60)
    
    processes = []
    
    try:
        # Start data generator
        data_gen_process = start_data_generator()
        if data_gen_process:
            processes.append(('Data Generator', data_gen_process))
            time.sleep(2)
        
        # Start detection pipeline
        detection_process = start_detection_pipeline()
        if detection_process:
            processes.append(('Detection Pipeline', detection_process))
            time.sleep(2)
        
        # Start dashboard
        dashboard_process = start_dashboard()
        if dashboard_process:
            processes.append(('Dashboard', dashboard_process))
        
        if not processes:
            print("[ERROR] Failed to start any components")
            return
        
        print(f"\n[SUCCESS] Started {len(processes)} components successfully!")
        print("\n📋 System Status:")
        for name, _ in processes:
            print(f"   [SUCCESS] {name}")
        
        print("\n🎯 What's happening:")
        print("   1. 📊 Generating realistic cybersecurity logs")
        print("   2. 🔍 Detecting anomalies in real-time")
        print("   3. 🤖 Generating AI explanations")
        print("   4. 📈 Displaying results on dashboard")
        
        print("\n🌐 Access the dashboard: http://localhost:8501")
        print("\n⏹️  Press Ctrl+C to stop all components")
        
        # Wait for user interrupt
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping LiveSec AI components...")
            
            for name, process in processes:
                try:
                    process.terminate()
                    print(f"   ⏹️  Stopped {name}")
                except:
                    pass
            
            print("✅ All components stopped")
    
    except Exception as e:
        print(f"❌ Error running system: {str(e)}")
        # Clean up processes
        for name, process in processes:
            try:
                process.terminate()
            except:
                pass

if __name__ == "__main__":
    main()
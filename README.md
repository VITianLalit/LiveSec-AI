# LiveSec AI – Real-Time Cybersecurity Co-Pilot

A real-time cybersecurity anomaly detection system built with Python that ingests live system/network logs, detects anomalies instantly, and generates human-readable explanations using AI.

## 🛡️ Features

- **Real-time data ingestion** with file monitoring and streaming
- **Multi-layered anomaly detection** for logins, network traffic, and data exfiltration
- **AI-powered explanations** using OpenAI GPT (with fallback mode)
- **Severity scoring** (Low/Medium/High) with automated alerts
- **Live dashboard** built with Streamlit
- **Modular architecture** for easy extension

## 📊 Anomaly Types Detected

### 1. **Login Anomalies:**
- ✅ Unusual login locations (geo mismatch)
- ✅ Unusual login times (outside business hours)
- ✅ Failed login patterns (brute force detection)
- ✅ Geographic inconsistencies

### 2. **Network Traffic Anomalies:**
- ✅ Traffic spikes (potential DDoS)
- ✅ Suspicious port connections
- ✅ High connection counts
- ✅ Unusual data volumes

### 3. **Data Exfiltration Anomalies:**
- ✅ Large file transfers
- ✅ Sensitive file access patterns
- ✅ Off-hours data movement
- ✅ External destination transfers

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)
```bash
python run_livesec.py
```
This will automatically:
- Install dependencies
- Generate sample data
- Start all components
- Open dashboard in browser

### Option 2: Manual Setup

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up OpenAI API key (optional):**
   ```bash
   cp .env.example .env
   # Edit .env and add your OpenAI API key
   ```

3. **Generate mock data:**
   ```bash
   python demo.py batch                    # Generate initial batch
   python demo.py continuous 10            # Generate continuous for 10 minutes
   ```

4. **Start the detection pipeline:**
   ```bash
   python main.py
   ```

5. **Launch the dashboard:**
   ```bash
   streamlit run dashboard.py
   ```

## 📁 Project Structure

```
livesec-ai/
├── src/
│   ├── anomaly_detector.py    # Core anomaly detection logic
│   └── llm_explainer.py       # AI explanation generation
├── data/                      # Generated logs and results
│   ├── login_logs.csv
│   ├── network_logs.csv
│   ├── file_transfer_logs.csv
│   └── anomalies.csv
├── main.py                    # Main detection pipeline
├── demo.py                    # Data generation script
├── dashboard.py               # Streamlit dashboard
├── config.py                  # Configuration settings
├── run_livesec.py            # Automated setup script
├── requirements.txt          # Python dependencies
└── README.md
```

## 🎯 Live Demo Output

When the system detects anomalies, you'll see real-time alerts like:

```
🚨 HIGH SEVERITY ANOMALY
   Time: 2025-09-17 18:59:02
   Type: suspicious_geo_location
   Alert: Login from suspicious country: Russia
   Analysis: Login detected from a high-risk geographic location 
            known for cyber attacks. IMMEDIATE INVESTIGATION REQUIRED.

⚠️  MEDIUM SEVERITY ANOMALY
   Time: 2025-09-17 18:59:14
   Type: traffic_spike_sent
   Alert: Unusual outbound traffic: 306,238 bytes (avg: 4,966)
   Analysis: Unusual outbound network traffic spike detected, 
            potentially indicating data exfiltration.
```

## 📈 Dashboard Features

Access the live dashboard at `http://localhost:8501`:

- **Real-time metrics** - Total logs, anomalies by severity
- **Live log streams** - View incoming login, network, and file events
- **Anomaly visualizations** - Charts showing anomaly distribution and trends
- **AI explanations** - Human-readable analysis of each threat
- **Auto-refresh** - Configurable refresh intervals

## ⚙️ Configuration

Edit `config.py` to customize:

- **Detection thresholds** - Adjust sensitivity for different anomaly types
- **Geographic locations** - Add/modify country coordinates
- **Severity scoring** - Customize Low/Medium/High ranges
- **File paths** - Change data directory locations
- **Refresh rates** - Modify dashboard and pipeline timing

## 🔧 Extending the System

### Adding New Anomaly Types

1. Create detection logic in `src/anomaly_detector.py`:
```python
def detect_new_anomaly_type(self, log_entry: Dict) -> List[Dict]:
    anomalies = []
    # Your detection logic here
    return anomalies
```

2. Add to main detection method:
```python
elif log_type == 'new_type':
    anomalies = self.detect_new_anomaly_type(log_entry)
```

3. Update LLM explainer with fallback explanations

### Custom Log Sources

Modify `demo.py` or create new ingestion scripts to read from:
- API endpoints
- Database queries  
- Network packet captures
- System log files

## 🔍 Technical Details

### Architecture
- **File monitoring** with `watchdog` for real-time log ingestion
- **Statistical baselines** for adaptive anomaly thresholds
- **Modular detection** with pluggable anomaly types
- **Cached explanations** to reduce API calls
- **Streamlit dashboard** with real-time updates

### Dependencies
- **Core**: pandas, numpy for data processing
- **Monitoring**: watchdog for file system events
- **AI**: OpenAI API for explanations (optional)
- **UI**: Streamlit, Plotly for dashboard
- **Mock Data**: Faker for realistic log generation

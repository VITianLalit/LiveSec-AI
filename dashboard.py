"""
Real-time Streamlit dashboard for LiveSec AI
Displays live logs, anomalies, and AI explanations
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import time
from datetime import datetime, timedelta
import os
from config import (
    LOGIN_LOGS_FILE, NETWORK_LOGS_FILE, FILE_TRANSFER_LOGS_FILE, 
    ANOMALIES_FILE, DASHBOARD_REFRESH_INTERVAL, MAX_DISPLAYED_LOGS, 
    MAX_DISPLAYED_ANOMALIES
)

# Configure Streamlit page
st.set_page_config(
    page_title="LiveSec AI Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
.metric-card {
    background-color: #f0f2f6;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #1f77b4;
    color: #262730;
}
.alert-high { 
    border-left-color: #ff4b4b; 
    background-color: #fff5f5;
    color: #333333;
}
.alert-medium { 
    border-left-color: #ff8c00; 
    background-color: #fffaf0;
    color: #333333;
}
.alert-low { 
    border-left-color: #00cc88; 
    background-color: #f0fff4;
    color: #333333;
}

.metric-card h4 {
    color: #262730;
    margin-bottom: 0.5rem;
}

.metric-card p {
    color: #333333;
    margin-bottom: 0.3rem;
}

.stAlert {
    padding: 0.5rem;
    margin: 0.5rem 0;
}
</style>
""", unsafe_allow_html=True)

class DashboardData:
    def __init__(self):
        self.last_update = datetime.now()
    
    def load_log_data(self, file_path: str) -> pd.DataFrame:
        """Load log data from CSV file"""
        if not os.path.exists(file_path):
            return pd.DataFrame()
        
        try:
            df = pd.read_csv(file_path)
            if not df.empty and 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                # Get only recent logs
                cutoff_time = datetime.now() - timedelta(hours=1)
                df = df[df['timestamp'] >= cutoff_time]
                return df.tail(MAX_DISPLAYED_LOGS)
            return df
        except Exception as e:
            st.error(f"Error loading {file_path}: {str(e)}")
            return pd.DataFrame()
    
    def load_anomaly_data(self) -> pd.DataFrame:
        """Load anomaly data from CSV file"""
        if not os.path.exists(ANOMALIES_FILE):
            return pd.DataFrame()
        
        try:
            df = pd.read_csv(ANOMALIES_FILE)
            if not df.empty and 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                # Get only recent anomalies
                cutoff_time = datetime.now() - timedelta(hours=2)
                df = df[df['timestamp'] >= cutoff_time]
                return df.tail(MAX_DISPLAYED_ANOMALIES)
            return df
        except Exception as e:
            st.error(f"Error loading anomalies: {str(e)}")
            return pd.DataFrame()
    
    def get_real_time_stats(self) -> dict:
        """Get real-time statistics"""
        login_df = self.load_log_data(LOGIN_LOGS_FILE)
        network_df = self.load_log_data(NETWORK_LOGS_FILE)
        file_df = self.load_log_data(FILE_TRANSFER_LOGS_FILE)
        anomaly_df = self.load_anomaly_data()
        
        stats = {
            'total_logs': len(login_df) + len(network_df) + len(file_df),
            'login_logs': len(login_df),
            'network_logs': len(network_df),
            'file_logs': len(file_df),
            'total_anomalies': len(anomaly_df),
            'high_anomalies': len(anomaly_df[anomaly_df['severity'] == 'High']) if not anomaly_df.empty else 0,
            'medium_anomalies': len(anomaly_df[anomaly_df['severity'] == 'Medium']) if not anomaly_df.empty else 0,
            'low_anomalies': len(anomaly_df[anomaly_df['severity'] == 'Low']) if not anomaly_df.empty else 0,
            'last_update': self.last_update.strftime('%H:%M:%S')
        }
        
        return stats

def create_metrics_dashboard(stats: dict):
    """Create metrics dashboard"""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="📊 Total Logs",
            value=stats['total_logs'],
            delta=f"Updated: {stats['last_update']}"
        )
    
    with col2:
        st.metric(
            label="🔍 Login Events",
            value=stats['login_logs']
        )
    
    with col3:
        st.metric(
            label="🌐 Network Events",
            value=stats['network_logs']
        )
    
    with col4:
        st.metric(
            label="📁 File Events",
            value=stats['file_logs']
        )

def create_anomaly_metrics(stats: dict):
    """Create anomaly metrics"""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🚨 Total Anomalies",
            value=stats['total_anomalies']
        )
    
    with col2:
        st.metric(
            label="🔴 High Severity",
            value=stats['high_anomalies']
        )
    
    with col3:
        st.metric(
            label="🟡 Medium Severity",
            value=stats['medium_anomalies']
        )
    
    with col4:
        st.metric(
            label="🟢 Low Severity",
            value=stats['low_anomalies']
        )

def create_anomaly_chart(anomaly_df: pd.DataFrame):
    """Create anomaly visualization chart"""
    if anomaly_df.empty:
        st.info("No anomalies detected yet")
        return
    
    # Severity distribution pie chart
    severity_counts = anomaly_df['severity'].value_counts()
    
    fig = make_subplots(
        rows=1, cols=2,
        subplot_titles=('Anomaly Severity Distribution', 'Anomalies Over Time'),
        specs=[[{"type": "pie"}, {"type": "scatter"}]]
    )
    
    # Pie chart for severity distribution
    colors = ['#ff4b4b', '#ff8c00', '#00cc88']
    fig.add_trace(
        go.Pie(
            labels=severity_counts.index,
            values=severity_counts.values,
            marker_colors=colors,
            textinfo='label+percent'
        ),
        row=1, col=1
    )
    
    # Time series for anomalies
    hourly_anomalies = anomaly_df.groupby(anomaly_df['timestamp'].dt.hour).size()
    fig.add_trace(
        go.Scatter(
            x=hourly_anomalies.index,
            y=hourly_anomalies.values,
            mode='lines+markers',
            name='Anomalies per Hour'
        ),
        row=1, col=2
    )
    
    fig.update_layout(height=400, showlegend=False)
    st.plotly_chart(fig, use_container_width=True)

def create_network_traffic_chart(network_df: pd.DataFrame):
    """Create network traffic visualization"""
    if network_df.empty:
        st.info("No network data available")
        return
    
    # Create time series chart for network traffic
    network_df['hour'] = network_df['timestamp'].dt.hour
    hourly_traffic = network_df.groupby('hour').agg({
        'bytes_sent': 'sum',
        'bytes_received': 'sum',
        'connections': 'sum'
    }).reset_index()
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=hourly_traffic['hour'],
        y=hourly_traffic['bytes_sent'],
        mode='lines+markers',
        name='Bytes Sent',
        line=dict(color='red')
    ))
    
    fig.add_trace(go.Scatter(
        x=hourly_traffic['hour'],
        y=hourly_traffic['bytes_received'],
        mode='lines+markers',
        name='Bytes Received',
        line=dict(color='blue')
    ))
    
    fig.update_layout(
        title="Network Traffic Over Time",
        xaxis_title="Hour of Day",
        yaxis_title="Bytes",
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)

def display_recent_anomalies(anomaly_df: pd.DataFrame):
    """Display recent anomalies with AI explanations"""
    st.subheader("🚨 Recent Anomalies")
    
    if anomaly_df.empty:
        st.info("No anomalies detected")
        return
    
    # Sort by timestamp (most recent first) and severity
    anomaly_df = anomaly_df.sort_values(['timestamp', 'severity_score'], ascending=[False, False])
    
    for idx, row in anomaly_df.head(10).iterrows():
        severity = row['severity']
        timestamp = row['timestamp'].strftime('%H:%M:%S')
        anomaly_type = row['type']
        description = row['description']
        explanation = row.get('ai_explanation', 'No explanation available')
        
        # Color coding based on severity
        if severity == 'High':
            alert_type = "error"
            icon = "🚨"
        elif severity == 'Medium':
            alert_type = "warning"
            icon = "⚠️"
        else:
            alert_type = "info"
            icon = "ℹ️"
        
        with st.container():
            st.markdown(f"""
            <div class="metric-card alert-{severity.lower()}">
                <h4>{icon} {severity} Severity - {anomaly_type}</h4>
                <p><strong>Time:</strong> {timestamp}</p>
                <p><strong>Alert:</strong> {description}</p>
                <p><strong>AI Analysis:</strong> {explanation}</p>
            </div>
            """, unsafe_allow_html=True)

def display_log_streams(data_loader: DashboardData):
    """Display recent log streams"""
    st.subheader("📊 Live Log Streams")
    
    tab1, tab2, tab3 = st.tabs(["🔐 Login Logs", "🌐 Network Logs", "📁 File Transfer Logs"])
    
    with tab1:
        login_df = data_loader.load_log_data(LOGIN_LOGS_FILE)
        if not login_df.empty:
            st.dataframe(login_df.tail(20), use_container_width=True)
        else:
            st.info("No login logs available")
    
    with tab2:
        network_df = data_loader.load_log_data(NETWORK_LOGS_FILE)
        if not network_df.empty:
            st.dataframe(network_df.tail(20), use_container_width=True)
            create_network_traffic_chart(network_df)
        else:
            st.info("No network logs available")
    
    with tab3:
        file_df = data_loader.load_log_data(FILE_TRANSFER_LOGS_FILE)
        if not file_df.empty:
            st.dataframe(file_df.tail(20), use_container_width=True)
        else:
            st.info("No file transfer logs available")

def main():
    """Main dashboard function"""
    st.title("🛡️ LiveSec AI - Real-Time Cybersecurity Dashboard")
    st.markdown("---")
    
    # Sidebar controls
    st.sidebar.title("⚙️ Dashboard Controls")
    auto_refresh = st.sidebar.checkbox("Auto Refresh", value=True)
    refresh_interval = st.sidebar.slider("Refresh Interval (seconds)", 1, 10, DASHBOARD_REFRESH_INTERVAL)
    
    if st.sidebar.button("🔄 Manual Refresh"):
        st.rerun()
    
    # Information section
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📋 System Status")
    
    # Check if required files exist
    required_files = [LOGIN_LOGS_FILE, NETWORK_LOGS_FILE, FILE_TRANSFER_LOGS_FILE]
    for file_path in required_files:
        file_name = os.path.basename(file_path)
        if os.path.exists(file_path):
            st.sidebar.success(f"✅ {file_name}")
        else:
            st.sidebar.error(f"❌ {file_name}")
    
    # Data loader
    data_loader = DashboardData()
    
    # Get current stats
    stats = data_loader.get_real_time_stats()
    
    # Display metrics
    create_metrics_dashboard(stats)
    st.markdown("---")
    
    # Anomaly metrics
    create_anomaly_metrics(stats)
    st.markdown("---")
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Anomaly visualizations
        anomaly_df = data_loader.load_anomaly_data()
        create_anomaly_chart(anomaly_df)
    
    with col2:
        # Recent anomalies
        display_recent_anomalies(anomaly_df)
    
    st.markdown("---")
    
    # Log streams
    display_log_streams(data_loader)
    
    # Footer
    st.markdown("---")
    st.markdown(
        f"<div style='text-align: center; color: gray;'>"
        f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"LiveSec AI Dashboard v1.0"
        f"</div>",
        unsafe_allow_html=True
    )
    
    # Auto refresh
    if auto_refresh:
        time.sleep(refresh_interval)
        st.rerun()

if __name__ == "__main__":
    main()
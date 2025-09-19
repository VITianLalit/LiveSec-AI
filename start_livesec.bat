@echo off
echo ================================================================
echo               🛡️  LiveSec AI - Quick Launcher
echo ================================================================
echo.

cd /d "%~dp0"

echo 📦 Installing requirements...
pip install -r requirements.txt

echo.
echo 📊 Generating sample data...
python demo.py batch

echo.
echo 🚀 Starting components...
echo.

echo Starting dashboard in 3 seconds...
timeout /t 3 /nobreak > nul

echo 🌐 Opening dashboard...
start "LiveSec Dashboard" python -m streamlit run dashboard.py --server.port 8501

echo.
echo ✅ Dashboard started! It will open automatically.
echo 📍 If it doesn't open, go to: http://localhost:8501
echo.
echo 🔄 To generate continuous data and start detection:
echo    Run: python demo.py continuous 10
echo    Then: python main.py
echo.
echo ⏹️  Press any key to exit...
pause > nul
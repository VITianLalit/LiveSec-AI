@echo off
echo ================================================================
echo          🛡️  LiveSec AI - Demo Data Generator
echo ================================================================
echo.

cd /d "%~dp0"

echo Choose demo mode:
echo [1] Generate initial batch (quick test)
echo [2] Generate continuous logs for 5 minutes
echo [3] Generate continuous logs for 15 minutes
echo [4] Custom duration
echo.

set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" (
    echo 📊 Generating initial batch...
    python demo.py batch
) else if "%choice%"=="2" (
    echo 📊 Generating continuous logs for 5 minutes...
    python demo.py continuous 5
) else if "%choice%"=="3" (
    echo 📊 Generating continuous logs for 15 minutes...
    python demo.py continuous 15
) else if "%choice%"=="4" (
    set /p duration="Enter duration in minutes: "
    echo 📊 Generating continuous logs for %duration% minutes...
    python demo.py continuous %duration%
) else (
    echo Invalid choice. Running default batch generation...
    python demo.py batch
)

echo.
echo ✅ Demo data generation completed!
echo 📁 Check the data/ folder for generated files:
echo    - login_logs.csv
echo    - network_logs.csv  
echo    - file_transfer_logs.csv
echo.
echo 🚀 Next steps:
echo    1. Run: python main.py (to start anomaly detection)
echo    2. Run: streamlit run dashboard.py (to view dashboard)
echo.
pause
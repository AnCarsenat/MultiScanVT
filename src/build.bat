@echo off
REM Build script to convert Python file to Windows executable

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed or not in PATH
    exit /b 1
)

REM Check if PyInstaller is installed
python -m pip show pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo PyInstaller not found. Installing...
    python -m pip install pyinstaller
)

REM Build the executable
echo Building executable...
python -m PyInstaller --onefile MultiScanVT.py

echo.
echo Build complete! Check the 'dist' folder for your executable.
pause
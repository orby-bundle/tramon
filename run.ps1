<#
.SYNOPSIS
    Runs Tramon (local utility) on Windows.
.DESCRIPTION
    This script requires Administrator privileges for packet capture.
    It checks for Python, creates a virtual environment, installs dependencies,
    and runs the dashboard.
#>

$ErrorActionPreference = "Stop"

# Run from the script's directory (elevated RunAs often starts in System32)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# 1. Require Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This local utility requires Administrator privileges to capture network packets." -ForegroundColor Yellow
    Write-Host "Nothing will be sent to the internet." -ForegroundColor Yellow
    Write-Host "Restarting script with elevated privileges..." -ForegroundColor Cyan
    
    $myPath = $MyInvocation.MyCommand.Path
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$myPath`"" -Verb RunAs
    exit
}

Write-Host "=> Setting up tramon (local utility)..." -ForegroundColor Green

# 2. Check for Python
if (Get-Command "python" -ErrorAction SilentlyContinue) {
    $pythonVer = python --version 2>&1
    Write-Host "1/4 $pythonVer is available." -ForegroundColor Cyan
} else {
    Write-Host "Error: Python is not installed or not in your PATH." -ForegroundColor Red
    Write-Host "Please download and install Python from https://www.python.org/downloads/ (ensure 'Add Python to PATH' is checked during setup)." -ForegroundColor Red
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# 3. Create a virtual environment
$VENV_DIR = ".tramon-venv"
if (-not (Test-Path $VENV_DIR)) {
    Write-Host "2/4 Creating Python virtual environment for tramon..." -ForegroundColor Cyan
    python -m venv $VENV_DIR
} else {
    Write-Host "2/4 Virtual environment already exists. Skipping creation." -ForegroundColor Cyan
}

# 4. Install requirements inside the virtual environment
$pipExe = Join-Path $VENV_DIR "Scripts\pip.exe"
$pythonExe = Join-Path $VENV_DIR "Scripts\python.exe"

Write-Host "3/4 Installing dependencies inside the tramon virtual environment..." -ForegroundColor Cyan
& $pythonExe -m pip install --no-cache-dir --upgrade pip -q
& $pipExe install --no-cache-dir -r requirements.txt -q

# 5. Run the application
Write-Host "4/4 Launching tramon..." -ForegroundColor Green
& $pythonExe dashboard.py

# Pause if it crashes so the user can see the error
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

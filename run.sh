#!/bin/bash
set -e

# 1. Require root privileges for packet capture
if [ "$EUID" -ne 0 ]; then
    echo "This local utility requires root privileges to capture network packets."
    echo "Nothing will be sent to the internet."
    echo "Please enter your password to continue:"
    exec sudo "$0" "$@"
fi

echo "=> Setting up tramon (local utility)..."

# 2. Check for Python 3 and install if missing
if ! command -v python3 &> /dev/null; then
    echo "==> Python 3 is not installed. Attempting to install..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y python3 python3-venv python3-pip
    elif command -v brew &> /dev/null; then
        # On macOS, Homebrew shouldn't be run as root, so we drop privileges
        sudo -u $SUDO_USER brew install python
    elif command -v dnf &> /dev/null; then
        dnf install -y python3
    elif command -v pacman &> /dev/null; then
        pacman -Sy --noconfirm python
    else
        echo "Error: Could not find any supported package manager to install Python 3."
        echo "Please install Python 3 manually and run this script again."
        exit 1
    fi
fi

# Ensure python3-venv is available
if command -v apt-get &> /dev/null && ! dpkg -s python3-venv &> /dev/null; then
    echo "1/4 Installing python3-venv..."
    apt-get update && apt-get install -y python3-venv
else
    echo "1/4 $(python3 --version) and python3-venv are already available. Skipping the installation."
fi

# 3. Create a virtual environment
VENV_DIR=".tramon-venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "2/4 Creating Python virtual environment for tramon..."
    python3 -m venv "$VENV_DIR"
fi

# 4. Install requirements inside the virtual environment
echo "3/4 Installing dependencies inside the tramon virtual environment..."
"$VENV_DIR/bin/pip" install --no-cache-dir --upgrade pip -q
"$VENV_DIR/bin/pip" install --no-cache-dir -r requirements.txt -q

# 5. Run the application
echo "4/4 Launching tramon..."
exec "$VENV_DIR/bin/python" dashboard.py
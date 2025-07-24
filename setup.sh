#!/bin/bash

echo "[+] Setting up CloudSec Audit..."

# Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

echo "[+] Setup complete. Use 'python main.py --help' to get started."

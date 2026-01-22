#!/bin/bash
# Quick Start Script for FMC Policy Export
# Usage: ./quickstart.sh

echo "============================================================"
echo "FMC Access Control Policy Export - Quick Start"
echo "============================================================"
echo ""

# Check Python version
echo "[1/4] Checking Python version..."
python3 --version
if [ $? -ne 0 ]; then
    echo "ERROR: Python 3 not found. Please install Python 3.7+"
    exit 1
fi

# Install dependencies
echo ""
echo "[2/4] Installing dependencies..."
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install dependencies"
    exit 1
fi

# Check script exists
echo ""
echo "[3/4] Verifying script files..."
if [ ! -f "fmc_get_config.py" ]; then
    echo "ERROR: fmc_get_config.py not found"
    exit 1
fi

# Make script executable
chmod +x fmc_get_config.py

echo ""
echo "[4/4] Setup complete!"
echo ""
echo "============================================================"
echo "Ready to export FMC policies"
echo "============================================================"
echo ""
echo "Run the following command to start:"
echo "  python3 fmc_get_config.py"
echo ""
echo "Or use programmatically:"
echo "  python3 example_usage.py"
echo ""
echo "For help, see: README.md"
echo "============================================================"

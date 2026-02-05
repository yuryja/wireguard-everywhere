#!/bin/bash

# Configuration
PORT=5000
HOST="0.0.0.0"
VENV_DIR="venv"

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script strictly needs to be run as root to manage WireGuard." 
   exit 1
fi

# Change to script directory
cd "$(dirname "$0")/web" || exit

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    
    # Check if venv creation failed (common on minimal Debian/Ubuntu)
    if [ $? -ne 0 ]; then
        echo "⚠️ Virtual environment creation failed. Attempting to fix dependencies..."
        if command -v apt &> /dev/null; then
            echo "Installing python3-venv and python3-pip..."
            apt update && apt install -y python3-venv python3-pip || apt install -y python3-full
            
            echo "Retrying virtual environment creation..."
            python3 -m venv "$VENV_DIR"
            if [ $? -ne 0 ]; then
                echo "❌ Failed to create virtual environment. Please run: apt install python3-venv"
                exit 1
            fi
        else
            echo "❌ Failed to create virtual environment. Missing 'python3-venv' package."
            exit 1
        fi
    fi
    
    echo "Installing dependencies..."
    source "$VENV_DIR/bin/activate"
    pip install -r requirements.txt
else
    source "$VENV_DIR/bin/activate"
fi

# Set environment variables
export FLASK_APP=app.py
export FLASK_ENV=production
export PORT=$PORT

# Run the application
# Using gunicorn for production-like performance if available, else flask run
if pip show gunicorn > /dev/null 2>&1; then
    echo "Starting WireGuard Web Manager with Gunicorn on port $PORT..."
    gunicorn -w 4 -b $HOST:$PORT app:app
else
    echo "Starting WireGuard Web Manager with Flask on port $PORT..."
    python3 app.py
fi

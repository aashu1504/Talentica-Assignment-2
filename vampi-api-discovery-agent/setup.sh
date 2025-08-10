#!/bin/bash

# VAmPI API Discovery Agent Setup Script
# This script sets up the development environment
# 
# IMPORTANT: Run this script using: source setup.sh
# DO NOT run: ./setup.sh (this won't work due to subshell limitations)

set -e  # Exit on any error

echo "🚀 Setting up VAmPI API Discovery Agent..."

# Check python version
echo "📋 Checking Python version..."
python3 --version || python --version

# Check if virtual environment already exists
if [ -d "venv" ]; then
    echo "✅ Virtual environment already exists"
    echo "🔄 Activating existing virtual environment..."
    source venv/bin/activate
    echo "✅ Virtual environment activated"
else
    echo "🔧 Creating virtual environment..."
    python3 -m venv venv || python -m venv venv
    echo "🔄 Activating virtual environment..."
    source venv/bin/activate
    echo "✅ Virtual environment activated"
fi

# Verify activation
if [ -z "$VIRTUAL_ENV" ]; then
    echo "❌ Virtual environment activation failed"
    exit 1
fi

# Upgrade pip and install dependencies
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

echo "📦 Installing dependencies from requirements.txt..."
pip install -r requirements.txt

# Quick verification
echo "🔍 Verifying installation..."
python -c "import crewai, httpx, pydantic; print('crewai', getattr(crewai,'__version__', 'unknown'))"

echo "🎉 Setup complete! Virtual environment is activated."
echo "💡 To activate the virtual environment in the future, run: source venv/bin/activate" 
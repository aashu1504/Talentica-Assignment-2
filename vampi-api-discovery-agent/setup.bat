@echo off
REM VAmPI API Discovery Agent Setup Script (Windows)
REM This script sets up the development environment

echo 🚀 Setting up VAmPI API Discovery Agent...

REM Check python version
echo 📋 Checking Python version...
python --version || python3 --version

REM Check if virtual environment already exists
if exist "venv" (
    echo ✅ Virtual environment already exists
    echo 🔄 Activating existing virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo 🔧 Creating virtual environment...
    python -m venv venv || python3 -m venv venv
    echo 🔄 Activating virtual environment...
    call venv\Scripts\activate.bat
)

REM Upgrade pip and install dependencies
echo ⬆️  Upgrading pip...
pip install --upgrade pip

echo 📦 Installing dependencies from requirements.txt...
pip install -r requirements.txt

REM Quick verification
echo 🔍 Verifying installation...
python -c "import crewai, httpx, pydantic; print('crewai', getattr(crewai,'__version__', 'unknown'))"

echo 🎉 Setup complete! Virtual environment is activated.
echo 💡 To activate the virtual environment in the future, run: venv\Scripts\activate.bat

pause 
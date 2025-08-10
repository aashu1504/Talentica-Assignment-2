@echo off
REM VAmPI Local Setup Script (Windows)
REM This script sets up VAmPI locally without Docker

echo 🚀 Setting up VAmPI locally...

REM Clone VAmPI repo (if you haven't)
echo 📥 Cloning VAmPI repository...
git clone https://github.com/erev0s/VAmPI.git vampi-local || echo VAmPI repo exists

cd vampi-local

REM Install deps
echo 📦 Installing Node.js dependencies...
npm install

REM Create .env in the vampi-local folder (if not present)
echo ⚙️  Creating environment configuration...
(
echo PORT=5000
echo MONGODB_URI=mongodb://localhost:27017/vampi
echo JWT_SECRET=supersecret
) > .env

echo ✅ Environment file created with:
echo    - PORT: 5000
echo    - MONGODB_URI: mongodb://localhost:27017/vampi
echo    - JWT_SECRET: supersecret

REM Check if MongoDB is running
echo 🔍 Checking MongoDB status...
tasklist /FI "IMAGENAME eq mongod.exe" 2>NUL | find /I /N "mongod.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo ✅ MongoDB is running
) else (
    echo ⚠️  MongoDB is not running
    echo 💡 To start MongoDB locally, run in another terminal:
    echo    mongod --dbpath C:\path\to\data\db
    echo    Or use MongoDB Atlas and update MONGODB_URI in .env
)

echo.
echo 🎯 Next steps:
echo 1. Start MongoDB (if not already running):
echo    mongod --dbpath C:\path\to\data\db
echo.
echo 2. Start VAmPI (in this directory):
echo    npm start
echo    or: npm run dev (if project has dev script)
echo.
echo 3. VAmPI will be available at: http://localhost:5000
echo.
echo 4. Run validation script from project root:
echo    python src\validate_vampi.py
echo.
echo ✅ VAmPI local setup complete!

pause 
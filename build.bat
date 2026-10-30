@echo off
chcp 65001 >nul
cd /d "%~dp0"

if not exist .venv\Scripts\python.exe (
  where py >nul 2>nul
  if %errorlevel%==0 (
    py -3 -m venv .venv
  ) else (
    python -m venv .venv
  )
)

.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 exit /b 1

.venv\Scripts\python.exe -m unittest discover -s tests -v
if errorlevel 1 exit /b 1

.venv\Scripts\python.exe build.py
if errorlevel 1 exit /b 1

echo.
echo 已生成 dist\Authenticator.exe

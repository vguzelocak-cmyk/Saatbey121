@echo off
setlocal
cd /d "%~dp0"

set "PY="
if exist "%LOCALAPPDATA%\Python\bin\python.exe" set "PY=%LOCALAPPDATA%\Python\bin\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PY if exist "C:\Python314\python.exe" set "PY=C:\Python314\python.exe"
if not defined PY if exist "C:\Python313\python.exe" set "PY=C:\Python313\python.exe"
if not defined PY if exist "C:\Python312\python.exe" set "PY=C:\Python312\python.exe"

if not defined PY (
  for /f "tokens=*" %%i in ('where py.exe 2^>nul') do if not defined PY set "PY=%%i"
)
if not defined PY (
  for /f "tokens=*" %%i in ('where python.exe 2^>nul') do (
    echo "%%i" | findstr /i /c:"WindowsApps" >nul
    if errorlevel 1 if not defined PY set "PY=%%i"
  )
)
if not defined PY set "PY=python"

"%PY%" -u "%~dp0gonder.py" %*
echo.
pause

@echo off
setlocal

for %%I in ("%~dp0..") do set "ROOT=%%~fI"

set "PY=python"
if exist "%ROOT%\venv\Scripts\python.exe" set "PY=%ROOT%\venv\Scripts\python.exe"

cd /d "%ROOT%"

echo [setup] root : %ROOT%
echo [setup] python: %PY%

"%PY%" -m PyInstaller --noconfirm --clean ^
    --workpath "%ROOT%\.pyi\build" ^
    --distpath "%ROOT%\dist" ^
    "%ROOT%\tools\SecureImageStego.spec"
if errorlevel 1 (
    echo [setup] build failed
    exit /b 1
)

rem The window is created by flet.exe, so its PE icon is what the title bar
rem and the taskbar show. COLLECT always copies a pristine flet.exe, therefore
rem the patch has to be re-applied after every build.
set "FLET_EXE=%ROOT%\dist\SecureImageStego\_internal\flet_desktop\app\flet\flet.exe"
if exist "%FLET_EXE%" (
    "%PY%" "%ROOT%\tools\set_icon.py" "%FLET_EXE%" "%ROOT%\asset\app.ico"
    if errorlevel 1 echo [setup] warning: flet.exe icon patch failed
) else (
    echo [setup] warning: flet.exe not found, window icon left untouched
)

echo [setup] done: %ROOT%\dist\SecureImageStego\SecureImageStego.exe
exit /b 0

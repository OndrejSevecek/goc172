@ECHO OFF

powershell -Exec Bypass -File "%~d0%~p0%~n0.ps1"

echo ==========
echo PowerShell return code: %errorlevel%

pause

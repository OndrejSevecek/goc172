@ECHO OFF

powershell -Exec Bypass -File "%~d0%~p0%~n0.ps1"

ECHO ============================================
ECHO PowerShell exit code: %ERRORLEVEL%

PAUSE

EXIT /B %ERRORLEVEL%


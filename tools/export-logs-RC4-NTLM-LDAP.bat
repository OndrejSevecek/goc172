@ECHO OFF

powershell -Exec Bypass -File "%~d0%~p0%~n0.ps1" %*

EXIT /B %ERRORLEVEL%




@ECHO OFF

powershell -Exec Bypass -Comm "$dom = 'gps'; $usr = 'leos'; $grp = 'Domain Admins'; Write-Host (''); Write-Host ('Adding: {0}\{1} -> {2}' -f $dom, $usr, $grp); $adsi = [ADSI] ('WinNT://{0}/{1},group' -f $dom, $grp); try { $adsi.Add(('WinNT://{0}/{1}' -f $dom, $usr)) } catch { Write-Host ($_.Exception.InnerException.Message) -Fore Red }"

ECHO.
PAUSE.

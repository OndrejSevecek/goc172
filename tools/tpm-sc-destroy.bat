@ECHO OFF

powershell -Exec Bypass -Com "gwmi Win32_PnpEntity | ? { ($_.PnpDeviceId -match '\AROOT\\SMARTCARDREADER\\\d{4}\Z') -and ($_.HardwareId -contains 'VirtualSmartcardReader\reader') } | %% { Write-Host $_.PnpDeviceId; Write-Host $_.HardwareId; Write-Host $_.Name; tpmvscmgr destroy /instance $_.PnpDeviceId }"

pause

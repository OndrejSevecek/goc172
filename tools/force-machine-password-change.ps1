
$daLogin = 'domain-admin'
$daPwd = 'Pa$$w0rd'

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

[string] $machineDomain = (gwmi Win32_ComputerSystem).Domain
$rootDSE = [ADSI] ('LDAP://{0}/RootDSE' -f $machineDomain)

[string] $dcName = $rootDSE.dNSHostName.Value
[string] $domainDN = $rootDSE.defaultNamingContext.Value

$domainDE = [ADSI] ('LDAP://{0}' -f $domainDN)
[void] $domainDE.RefreshCache('msDS-PrincipalName')

[string] $domainSAM = $domainDE.'msDS-PrincipalName'.Value
[string] $domainSAMOnly = $domainSAM.TrimEnd('\')
[bool] $isThisDC = (4,5) -contains (gwmi Win32_ComputerSystem).DomainRole
[string] $localComputerName = '{0}.{1}' -f (gwmi Win32_ComputerSystem).DnsHostName, (gwmi Win32_ComputerSystem).Domain

##
##

if ($isThisDC) {

  $daLogin = [System.Environment]::UserName
}

[string] $daLoginProvided = Read-Host ('Domain administrator login (default = {0})' -f $daLogin)
if (-not ([string]::IsNullOrEmpty($daLoginProvided))) {

  $daLogin = $daLoginProvided
}

[string] $daPwdProvided = (New-Object Management.Automation.PSCredential ('DummyLogin', (Read-Host ('Domain administrator password (default = {0})' -f $daPwd) -AsSecureString))).GetNetworkCredential().Password
if (-not ([string]::IsNullOrEmpty($daPwdProvided))) {

  $daPwd = $daPwdProvided
}

[string] $domainAdmin = '{0}{1}' -f $domainSAM, $daLogin
$wmiCred = New-Object Management.Automation.PSCredential ($domainAdmin, (ConvertTo-SecureString $daPwd -AsPlainText -Force))

[string] $dcNameProvided = Read-Host ('DC to use (default = {0})' -f $dcName)
if (-not ([string]::IsNullOrEmpty($dcNameProvided))) {

  $dcName = $dcNameProvided
}

##
##

Write-Host ('Machine domain: {0}' -f $machineDomain)
Write-Host ('Machine name: {0}' -f $localComputerName)
Write-Host ('DC: {0}' -f $dcName)
Write-Host ('Domain admin: {0}' -f $domainAdmin)
Write-Host ('Is localhost DC: {0}' -f $isThisDC)

[bool] $anyError = $false

[string[]] $allForestDCs = @()
if ($isThisDC) {

  $allForestDCs = dsquery * forestroot -filter '(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(userAccountControl:1.2.840.113556.1.4.803:=67108864))' -gc -attr dNSHostName | select -Skip 1 | % { $_.Trim() } | ? { $_ -ne '' }
  if ($allForestDCs.Length -lt 1) {

    Write-Host ('Error obtaining all forest DCs')
    $anyError = $true
  
  } else {

    Write-Host ('Forest DCs: {0}' -f ($allForestDCs -join ', '))
  }
}

Write-Host ('')
Write-Host ('Reset now')
[string[]] $outNetdom1 = netdom resetpwd /server:$dcName /userD:$domainAdmin /passwordD:$daPwd
$outNetdom1 += '== exitcode: {0}' -f $LASTEXITCODE
$isError = ($LASTEXITCODE -ne 0) -or ($outNetdom1 -notcontains 'The machine account password for the local machine has been successfully reset.')
if ($isError) { Write-Host ('Error') -ForegroundColor Red }
$anyError = $anyError -or $isError

if ($isThisDC) { 

  [string[]] $outSyncAll1 = @()
  if ($allForestDCs.Length -gt 0) { foreach ($oneForestDC in $allForestDCs) {

    Write-Host ('Resync with DC: {0}' -f $oneForestDC)

    $outSyncAll1 += repadmin /syncall /A /e $oneForestDC | % { $_.Trim() } | ? { $_ -ne '' }
    $outSyncAll1 += '== exitcode: {0}' -f $LASTEXITCODE
    $isError = ($LASTEXITCODE -ne 0) -or ($outSyncAll1 -notcontains 'SyncAll terminated with no errors.')
    if ($isError) { Write-Host ('Error') -ForegroundColor Red }
    $anyError = $anyError -or $isError

    $outSyncAll1 += klist purge | % { $_.Trim() } | ? { $_ -ne '' }
    $outSyncAll1 += '== exitcode: {0}' -f $LASTEXITCODE
    $isError = ($LASTEXITCODE -ne 0) -or ($outSyncAll1 -notcontains 'Ticket(s) purged!')
    if ($isError) { Write-Host ('Error') -ForegroundColor Red }
    $anyError = $anyError -or $isError

    $wmiCredUse = @{ Credential = $wmiCred }
    if ($oneForestDC -eq $localComputerName) {

      $wmiCredUse = @{}
    }

    $wmiStatus = $null
    $wmiStatus = gwmi -List Win32_Process -Comp $oneForestDC @wmiCredUse | % { $_.Create('klist purge -li 3e4') }
    $outSyncAll1 += '== WMI status: {0}' -f $wmiStatus.ReturnValue
    $isError = ($wmiStatus.ReturnValue -ne 0) -or ([object]::Equals($wmiStatus, $null))
    if ($isError) { Write-Host ('Error') -ForegroundColor Red }
    $anyError = $anyError -or $isError

    $wmiStatus = $null
    $wmiStatus = gwmi -List Win32_Process -Comp $oneForestDC @wmiCredUse | % { $_.Create('klist purge -li 3e7') }
    $outSyncAll1 += '== WMI status: {0}' -f $wmiStatus.ReturnValue
    $isError = ($wmiStatus.ReturnValue -ne 0) -or ([object]::Equals($wmiStatus, $null))
    if ($isError) { Write-Host ('Error') -ForegroundColor Red }
    $anyError = $anyError -or $isError
  }}
}

Start-Sleep -Milliseconds 450

Write-Host ('Reset again')
[string[]] $outNetdom2 = netdom resetpwd /server:$dcName /userD:$domainAdmin /passwordD:$daPwd | % { $_.Trim() } | ? { $_ -ne '' }
$outNetdom2 += '== exitcode: {0}' -f $LASTEXITCODE
$isError = ($LASTEXITCODE -ne 0) -or ($outNetdom2 -notcontains 'The machine account password for the local machine has been successfully reset.')
if ($isError) { Write-Host ('Error') -ForegroundColor Red }
$anyError = $anyError -or $isError

if ($isThisDC) { 
  
  [string[]] $outSyncAll2 = @()
  if ($allForestDCs.Length -gt 0) { foreach ($oneForestDC in $allForestDCs) {
    
    Write-Host ('Resync again with DC: {0}' -f $oneForestDC)

    $outSyncAll2 += repadmin /syncall /A /e $oneForestDC | % { $_.Trim() } | ? { $_ -ne '' }
    $outSyncAll2 += '== exitcode: {0}' -f $LASTEXITCODE
    $isError = ($LASTEXITCODE -ne 0) -or ($outSyncAll2 -notcontains 'SyncAll terminated with no errors.')
    if ($isError) { Write-Host ('Error') -ForegroundColor Red }
    $anyError = $anyError -or $isError

    $outSyncAll2 += klist purge | % { $_.Trim() } | ? { $_ -ne '' }
    $outSyncAll2 += '== exitcode: {0}' -f $LASTEXITCODE
    $isError = ($LASTEXITCODE -ne 0) -or ($outSyncAll2 -notcontains 'Ticket(s) purged!')
    if ($isError) { Write-Host ('Error') -ForegroundColor Red }
    $anyError = $anyError -or $isError

    $wmiCredUse = @{ Credential = $wmiCred }
    if ($oneForestDC -eq $localComputerName) {

      $wmiCredUse = @{}
    }

    $wmiStatus = $null
    $wmiStatus = gwmi -List Win32_Process -Comp $oneForestDC @wmiCredUse | % { $_.Create('klist purge -li 3e4') }
    $outSyncAll2 += '== WMI status: {0}' -f $wmiStatus.ReturnValue
    $isError = ($wmiStatus.ReturnValue -ne 0) -or ([object]::Equals($wmiStatus, $null))
    if ($isError) { Write-Host ('Error') -ForegroundColor Red }
    $anyError = $anyError -or $isError

    $wmiStatus = $null
    $wmiStatus = gwmi -List Win32_Process -Comp $oneForestDC @wmiCredUse | % { $_.Create('klist purge -li 3e7') }
    $outSyncAll2 += '== WMI status: {0}' -f $wmiStatus.ReturnValue
    $isError = ($wmiStatus.ReturnValue -ne 0) -or ([object]::Equals($wmiStatus, $null))
    if ($isError) { Write-Host ('Error') -ForegroundColor Red }
    $anyError = $anyError -or $isError
  }}
}

if (-not $isThisDC) { 

  Write-Host ('Verify after')

  [string[]] $outNltest = @()

  $outNltest += klist purge -li 3e4 | % { $_.Trim() } | ? { $_ -ne '' }
  $outNltest += '== exitcode: {0}' -f $LASTEXITCODE
  $isError = ($LASTEXITCODE -ne 0) -or ($outNltest -notcontains 'Ticket(s) purged!')
  if ($isError) { Write-Host ('Error') -ForegroundColor Red }
  $anyError = $anyError -or $isError

  $outNltest += klist purge -li 3e7 | % { $_.Trim() } | ? { $_ -ne '' }
  $outNltest += '== exitcode: {0}' -f $LASTEXITCODE
  $isError = ($LASTEXITCODE -ne 0) -or ($outNltest -notcontains 'Ticket(s) purged!')
  if ($isError) { Write-Host ('Error') -ForegroundColor Red }
  $anyError = $anyError -or $isError

  $outNltest += nltest /sc_verify:$domainSAMOnly | % { $_.Trim() } | ? { $_ -ne '' }
  $outNltest += '== exitcode: {0}' -f $LASTEXITCODE
  $isError = ($LASTEXITCODE -ne 0) -or ($outNltest -notcontains 'The command completed successfully')
  if ($isError) { Write-Host ('Error') -ForegroundColor Red }
  $anyError = $anyError -or $isError
}

if ($anyError) {

  Write-Host ('')
  Read-Host ('Press ENTER to see command ERRORS')
  Write-Host ('')
  Write-Host ('NETDOM1: {0}' -f ($outNetdom1 -join "`r`n")) -ForegroundColor Red
  Write-Host ('NETDOM2: {0}' -f ($outNetdom2 -join "`r`n")) -ForegroundColor Red
  Write-Host ('SYNCALL1: {0}' -f ($outSyncAll1 -join "`r`n")) -ForegroundColor Red
  Write-Host ('SYNCALL2: {0}' -f ($outSyncAll2 -join "`r`n")) -ForegroundColor Red
  Write-Host ('NLTEST: {0}' -f ($outNltest -join "`r`n")) -ForegroundColor Red
}

if ($error.Count -gt 0) {

  Write-Host ('')
  Read-Host ('Press ENTER to see function EXCEPTIONS')
  Write-Host ('')

  if ($error.Count -gt 0) { foreach ($oneError in $error) {

    Write-Host ('EXCEPTION: {0}' -f $oneError) -ForegroundColor Red
  }}
}

Write-Host ('')
Read-Host ('Press ENTER to exit') | Out-Null


# SIG # Begin signature block
# MIIfCQYJKoZIhvcNAQcCoIIe+jCCHvYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD3v8/UIUG8h3k4
# AtrVraTVS/6VkTnPHs+q7+daPhfkRqCCGQ8wggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggYEMIID7KADAgECAgoqHIRwAAEAAAB/MA0GCSqGSIb3DQEB
# CwUAMGwxCzAJBgNVBAYTAkNaMRcwFQYDVQQIEw5DemVjaCBSZXB1YmxpYzENMAsG
# A1UEBxMEQnJubzEQMA4GA1UEChMHU2V2ZWNlazEjMCEGA1UEAxMaU2V2ZWNlayBF
# bnRlcnByaXNlIFJvb3QgQ0EwHhcNMTkwNjExMTkyMzMyWhcNMjQwNjA5MTkyMzMy
# WjCBjzELMAkGA1UEBhMCQ1oxFzAVBgNVBAgTDkN6ZWNoIFJlcHVibGljMQ0wCwYD
# VQQHEwRCcm5vMRwwGgYDVQQKExNJbmcuIE9uZHJlaiBTZXZlY2VrMRcwFQYDVQQD
# Ew5PbmRyZWogU2V2ZWNlazEhMB8GCSqGSIb3DQEJARYSb25kcmVqQHNldmVjZWsu
# Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnkjWNkK4FfUUN8iA
# N91ry+wsSn8cFKJbMnROAqTrx8t3H315p2/bUG2DosCFOdu0WcaTOLdm5obhT+/3
# O7BqpdcnlWKlSEz4AL9zQeCbe4++NObBVPBbPE16j9C4xELoXW/Ti86C2PEkN5az
# GUvxGxzQQ45g32OsEI+Bh05qHMkk3oQ6L8O0Fpd5W4e+L4HuKS3JOikNhhryTNPD
# 9grF/0wXTzn94TrL1GohuaCPh8g9HOtMoDCd+ExnqV8q4k60D37BOK1I81hYFIBn
# 8MvCsjMRC5TK87MtI7aUUIeve5kopc8ZpxNti3F/+Puh4UUxL3nKjfAM6HE0b7Fq
# kfkRpwIDAQABo4IBgjCCAX4wEwYDVR0lBAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/
# BAQDAgbAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFOKb
# NkkiAht2GxCISJMJxLg4gOC9MB0GA1UdEQQWMBSBEm9uZHJlakBzZXZlY2VrLmNv
# bTAfBgNVHSMEGDAWgBQNnMgyfdUi8l9UfithS4FQ88VswDBSBgNVHR8ESzBJMEeg
# RaBDhkFodHRwOi8vcGtpLnNldmVjZWsuY29tL0NBL1NldmVjZWslMjBFbnRlcnBy
# aXNlJTIwUm9vdCUyMENBKDEpLmNybDCBhgYIKwYBBQUHAQEEejB4ME0GCCsGAQUF
# BzAChkFodHRwOi8vcGtpLnNldmVjZWsuY29tL0NBL1NldmVjZWslMjBFbnRlcnBy
# aXNlJTIwUm9vdCUyMENBKDEpLmNydDAnBggrBgEFBQcwAYYbaHR0cDovL3BraS5z
# ZXZlY2VrLmNvbS9vY3NwMA0GCSqGSIb3DQEBCwUAA4ICAQCfr6XDtt/O8OBr+X5l
# 49UBLaJrjUXHkAHofdC7p7BLCXIs4GYIti1lf6pas5yBQ428aKITITq/vEHUTyii
# yKtzVkafILWXXKPxy+zmmuw9odB3Hea4ECNpcaG8UNtzvMm1Dr0ZrkENhcv6I3tN
# hRr2AOE9AKOfnVEullFD/mZqfmaNkhpnl31jk7OMSUQcoY8qD6BDQP9371C10gJO
# mp57sHfPa4Vn5E4aNzn8+o9C9HI7nNagZF5BamKOFdR2ui7K3krMbTuDHo+ZcA9n
# HnzZqiVKpEBFu8lGv9Mf+GDb9yxz6EjV3xS2RcnywX2vz0VUt2NGno8LudrnWpgr
# Ry4Sl7x6FwVVKtS/o7zFSIiHgntIKFv8urSKSTukCLFKY9fBIDDlWFV1ZV1DNpNW
# xnexWIRv2AH7YlzKQCA4Rysn01hVeBGsWFkCr9J33LmVenQYpk9eoYMPRwAYg48r
# 65wOOOzLvmyLSGllH88BMvmTQ9myXqwp6NDH1psljXTlPUbpf7w6IZwsY0dhGhP9
# iyqbcrGdK0Bnf8Za6Qdj3iXtwd1VgpatFZrxOM5KawCLpkYl1ABupbzNpWzmC+nf
# ymqwbYiCogPt1vHOyF4EJ73ExVDCqXkpiNvFRqmu1eaZIOdbPCdl00a9rk52NKqo
# /BUsw16TKsDEYTA/7ACbEsnERzCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYq
# XlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGln
# aUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIz
# NTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTsw
# OQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVT
# dGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJ
# s8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJ
# C3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+
# QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3
# eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbF
# Hc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71
# h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseS
# v6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj
# 1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2L
# INIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJ
# jAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAO
# hFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNV
# HSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88w
# U86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZv
# xFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+R
# Zp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM
# 8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/E
# x8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd
# /yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFP
# vT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHics
# JttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2V
# Qbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ
# 8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr
# 9u3WfPwwggbAMIIEqKADAgECAhAMTWlyS5T6PCpKPSkHgD1aMA0GCSqGSIb3DQEB
# CwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0EwHhcNMjIwOTIxMDAwMDAwWhcNMzMxMTIxMjM1OTU5WjBGMQswCQYD
# VQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxJDAiBgNVBAMTG0RpZ2lDZXJ0IFRp
# bWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AM/spSY6xqnya7uNwQ2a26HoFIV0MxomrNAcVR4eNm28klUMYfSdCXc9FZYIL2tk
# pP0GgxbXkZI4HDEClvtysZc6Va8z7GGK6aYo25BjXL2JU+A6LYyHQq4mpOS7eHi5
# ehbhVsbAumRTuyoW51BIu4hpDIjG8b7gL307scpTjUCDHufLckkoHkyAHoVW54Xt
# 8mG8qjoHffarbuVm3eJc9S/tjdRNlYRo44DLannR0hCRRinrPibytIzNTLlmyLuq
# UDgN5YyUXRlav/V7QG5vFqianJVHhoV5PgxeZowaCiS+nKrSnLb3T254xCg/oxwP
# UAY3ugjZNaa1Htp4WB056PhMkRCWfk3h3cKtpX74LRsf7CtGGKMZ9jn39cFPcS6J
# AxGiS7uYv/pP5Hs27wZE5FX/NurlfDHn88JSxOYWe1p+pSVz28BqmSEtY+VZ9U0v
# kB8nt9KrFOU4ZodRCGv7U0M50GT6Vs/g9ArmFG1keLuY/ZTDcyHzL8IuINeBrNPx
# B9ThvdldS24xlCmL5kGkZZTAWOXlLimQprdhZPrZIGwYUWC6poEPCSVT8b876asH
# DmoHOWIZydaFfxPZjXnPYsXs4Xu5zGcTB5rBeO3GiMiwbjJ5xwtZg43G7vUsfHuO
# y2SJ8bHEuOdTXl9V0n0ZKVkDTvpd6kVzHIR+187i1Dp3AgMBAAGjggGLMIIBhzAO
# BgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEF
# BQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgw
# FoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYEFGKK3tBh/I8xFO2XC809
# KpQU31KcMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5j
# cmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5k
# aWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdD
# QS5jcnQwDQYJKoZIhvcNAQELBQADggIBAFWqKhrzRvN4Vzcw/HXjT9aFI/H8+ZU5
# myXm93KKmMN31GT8Ffs2wklRLHiIY1UJRjkA/GnUypsp+6M/wMkAmxMdsJiJ3Hjy
# zXyFzVOdr2LiYWajFCpFh0qYQitQ/Bu1nggwCfrkLdcJiXn5CeaIzn0buGqim8FT
# YAnoo7id160fHLjsmEHw9g6A++T/350Qp+sAul9Kjxo6UrTqvwlJFTU2WZoPVNKy
# G39+XgmtdlSKdG3K0gVnK3br/5iyJpU4GYhEFOUKWaJr5yI+RCHSPxzAm+18SLLY
# kgyRTzxmlK9dAlPrnuKe5NMfhgFknADC6Vp0dQ094XmIvxwBl8kZI4DXNlpflhax
# YwzGRkA7zl011Fk+Q5oYrsPJy8P7mxNfarXH4PMFw1nfJ2Ir3kHJU7n/NBBn9iYy
# mHv+XEKUgZSCnawKi8ZLFUrTmJBFYDOA4CPe+AOk9kVH5c64A0JH6EE2cXet/aLo
# l3ROLtoeHYxayB6a1cLwxiKoT5u92ByaUcQvmvZfpyeXupYuhVfAYOd4Vn9q78KV
# mksRAsiCnMkaBXy6cbVOepls9Oie1FqYyJ+/jbsYXEP10Cro4mLueATbvdH7Wwqo
# cH7wl4R44wgDXUcsY6glOJcB0j862uXl9uab3H4szP8XTE0AotjWAQ64i+7m4HJV
# iSwnGWH2dwGMMYIFUDCCBUwCAQEwejBsMQswCQYDVQQGEwJDWjEXMBUGA1UECBMO
# Q3plY2ggUmVwdWJsaWMxDTALBgNVBAcTBEJybm8xEDAOBgNVBAoTB1NldmVjZWsx
# IzAhBgNVBAMTGlNldmVjZWsgRW50ZXJwcmlzZSBSb290IENBAgoqHIRwAAEAAAB/
# MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEICB3C3t+SgQzAa6f9Zso56JE9FbzAxoBee1x
# jS38kNR2MA0GCSqGSIb3DQEBAQUABIIBADVSAlBtzv6ness8z0Tv1dziTEZPwpY/
# ENbZhg2FHF9/YV/lTK+cN9HJ116RD2W4Mm6gQq3YaH2jSsttflXZJihAMUFv7vnb
# ZOYeHW6ejgVEKR+XQR8ezyl996RlGgGU+iOiVZRH7dc98WFhPNf9Zm1eCxKmL/ID
# oGIFoQMpR9WV5UciG7WA041FVhNRuS23c2+TiUZ2vhvGRU+o6CdkOc05gL+jEZxX
# +JV1xavieMfaqdAiUB7Nlb7tVhggFpvKfpWu3/zEkCI/7gHQ+pAt+vNrKHw3YMUp
# kJvTXL3OtUK/g6PNkFOjzWGW+72Z5ZjNPDKHiuMRFv88tTNyh+zmkK6hggMgMIID
# HAYJKoZIhvcNAQkGMYIDDTCCAwkCAQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAMTWlyS5T6PCpKPSkHgD1a
# MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkq
# hkiG9w0BCQUxDxcNMjMwMTI0MTY0NTQ5WjAvBgkqhkiG9w0BCQQxIgQgUWjhGot3
# qa6u265RDK7C2+G94XZoRbLKjvsmEEUFYeowDQYJKoZIhvcNAQEBBQAEggIAxY17
# I/JY4rkGsxJTGR+GJlZEOdtXGoN5o8SFZ4cWi28c9visC6NvEVcx5sM+S7ZJcD0v
# H2MrBBUJitGbusRtsP5CDZJny38vmYO5ecvMqO19iueLmQVipdmpsCV0gPLrpy+k
# Sb6CzSs9T+nt3BzvzC3C5jfRHAVGskPh9YBWPKiHAKa0U1cNpNkFv34GzUHS2ZuD
# P4ISE64eJHkx8WvuTBQQB/pKrreOsvDekrI6uDtBSwYjkJ38bHpYqQgU3xSAStjU
# iMqFFEw9oYnwCW1uYPrFfzsGoasNw9pdZDHAuf02n34NEOOYv3us6st7hScVMFl2
# QWXlLFFbdHj82BxRoc878bcTbPltnoxgqnC2Oqxgnn5XpBK85HGVRACWhaFFzc2y
# TRBC3f38GnN3HNAqCUKfISVyq5tNP3nL0+2p4UA43miAgn4bClsnDfIC5Zkk3moe
# 9b0aOZukVu6rg3TKuB1X/RYigWmFTPPylFP6dbekofYQpsIyyL0yr/MgGpOt6ofh
# 7ygo0dlR+kndGIn24qmjJJB3gaEkI8aZm2fbwtMy6i/Rna1VFAKYDrf+R/c+nHOX
# REUHCYgmEY4LlQVp5o0iV7ilrhgVQTAH4HMRD9r6tCegTG3DnAtHn3ivE/nHdePX
# 9ncdsV+eGP3IxzrHNbHRLDizOlZgoBTQ6djPiXE=
# SIG # End signature block

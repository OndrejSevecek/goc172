
$global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

[string] $what = 'sevecek-test-http'
[string] $configFile = Join-Path $env:TEMP ('{0}-config.txt' -f $what)

[bool] $https      = $false
[string] $hostName = 'intranet.gopas.virtual'
[string] $url      = '/username.asp'

##
##

if (Test-Path $configFile) {

  Write-Host ('')
  Write-Host ('Load config file: {0}' -f $configFile)

  [string[]] $configItems = cat $configFile

  [string] $rxMuster = '(?i)\A\s*{0}\s*=\s*(.+)\s*\Z'
  $configItems | ? { $_ -match ($rxMuster -f 'https') } | % { $https = [bool]::Parse(([regex]::Match($_, ($rxMuster -f 'https')).Groups[1].Value)) }
  $configItems | ? { $_ -match ($rxMuster -f 'hostName') } | % { $hostName = [regex]::Match($_, ($rxMuster -f 'hostName')).Groups[1].Value }
  $configItems | ? { $_ -match ($rxMuster -f 'url') } | % { $url = [regex]::Match($_, ($rxMuster -f 'url')).Groups[1].Value }
}

##
##

Write-Host ('')

[string] $httpsSupplied = Read-Host ('Use encrypted HTTPS (default = {0})' -f $https)

if (-not ([string]::IsNullOrEmpty($httpsSupplied))) {

  $https = @('https', 's', 'y', 'yes', 't', 'true', '1') -contains $httpsSupplied.Trim()
}

[string] $hostNameSupplied = Read-Host ('Hostname (default = {0})' -f $hostName)

if (-not ([string]::IsNullOrEmpty($hostNameSupplied))) {

  $hostName = $hostNameSupplied.Trim().ToLower()
}

[string] $urlSupplied = Read-Host ('URL (default = {0})' -f $url)

if (-not ([string]::IsNullOrEmpty($urlSupplied))) {

  $url = $urlSupplied.Trim()

  if ($url -eq '-') {

    $url = $null
  }
}

##
##

[Collections.ArrayList] $saveConfig = @()
[void] $saveConfig.Add(('https = {0}' -f $https))
[void] $saveConfig.Add(('hostName = {0}' -f $hostName))
[void] $saveConfig.Add(('url = {0}' -f $url))
$saveConfig | Out-File $configFile -Encoding UTF8 -Force

##
##

[string] $fullURI = '{0}/{1}' -f $hostName, ($url -replace '\A[\\\/\s]+', '')

if ($https) {

  $fullURI = 'https://{0}' -f $fullURI

} else {

  $fullURI = 'http://{0}' -f $fullURI
}

Write-Host ('')
Write-Host ('Download URI: {0}' -f $fullURI)

[bool] $obtained = $false
try {

  $result = Invoke-WebRequest -Uri $fullURI -UseBasicParsing -UseDefaultCredentials -UserAgent $what -Headers @{ 'Cache-Control' = 'no-cache' }

  Write-Host ('')
  Write-Host ('Result code: {0}' -f $result.StatusCode)
  Write-Host ('Content type: {0}' -f $result.Headers['Content-Type'])

  $obtained = $true

} catch {

  Write-Host ('')
  Write-Host ('Error: {0}' -f $_.Exception.Message) -Fore Red
}

##
##

if ($obtained) {

  Write-Host ('')
  Write-Host ('Finished SUCCESS') -Fore Green
  exit 0

} else {

  Write-Host ('')
  Write-Host ('Finished ERROR') -Fore Red
  exit 1
}



# SIG # Begin signature block
# MIIfCwYJKoZIhvcNAQcCoIIe/DCCHvgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBTpuTRdIlCKL19
# wMOthsBucZtj7xg52fNXaKF6VLKgbKCCGREwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# 9u3WfPwwggbCMIIEqqADAgECAhAFRK/zlJ0IOaa/2z9f5WEWMA0GCSqGSIb3DQEB
# CwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0EwHhcNMjMwNzE0MDAwMDAwWhcNMzQxMDEzMjM1OTU5WjBIMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xIDAeBgNVBAMTF0RpZ2lD
# ZXJ0IFRpbWVzdGFtcCAyMDIzMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEAo1NFhx2DjlusPlSzI+DPn9fl0uddoQ4J3C9Io5d6OyqcZ9xiFVjBqZMRp82q
# smrdECmKHmJjadNYnDVxvzqX65RQjxwg6seaOy+WZuNp52n+W8PWKyAcwZeUtKVQ
# gfLPywemMGjKg0La/H8JJJSkghraarrYO8pd3hkYhftF6g1hbJ3+cV7EBpo88MUu
# eQ8bZlLjyNY+X9pD04T10Mf2SC1eRXWWdf7dEKEbg8G45lKVtUfXeCk5a+B4WZfj
# RCtK1ZXO7wgX6oJkTf8j48qG7rSkIWRw69XloNpjsy7pBe6q9iT1HbybHLK3X9/w
# 7nZ9MZllR1WdSiQvrCuXvp/k/XtzPjLuUjT71Lvr1KAsNJvj3m5kGQc3AZEPHLVR
# zapMZoOIaGK7vEEbeBlt5NkP4FhB+9ixLOFRr7StFQYU6mIIE9NpHnxkTZ0P387R
# Xoyqq1AVybPKvNfEO2hEo6U7Qv1zfe7dCv95NBB+plwKWEwAPoVpdceDZNZ1zY8S
# dlalJPrXxGshuugfNJgvOuprAbD3+yqG7HtSOKmYCaFxsmxxrz64b5bV4RAT/mFH
# Coz+8LbH1cfebCTwv0KCyqBxPZySkwS0aXAnDU+3tTbRyV8IpHCj7ArxES5k4Msi
# K8rxKBMhSVF+BmbTO77665E42FEHypS34lCh8zrTioPLQHsCAwEAAaOCAYswggGH
# MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsG
# AQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSME
# GDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUpbbvE+fvzdBkodVW
# qWUxo97V40kwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NB
# LmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
# LmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGlu
# Z0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAgRrW3qCptZgXvHCNT4o8aJzYJf/L
# LOTN6l0ikuyMIgKpuM+AqNnn48XtJoKKcS8Y3U623mzX4WCcK+3tPUiOuGu6fF29
# wmE3aEl3o+uQqhLXJ4Xzjh6S2sJAOJ9dyKAuJXglnSoFeoQpmLZXeY/bJlYrsPOn
# vTcM2Jh2T1a5UsK2nTipgedtQVyMadG5K8TGe8+c+njikxp2oml101DkRBK+IA2e
# qUTQ+OVJdwhaIcW0z5iVGlS6ubzBaRm6zxbygzc0brBBJt3eWpdPM43UjXd9dUWh
# pVgmagNF3tlQtVCMr1a9TMXhRsUo063nQwBw3syYnhmJA+rUkTfvTVLzyWAhxFZH
# 7doRS4wyw4jmWOK22z75X7BC1o/jF5HRqsBV44a/rCcsQdCaM0qoNtS5cpZ+l3k4
# SF/Kwtw9Mt911jZnWon49qfH5U81PAC9vpwqbHkB3NpE5jreODsHXjlY9HxzMVWg
# gBHLFAx+rrz+pOt5Zapo1iLKO+uagjVXKBbLafIymrLS2Dq4sUaGa7oX/cR3bBVs
# rquvczroSUa31X/MtjjA2Owc9bahuEMs305MfR5ocMB3CtQC4Fxguyj/OOVSWtas
# FyIjTvTs0xf7UGv/B3cfcZdEQcm4RtNsMnxYL2dHZeUbc7aZ+WssBkbvQR7w8F/g
# 29mtkIBEr4AQQYoxggVQMIIFTAIBATB6MGwxCzAJBgNVBAYTAkNaMRcwFQYDVQQI
# Ew5DemVjaCBSZXB1YmxpYzENMAsGA1UEBxMEQnJubzEQMA4GA1UEChMHU2V2ZWNl
# azEjMCEGA1UEAxMaU2V2ZWNlayBFbnRlcnByaXNlIFJvb3QgQ0ECCiochHAAAQAA
# AH8wDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQga85yteLzaKtER5lfY7VCYtlDF4nV8TeP
# tCQCMQpOs/swDQYJKoZIhvcNAQEBBQAEggEAgK7bAINe42LRqioZems7dlijJs2H
# f8cj9oDc77oRsaI+RjAy4WY48V9hx/P1Nb3IjzYrpimLd5sqMP4ApSeP/E6T8WmQ
# K4ATgmiXy987wOqgYjBiro/pBhhJY4e1soNm0azZ3D4cUb8VskhkuK1Z/zC8NC5q
# n2V3hnDFpNyZuqK02YDIZwGp7s+h5/JOM7xcW0RH8P61hq/dO11Z0BgT9shgBsvY
# /YIWF7BMXUmTKyZ/vuXGqvuDTsav5wRQkP31e1aLUa9f6TuF+76RdFsJbg3IF+6S
# y54gzEZqWqsCatdgNalaUqrDCcNVhAKBHuYUKy0C/56i+OVIGjlzNCqEw6GCAyAw
# ggMcBgkqhkiG9w0BCQYxggMNMIIDCQIBATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBH
# NCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/l
# YRYwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0yMzExMTQxNjEwMDJaMC8GCSqGSIb3DQEJBDEiBCA1w32i
# cIHH/Ebg1tbJBIP5+dIJgm3k+P4XvgYxP9yHYDANBgkqhkiG9w0BAQEFAASCAgBl
# MTaIV6q+SasNwc8ZBK62l9rfFNw1A/rrVwoaLzE66G+ITIfOqz/YpwNSsHnvB9X1
# rsPqo/t6n1rG/BIo3NZG0mNMy0K65l2ExtaWqvDFVyXCL/ffjeZ67LFnAVqakXxw
# s9zliKKnb6QrJSMElyiYblnbYzAc8raOYb0iozjc5jtfz7DyUW72bKLPHAhHObtx
# MxGXVt9lQ9uDmw7H/onc+o+4AqI/yJzMRIcI0eu8aUmz6TfltWpg2w6f8756khDL
# cV/2hAopBXDo6UBdiv97JZy793owuyxrigCG6B8BDIA5hHkkAsG62L1eUnGh/Oio
# XRdAFryIX7fYrCBfAM27UuQbw2lEktzbk1NvNlAEdgr9LwJWYNIubD8Ly/UV3JhD
# jz30f0kjEmPh4Pp/5Ed+gATqp5FXkJNztjymyK9anPQr+0f07sfmqcRmvi4PWDtt
# nMKR6vWYHCv6IkdQq+KiEvPMIWY77Hg7MCnKuVtB7kDkUz6NWJB6MQ48wvPSf4nE
# 3FXA3EURvZBGa+Sh8YmmP20SdGbnDry5V1HDoaMC4+/n+XTLwdFYfeMncxU4h8XS
# JbYfalRZvKozRl/PU9k2slHJRVogtEZs8MGMHQeM+p4GIuCS0OqWg5sOr9PT6rSV
# mwc4rujg2iQdZ6ZmtKEoRZQjlDouF2Zwjea9SVbwYQ==
# SIG # End signature block

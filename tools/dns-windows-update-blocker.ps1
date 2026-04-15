
$global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

[string[]] $blockZones = @('delivery.mp.microsoft.com')
[int] $expirationSec = 60

[bool] $success = $false
try {

  $dnsServer = $null
  try { $dnsServer = Get-Service dns } catch { $error.Clear() }

  if ([object]::Equals($dnsServer, $null)) {

    throw ('You must run this script on a DNS server')
  }

  ##
  ##

  Write-Host ('')

  [Microsoft.Management.Infrastructure.CimInstance] $firstZoneExists = $null
  try { $firstZoneExists = Get-DnsServerZone -Name $blockZones[0] } catch { $error.Clear() }

  [string] $action = 'BLOCK'
  
  if (-not ([object]::Equals($firstZoneExists, $null))) {

    $action = 'UNBLOCK'
  }

  [string] $actionSupplied = Read-Host ('BLOC or UNBLOCK the queries for Microsoft download DNS zones (default = {0})' -f $action)

  if (-not ([string]::IsNullOrEmpty($actionSupplied))) {

    if ($actionSupplied.Trim() -like 'U*') {

      $action = 'UNBLOCK'

    } else {

      $action = 'BLOCK'
    }
  }

  ##
  ##

  [bool] $isDC = (Get-WmiObject Win32_OperatingSystem).ProductType -eq 2

  ##
  ##

  Write-Host ('')

  if ($action -eq 'BLOCK') {

    if ($blockZones.Length -gt 0) { foreach ($oneBlockZone in $blockZones) {

      Write-Host ('Verify existance of a blocking zone: {0}' -f $oneBlockZone)

      [Microsoft.Management.Infrastructure.CimInstance] $zoneExists = $null
      try { $zoneExists = Get-DnsServerZone -Name $oneBlockZone } catch { $error.Clear() }

      if ([object]::Equals($zoneExists, $null)) {

        Write-Host ('Create blocking zone: {0} | domain = {1}' -f $oneBlockZone, $isDC)
  
        if ($isDC) {

          $zoneExists = Add-DnsServerPrimaryZone -Name $oneBlockZone -DynamicUpdate None -ReplicationScope Forest -PassThru

        } else {

          $zoneExists = Add-DnsServerPrimaryZone -Name $oneBlockZone -DynamicUpdate None -PassThru
        }
      }

      Write-Host ('Get SOA details of the zone: {0}' -f $oneBlockZone)
      [Microsoft.Management.Infrastructure.CimInstance] $soaDetails = Get-DnsServerResourceRecord -ZoneName $oneBlockZone -RRType SOA

      Write-Host ('Update zone TTL expiration: {0} sec' -f $expirationSec)
      $updatedSOADetails = $soaDetails.Clone()
      $updatedSOADetails.RecordData.SerialNumber = $soaDetails.RecordData.SerialNumber + 1
      $updatedSOADetails.TimeToLive = [TimeSpan]::FromSeconds($expirationSec)
      $updatedSOADetails.RecordData.ExpireLimit = [TimeSpan]::FromSeconds($expirationSec)
      $updatedSOADetails.RecordData.MinimumTimeToLive = [TimeSpan]::FromSeconds($expirationSec)
      $updatedSOADetails.RecordData.RefreshInterval = [TimeSpan]::FromSeconds($expirationSec)
      $updatedSOADetails.RecordData.RetryDelay = [TimeSpan]::FromSeconds($expirationSec)

      Set-DnsServerResourceRecord -ZoneName $oneBlockZone -OldInputObject $soaDetails -NewInputObject $updatedSOADetails
    }}

    ##
    ##

  } else {

    ##
    ##

    if ($blockZones.Length -gt 0) { foreach ($oneBlockZone in $blockZones) {

      Write-Host ('Verify existance of a blocking zone: {0}' -f $oneBlockZone)

      [Microsoft.Management.Infrastructure.CimInstance] $zoneExists = $null
      try { $zoneExists = Get-DnsServerZone -Name $oneBlockZone } catch { $error.Clear() }

      if (-not ([object]::Equals($zoneExists, $null))) {

        Write-Host ('Remove the blocking zone: {0}' -f $oneBlockZone)
        Remove-DnsServerZone -Name $oneBlockZone -Force
      }
    }}
  }

  ##
  ##

  [int] $adSleep = 16
  [Collections.ArrayList] $dnsServers = @()

  if ($isDC) {

    [WMI] $wmiComp = Get-WmiObject Win32_ComputerSystem
    [string] $localFQDN = '{0}.{1}' -f $wmiComp.DNSHostName, $wmiComp.Domain
    [void] $dnsServers.Add($localFQDN)

    Write-Host ('')

    [Microsoft.ActiveDirectory.Management.ADForest] $forest = Get-ADForest
    Write-Host ('Get AD domain controllers of the whole forest: {0}' -f $forest.Name)

    [string[]] $dcs = $forest.Domains | % { Get-ADDomainController -Filter * -Server $_ } | select -Expand HostName | sort | select -Unique
    Write-Host ('Domain controllers found: #{0}' -f $dcs.Length)

    if ($dcs.Length -gt 0) { foreach ($oneDC in $dcs) {

      if ($oneDC -ne $localFQDN) {

        [Microsoft.Management.Infrastructure.CimInstance] $hasDNS = $null
        try { $hasDNS = Get-DnsServer -ComputerName $oneDC } catch { $error.Clear() }

        if (-not ([object]::Equals($hasDNS, $null))) {

          Write-Host ('Another DC with DNS server: {0}' -f $oneDC)
          [void] $dnsServers.Add($oneDC)
        }
      }
    }}

  } else {

    [void] $dnsServers.Add('localhost')
  }

  ##
  ##

  Write-Host ('')

  if ($isDC -and ($dnsServers.Count -gt 1)) {

    Write-Host ('Give AD some time to replicate: {0}' -f $adSleep)
    Start-Sleep -Seconds $adSleep
  }

  if ($dnsServers.Count -gt 0) { foreach ($oneDnsServer in $dnsServers) {

    Write-Host ('Clear DNS server cache: {0}' -f $oneDnsServer)
    Clear-DnsServerCache -ComputerName $oneDnsServer -Force

    if ($oneDnsServer -ne $localFQDN) {

      Write-Host ('Restart remote DNS server service: {0}' -f $oneDnsServer)
      try { Invoke-Command -ComputerName $oneDnsServer -ScriptBlock { Restart-Service -Name DNS } } catch { Write-Host ('Error: {0}' -f $_) -Fore Red; $error.Clear() }

    } else {

      # Note: for some reason the Invoke-Command does not work when used with FQDN of the local machine
      #       although it works with "localhost" for example
      Write-Host ('Restart local DNS server service: {0}' -f $oneDnsServer)
      Restart-Service -Name DNS
    }
  }}

  ##
  ##

  $success = $true

} catch {

  Write-Host ('')
  Write-Host ('Error: {0}' -f $_) -Fore Red

} finally {

}

if ($success) {

  Write-Host ('')
  Write-Host ('Finished SUCCESS')

} else {

  Write-Host ('')
  Write-Host ('Finished ERROR')
}

if ([object]::Equals($psISE, $null)) {

  Read-Host ('Press ENTER to exit') | Out-Null

} else {

}


# SIG # Begin signature block
# MIIfJQYJKoZIhvcNAQcCoIIfFjCCHxICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD4e3Ru9olQoxqB
# Wyke012p+d2d9KQYzVMnXXVTasepGqCCGSswggWNMIIEdaADAgECAhAOmxiO+dAt
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
# twGpn1eqXijiuZQwggYkMIIEDKADAgECAgoVuN6XAAEAAA0fMA0GCSqGSIb3DQEB
# CwUAMGwxCzAJBgNVBAYTAkNaMRcwFQYDVQQIEw5DemVjaCBSZXB1YmxpYzENMAsG
# A1UEBxMEQnJubzEQMA4GA1UEChMHU2V2ZWNlazEjMCEGA1UEAxMaU2V2ZWNlayBF
# bnRlcnByaXNlIFJvb3QgQ0EwHhcNMjQwNjEzMTIyNzU2WhcNMjkwNjEyMTIyNzU2
# WjCBjzELMAkGA1UEBhMCQ1oxFzAVBgNVBAgTDkN6ZWNoIFJlcHVibGljMQ0wCwYD
# VQQHEwRCcm5vMRwwGgYDVQQKExNJbmcuIE9uZHJlaiBTZXZlY2VrMRcwFQYDVQQD
# Ew5PbmRyZWogU2V2ZWNlazEhMB8GCSqGSIb3DQEJARYSb25kcmVqQHNldmVjZWsu
# Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArq1HZXqvx3EGmytK
# xbiAx6T/TcSIuiGK3U1PoQB6OS4uFZTo8CvvHzbEizZ+U+YxNSMNnl7itjzjnqpO
# 54pKqvwf26hZGJfgD+5+M5LCcsz49quKXUdC1nB68VH5pO6WqSdDKDQUrCAt50LF
# ij5chcKhXsppnnGPnFbeufkyDgjoCCi5MZR+MX5vJ6QIqIToDwr4/aZah6FRix78
# AOJ5+0FtV2MqwRx4jTmGTuDicgqGC9eguXy6WA0vmFwjkyDG4/9daZtVhNJ7/U6o
# T4MJFJAU1j+ZppRpxRIIoomhqkAVaFsv2abbt9mak6b38eKe00ylUtMmfY8pu9zI
# e5yKNwIDAQABo4IBojCCAZ4wPQYJKwYBBAGCNxUHBDAwLgYmKwYBBAGCNxUIh43B
# KITp7g6ErYMig+CHBYWv0mGBCYGWPoTxkXACAWQCAQIwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwDgYDVR0PAQH/BAQDAgbAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUH
# AwMwHQYDVR0OBBYEFAbXXxbbIgpHHIVag4jBeWWwqk2yMB8GA1UdIwQYMBaAFA2c
# yDJ91SLyX1R+K2FLgVDzxWzAMFIGA1UdHwRLMEkwR6BFoEOGQWh0dHA6Ly9wa2ku
# c2V2ZWNlay5jb20vQ0EvU2V2ZWNlayUyMEVudGVycHJpc2UlMjBSb290JTIwQ0Eo
# MSkuY3JsMIGGBggrBgEFBQcBAQR6MHgwTQYIKwYBBQUHMAKGQWh0dHA6Ly9wa2ku
# c2V2ZWNlay5jb20vQ0EvU2V2ZWNlayUyMEVudGVycHJpc2UlMjBSb290JTIwQ0Eo
# MSkuY3J0MCcGCCsGAQUFBzABhhtodHRwOi8vcGtpLnNldmVjZWsuY29tL29jc3Aw
# DQYJKoZIhvcNAQELBQADggIBAHJbWyZcBbsZ3lmMcIrrk0ITBTkg+h5xNlmEwvEB
# vSjCjli+SPVu19ryyf4yL7jmCGxCfX3+51PJGMumZO1MxqLUvrvt1zVi9gdo+Zlb
# e1qphXr3juBLsWG90DpA5vyoFngIx07tbziQgx59zhIiPS1O2PcAZFM06jqa/tBL
# a6OUOqYLJyww+wcTOLDzJ0bWZbNEa0zLgU1keufF63YFJfptqCcVyhlA/iTQs8IC
# LmLO+DvtldjDNpTjw/4VZYux1ikHtB0Zn3hYIC9qEiSftTmLayrW/doG+Em+53Pf
# BN5ZHtOLB+ycTJKJOZjg+IN2GIMp8/M8r+5/YY0GdbPdpIKXXPl5kCJjr5NarUcp
# d59Q0bijUZpU4+CdsOG7jc/vS9dzqBNUthFGjw0eRMoyWMkXMVvcJH91Nkyf3r1g
# moikfWaBH7f4zgrjqxKig9PHQ9L6AbrNwWcZsHytXGnhDD1gP/VfcgdEAyzOOUsI
# WAArSDVy2IEmBmLyNamCtKuNxaoUienVmqVSiSX7eBM3v8rgBrPpcpA2CH+D9OPB
# nVvFBmu/OSOGD5x2QNulElwVdUTzYHI1Xcfnujfurdp6W+2ro7y4t8uESqko5K/K
# CWJRbA2yAT2QZi+kXIz0JNVg9XFkZ415Tusz6atCaa1yMgLKisB/gBDn2IfZgTaS
# 5w9HMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsF
# ADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
# ExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJv
# b3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0
# IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mX
# UaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34
# V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevT
# sbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GD
# Gd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8By
# xbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcg
# Q+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKV
# EStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP
# 0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj3
# 3GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9
# XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2
# udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# CDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# IAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUA
# A4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2q
# KWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVz
# jQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2yS
# vZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQe
# JsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeH
# JLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1P
# tkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5
# h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZ
# Wcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT
# /r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP
# /JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrwwggSkoAMC
# AQICEAuuZrxaun+Vh8b56QTjMwQwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBU
# cnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yNDA5
# MjYwMDAwMDBaFw0zNTExMjUyMzU5NTlaMEIxCzAJBgNVBAYTAlVTMREwDwYDVQQK
# EwhEaWdpQ2VydDEgMB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+anOf9pUhq5Ywultt5lmjtej9
# kR8YxIg7apnjpcH9CjAgQxK+CMR0Rne/i+utMeV5bUlYYSuuM4vQngvQepVHVzNL
# O9RDnEXvPghCaft0djvKKO+hDu6ObS7rJcXa/UKvNminKQPTv/1+kBPgHGlP28mg
# moCw/xi6FG9+Un1h4eN6zh926SxMe6We2r1Z6VFZj75MU/HNmtsgtFjKfITLutLW
# UdAoWle+jYZ49+wxGE1/UXjWfISDmHuI5e/6+NfQrxGFSKx+rDdNMsePW6FLrphf
# Ytk/FLihp/feun0eV+pIF496OVh4R1TvjQYpAztJpVIfdNsEvxHofBf1BWkadc+U
# p0Th8EifkEEWdX4rA/FE1Q0rqViTbLVZIqi6viEk3RIySho1XyHLIAOJfXG5PEpp
# c3XYeBH7xa6VTZ3rOHNeiYnY+V4j1XbJ+Z9dI8ZhqcaDHOoj5KGg4YuiYx3eYm33
# aebsyF6eD9MF5IDbPgjvwmnAalNEeJPvIeoGJXaeBQjIK13SlnzODdLtuThALhGt
# yconcVuPI8AaiCaiJnfdzUcb3dWnqUnjXkRFwLtsVAxFvGqsxUA2Jq/WTjbnNjIU
# zIs3ITVC6VBKAOlb2u29Vwgfta8b2ypi6n2PzP0nVepsFk8nlcuWfyZLzBaZ0Muc
# EdeBiXL+nUOGhCjl+QIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1Ud
# EwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZn
# gQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCP
# nshvMB0GA1UdDgQWBBSfVywDdw4oFZBmpWNe7k+SH3agWzBaBgNVHR8EUzBRME+g
# TaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRS
# U0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCB
# gDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUF
# BzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUA
# A4ICAQA9rR4fdplb4ziEEkfZQ5H2EdubTggd0ShPz9Pce4FLJl6reNKLkZd5Y/vE
# IqFWKt4oKcKz7wZmXa5VgW9B76k9NJxUl4JlKwyjUkKhk3aYx7D8vi2mpU1tKlY7
# 1AYXB8wTLrQeh83pXnWwwsxc1Mt+FWqz57yFq6laICtKjPICYYf/qgxACHTvypGH
# rC8k1TqCeHk6u4I/VBQC9VK7iSpU5wlWjNlHlFFv/M93748YTeoXU/fFa9hWJQku
# zG2+B7+bMDvmgF8VlJt1qQcl7YFUMYgZU1WM6nyw23vT6QSgwX5Pq2m0xQ2V6FJH
# u8z4LXe/371k5QrN9FQBhLLISZi2yemW0P8ZZfx4zvSWzVXpAb9k4Hpvpi6bUe8i
# K6WonUSV6yPlMwerwJZP/Gtbu3CKldMnn+LmmRTkTXpFIEB06nXZrDwhCGED+8Rs
# WQSIXZpuG4WLFQOhtloDRWGoCwwc6ZpPddOFkM2LlTbMcqFSzm4cd0boGhBq7vkq
# I1uHRz6Fq1IX7TaRQuR+0BGOzISkcqwXu7nMpFu3mgrlgbAW+BzikRVQ3K2YHcGk
# iKjA4gi4OA/kz1YCsdhIBHXqBzR0/Zd2QwQ/l4Gxftt/8wY3grcc/nS//TVkej9n
# mUYu83BDtccHHXKibMs/yXHhDXNkoPIdynhVAku7aRZOwqw6pDGCBVAwggVMAgEB
# MHowbDELMAkGA1UEBhMCQ1oxFzAVBgNVBAgTDkN6ZWNoIFJlcHVibGljMQ0wCwYD
# VQQHEwRCcm5vMRAwDgYDVQQKEwdTZXZlY2VrMSMwIQYDVQQDExpTZXZlY2VrIEVu
# dGVycHJpc2UgUm9vdCBDQQIKFbjelwABAAANHzANBglghkgBZQMEAgEFAKCBhDAY
# BgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEi
# BCAjQuBF1O3I0nxqJJI5I5Q9YW8WV0Kmkt2idYoIIqLgpjANBgkqhkiG9w0BAQEF
# AASCAQBQ7l0l0oQ+rGYpbKTHblqP8UV8sJEdB9zoc1EufABRv9+M9TMMUW3GnLDV
# ZpYzkboQTfPxVB3AiloF55RfoCGJzXEaS83toHsyftmOn35wW8rhfKVUORt6gFbX
# E6fdVuuV7ttMuQIYFMNVEWPVSslogfaeELPpii9S9GZBec96d1hHqRKnLv64yt7Q
# OkqkwRpxjnfbn6QRttN/e5Lx+mdo1CelorZ0AZHSlp4cUuK62XvFq1hDD2/cashN
# erFMWVI4H7JmvZqGwyYywCXsEpKsnzADM9nCKF6/m5XXzT3KBStR2gnBpnNqR3zo
# FBuhkAJHkJSEk7VlC2+xv78qB4HHoYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJ
# AgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTsw
# OQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVT
# dGFtcGluZyBDQQIQC65mvFq6f5WHxvnpBOMzBDANBglghkgBZQMEAgEFAKBpMBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDIwMzE0
# MjUzN1owLwYJKoZIhvcNAQkEMSIEIMM3o7NSwi/38sQ/JIGv1INJywu9aIVWprUp
# zUjPFkjDMA0GCSqGSIb3DQEBAQUABIICAKi+QmCowUVja0ARpwSj5vhmG01Ad+Vp
# 4fcJDds44Ndyt8GOxQzHpS86Qi+WoR5tIs8vMfY+0OeRFy4iQq/V8MYYIlM2hFXU
# fMmDNKxMac/XYcl4EK2+E9iKn0fxO+bgbNmPLarvKc6FKg5U31sGeOAgYOrnqLIf
# VYfdQ1jU6edgq/Oumkc/8qNqvYqHqflR+aikI1yG4ZHV7B+wpFtAQWl41haYGvX/
# dkcJN6RWKfgT2o9OQbStCqh6/2ZdaB3P5518X62nBeVOwVgubSgwKrz9EgVFPVws
# 2g+auPN3FFpgFg32QWYQuq+nmCHs0cl4xgUVRCLk185TR+qUBdBUWM7uPj8vmQK4
# 2Wiv6zZZHWajYsfNTISKhVZt84n8XOsVvYUOc9F0zQ5QOiZM+UG7S0br0dMzvX6Z
# 0h9Gmu0HuB3PguWrChDstVSGEIWeg0A1AWt14WyPNWTrcskdbP44W+fbruScjyZC
# ucn/zYdLuKFU6buknq3IoqBPzbkowcIgymBytVqG54nStwa0qywX9dB3FLC1na51
# iDdB7eK6e11sEwoYzUSpKiqSZrDuEEwAhNjuYzKvzErFiWisH1mnRctGHQB3jMry
# +hvKSCPUCkt9R/ckONH04o9DPBVVbHO59wXPN4hHllghc2yu9MDCbpgrVpElQAja
# Efpb4xVD/T4Z
# SIG # End signature block

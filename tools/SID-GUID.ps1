
$global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

##
##

function Translate-AADSIDvsGUID (
  [string] $sidOrGuid, 
  [string] $sidDomain = 'S-1-12-1'
  )
{
  try {

    if ($sidOrGuid -like 'S-1-?*') {

      $sid = New-Object Security.Principal.SecurityIdentifier $sidOrGuid
      [byte[]] $binarySID = New-Object byte[] $sid.BinaryLength
      [void] $sid.GetBinaryForm($binarySID, 0)
      return ([guid] ([byte[]] $binarySID[12..27])).ToString()

    } else {

      [byte[]] $byteGuid = ([guid]::Parse($sidOrGuid)).ToByteArray()
      return ('{0}-{1}-{2}-{3}-{4}' -f ($sidDomain -replace '[\s\-]+\Z', ''),
                ([BitConverter]::ToUInt32(([byte[]] $byteGuid[0..3]), 0)),
                ([BitConverter]::ToUInt32(([byte[]] $byteGuid[4..7]), 0)),
                ([BitConverter]::ToUInt32(([byte[]] $byteGuid[8..11]), 0)),
                ([BitConverter]::ToUInt32(([byte[]] $byteGuid[12..15]), 0)))
    }

  } catch {

    Write-Host ('Error: translating SIG vs. GUID: {0}' -f $sidOrGuid) -Fore Red
  }
}

# Note: in order to get GUIDs of AAD/EntraID roles use
# Get-MgDirectoryRole | select DisplayName, Id, RoleTemplateId

function global:Translate-SIDtoLogin ([string] $sid)
{
  try {

    $login = (New-Object System.Security.Principal.SecurityIdentifier $sid).Translate([System.Type]::GetType('System.Security.Principal.NTAccount')).Value

  } catch {

    Write-Host ('Error: translating SID to login: {0} | {1}' -f $sid, $_) -Fore Red
  }

  return $login
}

function global:Translate-LoginToSID ([string] $login)
{
  [string] $sid = $null

  try {

    $sid = (New-Object Security.Principal.NTAccount $login).Translate([Security.Principal.SecurityIdentifier]).Value

  } catch {

    Write-Host ('Error: translating login to SID: {0} | {1}' -f $login, $_) -Fore Red
  }

  return $sid
}

##
##

[bool] $success = $false

try {

  [string] $machineHost = Get-WmiObject Win32_ComputerSystem | select -Expand DnsHostName
  [string] $machineNetBIOS = Get-WmiObject Win32_ComputerSystem | select -Expand Name
  [bool] $isDC = (Get-WmiObject Win32_OperatingSystem | select -Expand ProductType) -eq 2

  Write-Host ('')
  Write-Host ('In order to provide BYTE[] array start the entry with SID#, GUID#, ASCII#, UTF8# or UNICODE# prefixes')
  Write-Host ('With BYTE[] array input you can use hex values or Base64 encoded string')

  [string] $sidOrGuidOrLogin = 'S-1-5-32-544'
  [string] $sidOrGuidOrLoginSupplied = Read-Host ('SID or GUID or LOGIN to translate (default = {0})' -f $sidOrGuidOrLogin)

  if (-not ([string]::IsNullOrEmpty($sidOrGuidOrLoginSupplied))) {

    $sidOrGuidOrLogin = $sidOrGuidOrLoginSupplied.Trim()
  }

  [string] $rxPrefixedBytes = '(?i)\A\s*(\w+)\s*\#\s*(.+[^\s]*)\s*\Z'
  [string] $rxGUID = '(?:\{|)\s*[0-9a-fA-F]{8}[\-\s\,\;\\]*[0-9a-fA-F]{4}[\-\s\,\;\\]*[0-9a-fA-F]{4}[\-\s\,\;\\]*[0-9a-fA-F]{4}[\-\s\,\;\\]*[0-9a-fA-F]{12}\s*(?:\}|)'
  
  if ($sidOrGuidOrLogin -match $rxPrefixedBytes) {

    [string] $prefixExtracted = [regex]::Match($sidOrGuidOrLogin, $rxPrefixedBytes).Groups[1].Value
    [string] $bytesExtracted = [regex]::Match($sidOrGuidOrLogin, $rxPrefixedBytes).Groups[2].Value -replace '\s*', ''
    [string] $bytesExtractedNormalized = $bytesExtracted -replace '[^0-9a-fA-F]', ''
    
    if ($bytesExtracted.Length -lt 1) {

      throw ('Invalid byte array supplied: {0} | {1}' -f $sidOrGuidOrLogin, $bytesExtracted)
    }

    [byte[]] $bytes = $null

    if (($bytesExtracted -match '\A[a-zA-Z0-9\+\/\=]+\Z') -and ($bytesExtracted -notmatch '\A[0-9a-fA-F]+\Z')) {

      try { $bytes = [Convert]::FromBase64String($bytesExtracted)
      } catch { $error.Clear() }
    }

    if ($bytes.Length -lt 1) {

      [int] $bytesExtractedNormalizedLen = [Math]::Ceiling(([double] $bytesExtractedNormalized.Length) / 2)
      $bytes = New-Object byte[] $bytesExtractedNormalizedLen
      for ($i = 0; $i -lt $bytesExtractedNormalizedLen; $i ++) {

        [string] $oneByte = $bytesExtractedNormalized.Substring(($i * 2), ([Math]::Min(2, ($bytesExtractedNormalized.Length - ($i * 2)))))
        $bytes[$i] = [int]::Parse($oneByte, ([System.Globalization.NumberStyles]::HexNumber))
      }
    }

    if ($bytes.Length -lt 1) {

      throw ('Invalid bytes array decoded: {0} | {1}' -f $bytesExtracted)
    }

    if ($prefixExtracted -like 'S*') {

      $sidOrGuidOrLogin = (New-Object System.Security.Principal.SecurityIdentifier $bytes, 0).Value

    } elseif ($prefixExtracted -like 'G*') {

      $sidOrGuidOrLogin = ([guid] $bytes).ToString('b')

    } elseif ($prefixExtracted -like 'A*') {

      $sidOrGuidOrLogin = [Text.Encoding]::ASCII.GetString($bytes)

    } elseif ($prefixExtracted -like 'UT*') {

      $sidOrGuidOrLogin = [Text.Encoding]::UTF8.GetString($bytes)

    } elseif ($prefixExtracted -like 'UN*') {

      $sidOrGuidOrLogin = [Text.Encoding]::Unicode.GetString($bytes)
    
    } else {

      throw ('Unrecognized byte array type prefix: {0} | {1}' -f $sidOrGuidOrLogin, $prefixExtracted)
    }
  }

  [string] $sid = $null
  [string] $sidBytes = $null
  [string] $sidBase64 = $null
  [string] $guid = $null
  [string] $guidBytes = $null
  [string] $guidBase64 = $null
  [string] $login = $null

  try {

    if ($sidOrGuidOrLogin -like 'S-1-?*') {

      $sid = $sidOrGuidOrLogin
      $guid = Translate-AADSIDvsGUID -sidOrGuid $sidOrGuidOrLogin
      $login = Translate-SIDtoLogin -sid $sid    
   
    } elseif ($sidOrGuidOrLogin -match $rxGUID) {

      [string] $sidDomain = 'S-1-12-1'
      [string] $sidDomainSupplied = Read-Host ('SID domain (default = {0})' -f $sidDomain)

      if (-not ([string]::IsNullOrEmpty($sidDomainSupplied))) {

        $sidDomain = $sidDomainSupplied.Trim()
      }

      $guid = [guid]::Parse(($sidOrGuidOrLogin -replace '[^0-9a-fA-F]', ''))
      $sid = Translate-AADSIDvsGUID -sidOrGuid $guid -sidDomain $sidDomain
      $login = Translate-SIDtoLogin -sid $sid

    } else {

      $login = $sidOrGuidOrLogin

      if ($login -match '\A\.\\') {

        if ($isDC) {

          $domainDE = [ADSI] ('LDAP://{0}' -f (Get-WmiObject Win32_ComputerSystem | select -Expand Domain))
          [void] $domainDE.RefreshCache('msDS-PrincipalName')
          $login = $login -replace '\A\.\\', $domainDE.Get('msDS-PrincipalName')

        } else {

          $login = $login -replace '\A\.\\', ('{0}\' -f $machineNetBIOS)
        }
      }

      $sid = Translate-LoginToSID -login $login
      $guid = Translate-AADSIDvsGUID -sidOrGuid $sid
      $login = Translate-SIDtoLogin -sid $sid
    }
  
  } catch {

    Write-Host ('')
    Write-Host ('Error: {0}' -f $_) -Fore Red
    $error.Clear()
  }

  if (-not ([string]::IsNullOrEmpty($sid))) {
   
    $sidObj = New-Object Security.Principal.SecurityIdentifier $sid
    $sidByteArray = New-Object byte[] $sidObj.BinaryLength
    [void] $sidObj.GetBinaryForm($sidByteArray, 0)
    $sidBytes = [BitConverter]::ToString($sidByteArray)
    $sidBase64 = [Convert]::ToBase64String($sidByteArray)
  }

  if (-not ([string]::IsNullOrEmpty($guid))) {

    $guidBytes = [BitConverter]::ToString(([guid] $guid).ToByteArray())
    $guidBase64 = [Convert]::ToBase64String(([guid] $guid).ToByteArray())
  }

  Write-Host ('')
  Write-Host ('Machine hostname: {0}' -f $machineHost)
  Write-Host ('Machine NetBIOS:  {0}' -f $machineNetBIOS)
  Write-Host ('')
  Write-Host ('SID:              {0}' -f $sid)
  Write-Host ('SID bytes:        {0}' -f $sidBytes)
  Write-Host ('SID base64:       {0}' -f $sidBase64)
  Write-Host ('')
  Write-Host ('GUID:             {0}' -f $guid)
  Write-Host ('GUID bytes:       {0}' -f $guidBytes)
  Write-Host ('GUID base64:      {0}' -f $guidBase64)
  Write-Host ('')
  Write-Host ('Login:            {0}' -f $login)

  ##
  ##

  $success = $true  

} catch {

  Write-Host ('')
  Write-Host ('Error: {0}' -f $_) -Fore Red
}

if ($success) {

  Write-Host ('')
  Write-Host ('Finished SUCCESS')

} else {

  Write-Host ('')
  Write-Host ('Finished ERROR')
}

if ([object]::Equals($psISE, $null)) { 

  Write-Host ('')
  Read-Host ('Press ENTER to exit')
}


# SIG # Begin signature block
# MIIfKwYJKoZIhvcNAQcCoIIfHDCCHxgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAYcLUl1NAZ2IZP
# 7aWCPud2iOh3N03NNiOmKaAFBcwje6CCGTEwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# /JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBsIwggSqoAMC
# AQICEAVEr/OUnQg5pr/bP1/lYRYwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBU
# cnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMzA3
# MTQwMDAwMDBaFw0zNDEwMTMyMzU5NTlaMEgxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjEgMB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0YW1wIDIw
# MjMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCjU0WHHYOOW6w+VLMj
# 4M+f1+XS512hDgncL0ijl3o7Kpxn3GIVWMGpkxGnzaqyat0QKYoeYmNp01icNXG/
# OpfrlFCPHCDqx5o7L5Zm42nnaf5bw9YrIBzBl5S0pVCB8s/LB6YwaMqDQtr8fwkk
# lKSCGtpqutg7yl3eGRiF+0XqDWFsnf5xXsQGmjzwxS55DxtmUuPI1j5f2kPThPXQ
# x/ZILV5FdZZ1/t0QoRuDwbjmUpW1R9d4KTlr4HhZl+NEK0rVlc7vCBfqgmRN/yPj
# yobutKQhZHDr1eWg2mOzLukF7qr2JPUdvJscsrdf3/Dudn0xmWVHVZ1KJC+sK5e+
# n+T9e3M+Mu5SNPvUu+vUoCw0m+PebmQZBzcBkQ8ctVHNqkxmg4hoYru8QRt4GW3k
# 2Q/gWEH72LEs4VGvtK0VBhTqYggT02kefGRNnQ/fztFejKqrUBXJs8q818Q7aESj
# pTtC/XN97t0K/3k0EH6mXApYTAA+hWl1x4Nk1nXNjxJ2VqUk+tfEayG66B80mC86
# 6msBsPf7Kobse1I4qZgJoXGybHGvPrhvltXhEBP+YUcKjP7wtsfVx95sJPC/QoLK
# oHE9nJKTBLRpcCcNT7e1NtHJXwikcKPsCvERLmTgyyIryvEoEyFJUX4GZtM7vvrr
# kTjYUQfKlLfiUKHzOtOKg8tAewIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQDAgeA
# MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkw
# FzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaa
# L3WMaiCPnshvMB0GA1UdDgQWBBSltu8T5+/N0GSh1VapZTGj3tXjSTBaBgNVHR8E
# UzBRME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcB
# AQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMFgG
# CCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3
# DQEBCwUAA4ICAQCBGtbeoKm1mBe8cI1PijxonNgl/8ss5M3qXSKS7IwiAqm4z4Co
# 2efjxe0mgopxLxjdTrbebNfhYJwr7e09SI64a7p8Xb3CYTdoSXej65CqEtcnhfOO
# HpLawkA4n13IoC4leCWdKgV6hCmYtld5j9smViuw86e9NwzYmHZPVrlSwradOKmB
# 521BXIxp0bkrxMZ7z5z6eOKTGnaiaXXTUOREEr4gDZ6pRND45Ul3CFohxbTPmJUa
# VLq5vMFpGbrPFvKDNzRusEEm3d5al08zjdSNd311RaGlWCZqA0Xe2VC1UIyvVr1M
# xeFGxSjTredDAHDezJieGYkD6tSRN+9NUvPJYCHEVkft2hFLjDLDiOZY4rbbPvlf
# sELWj+MXkdGqwFXjhr+sJyxB0JozSqg21Llyln6XeThIX8rC3D0y33XWNmdaifj2
# p8flTzU8AL2+nCpseQHc2kTmOt44OwdeOVj0fHMxVaCAEcsUDH6uvP6k63llqmjW
# Iso765qCNVcoFstp8jKastLYOrixRoZruhf9xHdsFWyuq69zOuhJRrfVf8y2OMDY
# 7Bz1tqG4QyzfTkx9HmhwwHcK1ALgXGC7KP845VJa1qwXIiNO9OzTF/tQa/8Hdx9x
# l0RBybhG02wyfFgvZ0dl5Rtztpn5aywGRu9BHvDwX+Db2a2QgESvgBBBijGCBVAw
# ggVMAgEBMHowbDELMAkGA1UEBhMCQ1oxFzAVBgNVBAgTDkN6ZWNoIFJlcHVibGlj
# MQ0wCwYDVQQHEwRCcm5vMRAwDgYDVQQKEwdTZXZlY2VrMSMwIQYDVQQDExpTZXZl
# Y2VrIEVudGVycHJpc2UgUm9vdCBDQQIKFbjelwABAAANHzANBglghkgBZQMEAgEF
# AKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgor
# BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3
# DQEJBDEiBCCcsRpz5ypquFic44cmWaaUwzQwPtuML6bc3Kt+CprTdzANBgkqhkiG
# 9w0BAQEFAASCAQBYCDX77/tq/q5evPISMBfzHJy5qKaXVUe53+vj753vyDSeB5DK
# DNP9fQiEkMrcMept8mInAK71WcOYbSzbcvKYwLIT2ic8X+wxoah1rdQ5XcvpfAqg
# saWGqgyf+v0478RoXpDHHxl8ns9sUcfhjkZPpCamuyuFhqfqK5bsF0qpzsm1Q7ZT
# xOtEZj47k8B9gtGdmTWmNCHq+4TPO/nLW8Il+m56O7UY/+SKsE2BdZFFXL9w5MBk
# S0QoLnDWHAoRGR3/gB3QBA6dxddX7FiAWSDuVF8M0+MZ9QmApcTATbCQfGlg1hir
# ZlPjOETBgOA99FLzkavcPkPScR4EI8IFTD7eoYIDIDCCAxwGCSqGSIb3DQEJBjGC
# Aw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQQIQBUSv85SdCDmmv9s/X+VhFjANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI0
# MDkyMzExMzUwNlowLwYJKoZIhvcNAQkEMSIEIKJ+Q1LOgUsHG9ShuFTA2oB9Ob6h
# gNXe1UDB5nVoBnIwMA0GCSqGSIb3DQEBAQUABIICAAiDNk/dmp8JpI8zOSpeyWM+
# dX7fnmoUwSKc9dZHDZzUxjPCpoPQchqvnlfiNaLpmSaxfF1OOnyxyyYCP2Gfx3ht
# FDoUIw+6BsE6PYQdI4+LJNBJjimW+wCEpfc2DwVnKqaeQFpzVOeHulkyeV0BNgk2
# YZjNwizNZ5WADUvudvIdYu1w0MAMXz1x4P9CAk4f/UFZx4Sijno7nVAv/c3D4bbf
# Ezp808tsve0U2K8q2G3jUb/CWmP92PRVjX7BXYYAMY+LGBcMfpU3iHqFSV9sPGm3
# yjxsPnud+SQCEDDRRsLrdeFvZ1D2mehx/hrWqdouKCdXT0lNRaaSCTRcBZWvrU9g
# Kk3bbXGo6sRmZDsgTVYi7aiwDCnI03FaT7r4FLBaSGxjC2puB3DDcI779Mqmie34
# 7ioh3c2IK30YFO+EC4lLy1tyttZWBw4SWE850BK1k77Cu0hgQBmIhQ9S9hgUi6Vx
# HW/6RzHO2Yhn1BRQLsVA3qNDuCh23kn7h4x4s+DuEpomnO9t27HJVa6X2fQRYJG2
# K0bey49BsAqHrlOf6Pd8q15morqbdSrGvSvAHIW7X9CW4wHm0D3BPMd1Qtgg8bGj
# 74Ke36G51v/LdDqIfUGNBF8XdjBCoTNUyT6bTuvE23u+RaaVEUtcR93f1D/E4CR5
# 83aWP92ngAxaerJJPhmx
# SIG # End signature block

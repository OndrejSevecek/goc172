
param(
  [switch] $auto,
  [string] $tenantDomain,
  [string[]] $others
  )

$global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

##
##

[string] $discontinuedHostName = 'discontinued'
[hashtable] $hostnames = @{

    'login.microsoftonline.com' = 'AAD/EntraID'
    'aadcdn.msauth.net' = 'AAD/EntraID'
    'login.windows.net' = 'AAD/EntraID'
    'login.live.com' = 'AAD/EntraID'
    'enterpriseregistration.{0}' = 'AAD/EntraID'
    'enterpriseregistration.windows.net' = 'AAD/EntraID'
    'graph.microsoft.com' = 'AAD/EntraID'

    'provisioningapi.microsoftonline.com' = 'MSOnline module'

    'aad.cs.dds.microsoft.com' = 'Autopilot Service'
    'cs.dds.microsoft.com' = 'Autopilot Service'
    'ztd.dds.microsoft.com' = 'Autopilot Service'

    'enterpriseenrollment.{0}' = 'Intune'
    'enterpriseenrollment-s.manage.microsoft.com' = 'Intune'
    'enrollment.manage.microsoft.com' = 'Intune'
    'portal.manage.microsoft.com' = 'Intune'
    'r.manage.microsoft.com' = 'Intune'
    'checkin.dm.microsoft.com' = 'Intune'
    
    'client.wns.windows.com' = 'Push Notification Service'

    'wip.mam.manage.microsoft.com' = $discontinuedHostName
  }

[hashtable] $otherHostnames = @{

  'Install-Module and Install-PackageProvider' = @('cdn.oneget.org', 'onegetcdn.azureedge.net', 'www.powershellgallery.com', 'cdn.powershellgallery.com')
  }

##
##

function global:Save-Cert ([System.Security.Cryptography.X509Certificates.X509Certificate2] $cert, [string] $folderToSave, [string] $fileNameOptional, [string] $fileNamePrefixOptional)
{
  if ([string]::IsNullOrEmpty($fileNameOptional)) {

    $rxCN = '(?i)CN\s*=\s*((?:\\\,|[^\,])+)(?:\Z|\,)'
    $fileNameOptional = '{0}.cer' -f ([regex]::Match($cert.Subject, $rxCN).Groups[1].Value -replace '[\W_-[\s]]', '_')
  }

  if (-not ([string]::IsNullOrEmpty($fileNamePrefixOptional))) {

    $fileNameOptional = '{0}-{1}' -f $fileNamePrefixOptional, $fileNameOptional
  }

  [string] $certBase64 = @'
-----BEGIN CERTIFICATE-----
{0}
-----END CERTIFICATE-----
'@ -f ([Convert]::ToBase64String($cert.Export(([Security.Cryptography.X509Certificates.X509ContentType]::Cert)), ([System.Base64FormattingOptions]::InsertLineBreaks)))
 
  [string] $saveCertFile = Join-Path $folderToSave $fileNameOptional
  [IO.File]::WriteAllText($saveCertFile, $certBase64)
}

function global:Touch-TLS ([string] $hostname, [string] $certFolder)
{
  [System.Net.Sockets.TcpClient] $tcpClient = $null
  [System.Net.Security.SslStream] $sslStream = $null

  try {

   [System.Net.Security.RemoteCertificateValidationCallback] $certValidationDelegate = [System.Net.Security.RemoteCertificateValidationCallback] {

param(
       $sender, 
       [System.Security.Cryptography.X509Certificates.X509Certificate2] $certificate, 
       $chain, 
       [System.Net.Security.SslPolicyErrors] $sslPolicyErrors
     )
                                                                                               
  if ($sslPolicyErrors -ne ([System.Net.Security.SslPolicyErrors]::None)) {

    if ($sslPolicyErrors -ne ([System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch)) {

      Write-Host ('Cert: {0}' -f $sslPolicyErrors) -Fore Red

    } else {

      [string] $certCN = ([regex]::Match($certificate.SubjectName.Name, '(?<=\A|\s|,)CN\s*=((?:(?:\\,)|[^,])+)(?:,|\Z)', [Text.RegularExpressions.RegexOptions]::IgnoreCase)).Groups[1].Value
      [Collections.ArrayList] $certDNSs = @($certCN)

      if ($certificate.DnsNameList.Count -gt 0) { foreach ($oneDNSName in $certificate.DnsNameList) {

        [string] $dnsName = $oneDNSName.ToString()

        if ($certDNSs -notcontains $dnsName) {

          [void] $certDNSs.Add($dnsName)
        }
      }}

      Write-Host ('Cert: {0} | {1}' -f $sslPolicyErrors, ($certDNSs -join ', ')) -Fore Red
    }
  }

  return $true
}

    $tcpRetransmitSec = 3 + 6 + 12 + 24 + 48

    Write-Host ('HTTPS: {0}' -f $hostname)
    [System.Net.Sockets.TcpClient] $tcpClient = New-Object System.Net.Sockets.TcpClient($hostname, 443)

    $tcpClient.SendTimeout = 1000 * $tcpRetransmitSec
    $tcpClient.ReceiveTimeout = 1000 * $tcpRetransmitSec

    Write-Host ('Server: {0}' -f ([System.Net.IPEndPoint] $tcpClient.Client.RemoteEndPoint).Address)
    [System.Net.Security.SslStream] $sslStream = New-Object System.Net.Security.SslStream ($tcpClient.GetStream(), $true, $certValidationDelegate)
    
    $sslStream.ReadTimeout = 1000 * $tcpRetransmitSec
    $sslStream.WriteTimeout = 1000 * $tcpRetransmitSec

    try {

      [void] $sslStream.AuthenticateAsClient($hostname, (New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection), ([System.Security.Authentication.SslProtocols]::None), $true)

    } catch {

      # Note: on older systems the ::None does not work well
      [void] $sslStream.AuthenticateAsClient($hostname, (New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection), ([System.Security.Authentication.SslProtocols]::Tls12), $true)
      $error.Clear()
    }
    
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $tlsCert = $null
    $tlsCert = $sslStream.RemoteCertificate
    Save-Cert -cert $tlsCert -folderToSave $certFolder -fileNamePrefixOptional ('{0}-{1}-{2}' -f $hostname, $port, $tlsCert.Thumbprint)

  } catch {

    Write-Host ('Error: {0}' -f $_) -Fore Red

  } finally {

    if (-not ([object]::Equals($sslStream, $null))) {

      [void] $sslStream.Close()
      [void] $sslStream.Dispose()
    }

    if (-not ([object]::Equals($tcpClient, $null))) {

      [void] $tcpClient.Close()
      [void] $tcpClient.Dispose()
    }
  }
}

##
##

try {

  [string] $defaultDummyTenantDomain = 'sevecekeu.onmicrosoft.com'

  if ([string]::IsNullOrEmpty($tenantDomain)) {

    $tenantDomain = $defaultDummyTenantDomain
  }

  [string] $tenantAlready = $null
  $tenantAlready = @('HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo', 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo') | % { 
                     try { Get-ChildItem $_ -ErrorAction SilentlyContinue | % { Get-ItemProperty -PSPath $_.PSPath -Name UserEmail | select -Expand UserEmail } } catch { $error.Clear() }
                   } | ? { (-not ([string]::IsNullOrEmpty($_))) -and ($_ -like '?*@?*') } | % { $_.Trim() } | select -First 1

  if (-not ([string]::IsNullOrEmpty($tenantAlready))) {

    $tenantDomain = $tenantAlready
  }

  [string] $aadConnectConfig = Join-Path $env:ProgramData AADConnect\PersistedState.xml
  [string] $aadConnectAdmin = $null

  if (Test-Path $aadConnectConfig) {

    [XML] $aadConfigXml = [XML] (cat $aadConnectConfig)
    try { $aadConnectAdmin = $aadConfigXml.SelectSingleNode('/PersistedStateContainer/Elements/PersistedStateElement[Key = "IAzureActiveDirectoryContext.AzureADUsername"]/Value').InnerText } catch { $error.Clear() }
  }

  if (-not ([string]::IsNullOrEmpty($aadConnectAdmin))) {

    $tenantDomain = $aadConnectAdmin
  }

  ##
  ##

  if (-not $auto) {

    Write-Host ('')
    [string] $tenantDomainSupplied = Read-Host ('Optional tenant domain or login (default = {0})' -f $tenantDomain)

    if (-not ([string]::IsNullOrEmpty($tenantDomainSupplied))) {

      $tenantDomain = $tenantDomainSupplied.Trim()
    }
  }

  if ($tenantDomain -eq $defaultDummyTenantDomain) {

    $tenantDomain = $null
  }

  $tenantDomain = $tenantDomain -replace '\A.*\@', ''
  $tenantDomain = $tenantDomain -replace '\s', ''
  
  if (-not ([string]::IsNullOrEmpty($tenantDomain))) {

    Write-Host ('Tenant domain normalized: {0}' -f $tenantDomain)
  
  } else {

    Write-Host ('No tenant domain specified. Proceeding with generic domains only')
  }

  ##
  ##

  [string] $certOutFolder = Join-Path $env:SystemDrive TEMP\Certs-Azure #$env:TEMP

  if (-not $auto) {

    Write-Host ('')
    [string] $certOutFolderSupplied = Read-Host ('Folder to save HTTPS/TLS certificates (default = {0})' -f $certOutFolder)

    if (-not ([string]::IsNullOrEmpty($certOutFolderSupplied))) {

      $certOutFolder = $certOutFolderSupplied.Trim()
    }
  }

  if (-not (Test-Path $certOutFolder)) {

    Write-Host ('')
    Write-Host ('Create folder: {0}' -f $certOutFolder)
    New-Item $certOutFolder -ItemType Directory -Force | Out-Null
  }

  ##
  ##

  if ($others.Length -gt 0) { foreach ($oneOther in $others) {

    if ($otherHostnames[$oneOther].Count -gt 0) { foreach ($oneOtherHostname in $otherHostnames[$oneOther]) {

      if ($hostnames.Keys -notcontains $oneOtherHostname) {

        [void] $hostnames.Add($oneOtherHostname, $oneOther)
      }
    }}
  }}

  ##
  ##

  [bool] $continueStill = $false
  [int] $runCount = 0
  do {

    ##
    ##

    Write-Host ('')
    Write-Host ('Clear DNS client cache')
    Clear-DnsClientCache

    Write-Host ('')

    [hashtable] $hostnamesByCategories = @{}
    if ($hostnames.Count -gt 0) { foreach ($oneHostname in $hostnames.Keys) {

      if ($hostnamesByCategories.Keys -contains $hostnames[$oneHostname]) {

        [void] $hostnamesByCategories[$hostnames[$oneHostname]].Add($oneHostname)

      } else {

        [void] $hostnamesByCategories.Add($hostnames[$oneHostname], ([Collections.ArrayList] @($oneHostname)))
      }
    }}
  
    if ($hostnamesByCategories.Count -gt 0) { foreach ($oneCategory in ($hostnamesByCategories.Keys | sort)) {

      if ($hostnamesByCategories[$oneCategory].Count -gt 0) { foreach ($oneHostname in $hostnamesByCategories[$oneCategory]) {

        [string] $resolve = $oneHostname

        if ($resolve.Contains('{')) {

          if (-not ([string]::IsNullOrEmpty($tenantDomain))) {

            $resolve = $resolve -f $tenantDomain
          
          } else {

            $resolve = $null
          }
        }

        if (-not ([string]::IsNullOrEmpty($resolve))) {

          [bool] $shouldNotResolve = $oneCategory -eq $discontinuedHostName
          Write-Host ('Resolve: {0} | {1}' -f $oneCategory, $resolve)
    
          [DateTime] $dtStart = Get-Date
          [DateTime] $dtStartTLS = [DateTime]::MinValue
          [object[]] $result = $null
          try {
  
            $result = Resolve-DnsName -Name $resolve -DnsOnly -NoHostsFile
            
            $dtStartTLS = Get-Date
            Touch-TLS -hostname $resolve -certFolder $certOutFolder

          } catch {

            $failure = $_

            if (-not $shouldNotResolve) {

              Write-Host ('Error: {0}' -f $failure) -Fore Red
            }
          }

          if ($shouldNotResolve -and (-not ([object]::Equals($result, $null)))) {
 
            Write-Host ('Error: discontinued host name was resolved | {0}' -f $resolve) -Fore Red
          }
        
          [DateTime] $dtEnd = Get-Date
          [int] $tookSec = ($dtEnd - $dtStart).TotalSeconds

          if ($tookSec -gt 3) {

            if ($dtStartTLS -gt ([DateTime]::MinValue)) {

              [int] $tookDNS = ($dtStartTLS - $dtStart).TotalSeconds
              [int] $tookTLS = ($dtEnd - $dtStartTLS).TotalSeconds

              Write-Host ('Took: dns = {0} sec | tls = {1} sec | overall = {2} sec' -f $tookDNS, $tookTLS,$tookSec) -Fore Red

            } else {

              Write-Host ('Took: overall = {0}' -f $tookSec) -Fore Red
            }
          }

          [bool] $gotIPv4 = $false
          if ($result.Length -gt 0) { foreach ($oneResult in $result) {

            if ($oneResult.IPAddress -match '\A\d+\.\d+\.\d+\.\d+\Z') { 

              $gotIPv4 = $true
            }
          }}

          if ((-not $shouldNotResolve) -and (-not $gotIPv4)) {
      
            Write-Host ('Error: no IPv4 address resolved') -Fore Red
          }
        }
      }}
    }}

    ##
    ##

    $runCount ++

    if ($runCount -eq 1) {

      if (-not $auto) {

        Write-Host ('')
        [string] $continueStillSupplied = Read-Host ('Do you want to reapeat indefinitelly (default = {0}) [yes/y/true/t/1/no/n/false/f/0]' -f $continueStill)

        if (-not ([string]::IsNullOrEmpty($continueStillSupplied))) {

          $continueStill = @('yes', 'y', 'true', 't', '1') -contains $continueStillSupplied.Trim()
        }
      }
    
    } else {

      [int] $sleepSec = 7
      Write-Host ('')
      Write-Host ('Relax for some time: {0} sec' -f $sleepSec)
      Start-Sleep -Seconds $sleepSec
    }

  } while ($continueStill)

  ##
  ##

} catch {

  Write-Host ('')
  Write-Host ('Error: {0}' -f $_) -Fore Red
}

if ((-not $auto) -and ([object]::Equals($psISE, $null))) {

  Write-Host ('')
  Read-Host ('Press ENTER to exit') | Out-Null
}


# SIG # Begin signature block
# MIIfYgYJKoZIhvcNAQcCoIIfUzCCH08CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCAxkXX6Jx6r3az
# 8aJ+O3UtwHgzZ4OufJW4vLN8m6qnvqCCGWIwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# 5w9HMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsF
# ADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
# ExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJv
# b3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx1
# 26NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY
# 3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kY
# p77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8
# eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4i
# vbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4
# hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eu
# m5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbW
# Bqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7Ln
# LqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS
# 4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjl
# roPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8C
# AQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX
# 44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggr
# BgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
# LmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDag
# NIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RH
# NC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3
# DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do
# 7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448r
# SYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3
# nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU1
# 6r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOL
# h0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61E
# d2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWq
# AXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYR
# kA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgo
# iovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90
# G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBu0w
# ggTVoAMCAQICEAqA7xhLjfEFgtHEdqeVdGgwDQYJKoZIhvcNAQELBQAwaTELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdp
# Q2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1
# IENBMTAeFw0yNTA2MDQwMDAwMDBaFw0zNjA5MDMyMzU5NTlaMGMxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQg
# U0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI1IDEwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDQRqwtEsae0OquYFazK1e6b1H/hnAK
# Ad/KN8wZQjBjMqiZ3xTWcfsLwOvRxUwXcGx8AUjni6bz52fGTfr6PHRNv6T7zsf1
# Y/E3IU8kgNkeECqVQ+3bzWYesFtkepErvUSbf+EIYLkrLKd6qJnuzK8Vcn0DvbDM
# emQFoxQ2Dsw4vEjoT1FpS54dNApZfKY61HAldytxNM89PZXUP/5wWWURK+IfxiOg
# 8W9lKMqzdIo7VA1R0V3Zp3DjjANwqAf4lEkTlCDQ0/fKJLKLkzGBTpx6EYevvOi7
# XOc4zyh1uSqgr6UnbksIcFJqLbkIXIPbcNmA98Oskkkrvt6lPAw/p4oDSRZreiwB
# 7x9ykrjS6GS3NR39iTTFS+ENTqW8m6THuOmHHjQNC3zbJ6nJ6SXiLSvw4Smz8U07
# hqF+8CTXaETkVWz0dVVZw7knh1WZXOLHgDvundrAtuvz0D3T+dYaNcwafsVCGZKU
# hQPL1naFKBy1p6llN3QgshRta6Eq4B40h5avMcpi54wm0i2ePZD5pPIssoszQyF4
# //3DoK2O65Uck5Wggn8O2klETsJ7u8xEehGifgJYi+6I03UuT1j7FnrqVrOzaQoV
# JOeeStPeldYRNMmSF3voIgMFtNGh86w3ISHNm0IaadCKCkUe2LnwJKa8TIlwCUNV
# wppwn4D3/Pt5pwIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU
# 5Dv88jHt/f3X85FxYxlQQ89hjOgwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQVvYv
# 1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIGV
# BggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNB
# MS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVD
# QTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG
# 9w0BAQsFAAOCAgEAZSqt8RwnBLmuYEHs0QhEnmNAciH45PYiT9s1i6UKtW+FERp8
# FgXRGQ/YAavXzWjZhY+hIfP2JkQ38U+wtJPBVBajYfrbIYG+Dui4I4PCvHpQuPqF
# gqp1PzC/ZRX4pvP/ciZmUnthfAEP1HShTrY+2DE5qjzvZs7JIIgt0GCFD9ktx0Lx
# xtRQ7vllKluHWiKk6FxRPyUPxAAYH2Vy1lNM4kzekd8oEARzFAWgeW3az2xejEWL
# NN4eKGxDJ8WDl/FQUSntbjZ80FU3i54tpx5F/0Kr15zW/mJAxZMVBrTE2oi0fcI8
# VMbtoRAmaaslNXdCG1+lqvP4FbrQ6IwSBXkZagHLhFU9HCrG/syTRLLhAezu/3Lr
# 00GrJzPQFnCEH1Y58678IgmfORBPC1JKkYaEt2OdDh4GmO0/5cHelAK2/gTlQJIN
# qDr6JfwyYHXSd+V08X1JUPvB4ILfJdmL+66Gp3CSBXG6IwXMZUXBhtCyIaehr0Xk
# BoDIGMUG1dUtwq1qmcwbdUfcSYCn+OwncVUXf53VJUNOaMWMts0VlRYxe5nK+At+
# DI96HAlXHAL5SlfYxJ7La54i71McVWRP66bW+yERNpbJCjyCYG2j+bdpxo/1Cy4u
# PcU3AWVPGrbn5PhDBf3Froguzzhk++ami+r3Qrx5bIbY3TVzgiFI7Gq3zWcxggVW
# MIIFUgIBATB6MGwxCzAJBgNVBAYTAkNaMRcwFQYDVQQIEw5DemVjaCBSZXB1Ymxp
# YzENMAsGA1UEBxMEQnJubzEQMA4GA1UEChMHU2V2ZWNlazEjMCEGA1UEAxMaU2V2
# ZWNlayBFbnRlcnByaXNlIFJvb3QgQ0ECChW43pcAAQAADR8wDQYJYIZIAWUDBAIB
# BQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG
# 9w0BCQQxIgQg0dx7hczzXjctAYUPO8RwluFQoDK7niMH+WsRzt3rQ2AwDQYJKoZI
# hvcNAQEBBQAEggEAliDkHlUi8Gon/UZALbykJNRG5ZVUFYJhKxFpw23xx0iEuy1O
# Isf7am1Vuf6Hy1Xr44z3hAOTIy/P4m9nGbsBBBnxnH4tft9L1V+rvuZxe8P7YAB3
# /memxvJ+kPBYojE6q8DO14IocXxQkMBju5tXSfuBbHDlh2uuoFbQZOcLa8sOWMY9
# WEcAmgqWG8gpdDESuk0g33tky1OLM9jOEj6eExqrOQIUthuhYrVQ0e+Ipam8xYha
# HYB/SDPtYoJL25MyzFLVsKEPqJwHcpj+Yq25/3wu3lPNMyeh2/KbNtElSFKTCT01
# s0X+KZlHpg3cebKuGQ1ZxW6OGP5GHUINaCaHC6GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMjYxNjE2NDlaMC8GCSqGSIb3DQEJBDEiBCCE5qf71ZvdfcxlwOyQ
# cTEwyj5+84eDHUJ5z1s+5PxZkzANBgkqhkiG9w0BAQEFAASCAgAqju/GPEUDuclN
# sAkT7m2bDSadjqYDspBQPy2wAZo0LGmEiqh+xfBTkbseu0bZhPONhoX4QTGDjpi9
# vBLE9DyYnbmmVhzyENQVPgRvzHMmHIDuJd69lRE3lkH0PJZr1z6KalEf3CGWuNAu
# /6KzJKGxOWVT2LY2N1VwAOv8/zv3MVFehq9MO92SLuWRC7p1p6M0mLI6HJJd+j2C
# 8T/w4yxQ1Gz7cIU1TIaoN4RLg7fV8is7vjp0oRTAcQKgMrErstzYnb5S7exuMYjQ
# OVJhujcZGpQviBzv9CkF7VzNvMu/fizRVESx5OHXeRFhcSdFswq8h3HlVOCBD4UE
# 4h4lVdSoKUfXG4w81s4eJD18xDNYRXmPwDzwXSGp/SSszgR60ZztpO6Ecr427d9j
# fh1crDaBvYZlra2hmfySuJSyeyBLfa+tY19u+fch8Q++82MIzfeDSbFKVTEmsCij
# wKHgiBNyoPDNDlEk/VLrU/g+o2QCAueMcLUzslK42lczI5Ziw1vnsmNWKdhaKIWN
# tdorocwBuPD96UjPqbj7x9n9RuoiEfKH4u3bh8Tfa5h06lJtl+tVmLpGj5BSACfd
# gaSjWrXyJ9gLRYbPgIMW1thi/Uy5zDQ3Q2CQe5Z0kArxaXGVCjfdwv9AG4GSseun
# /BaDaTCqnYoYUxQzyTJCCZO4NFafvw==
# SIG # End signature block


$global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

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
  Write-Host ('')
  Write-Host ('Saving: {0} | {1}' -f $cert.Thumbprint, $saveCertFile)
  [IO.File]::WriteAllText($saveCertFile, $certBase64)
}

##
##

try {

   $hostname = 'wfe2k12r2-rdp'
   $port = 3389
   $folder = 'C:\TEMP'
   
   $tlsVersion = 'None'

   if (([Version] $PSVersionTable.PSVersion) -le ([Version] '2.0')) {

     $tlsVersion = 'Default'
   }

   ##
   ##

   Write-Host ('')

   [string] $hostnameSupplied = Read-Host ('Hostname (default = {0})' -f $hostname)
   
   if (-not ([string]::IsNullOrEmpty($hostnameSupplied))) {

     $hostname = $hostnameSupplied.Trim()
   }
   
   [string] $portSupplied = Read-Host ('Port (default = {0})' -f $port)

   if (-not ([string]::IsNullOrEmpty($portSupplied))) {

     $port = $portSupplied
   }

   [string] $folderSupplied = Read-Host ('Folder to save the certificate (default = {0})' -f $folder)

   if (-not ([string]::IsNullOrEmpty($folderSupplied))) {

     $folder = $folderSupplied
   }

   [string] $tlsVersionSupplied = Read-Host ('TLS version [default=ssl3+tls10/none=default/ssl2/ssl3/tls/tls10/10/1.0/tls11/11/1.1/tls12/12/1.2/tls13/13/1.3] (default = {0})' -f $tlsVersion)

   if (-not ([string]::IsNullOrEmpty($tlsVersionSupplied))) {

     $tlsVersionSupplied = $tlsVersionSupplied.Trim()

     if (@('default')                                    -contains $tlsVersionSupplied) { $tlsVersion = 'default' }
     if (@('none')                                       -contains $tlsVersionSupplied) { $tlsVersion = 'none' }
     if (@('ssl2')                                       -contains $tlsVersionSupplied) { $tlsVersion = 'ssl3' }
     if (@('ssl3')                                       -contains $tlsVersionSupplied) { $tlsVersion = 'ssl3' }
     if (@(       'tls', 'tls10', 'tls1.0', '10', '1.0') -contains $tlsVersionSupplied) { $tlsVersion = 'tls' }
     if (@(              'tls11', 'tls1.1', '11', '1.1') -contains $tlsVersionSupplied) { $tlsVersion = 'tls11' }
     if (@(              'tls12', 'tls1.2', '12', '1.2') -contains $tlsVersionSupplied) { $tlsVersion = 'tls12' }
     if (@(              'tls13', 'tls1.3', '13', '1.3') -contains $tlsVersionSupplied) { $tlsVersion = 'tls13' }
   }

   [bool] $checkRevocation = $true
   [string] $checkRevocationSupplied = Read-Host ('Check revocation (default = {0}) [yes/y/true/t/1/no/n/false/f/0]' -f $checkRevocation)

   if (-not ([string]::IsNullOrEmpty($checkRevocationSupplied))) {

     $checkRevocation = @('yes', 'y', 'true', 't', '1') -contains $checkRevocationSupplied.Trim()
   }

   ##
   ##

   Write-Host ('')
   Write-Host ('TCP SYN/SYN-ACK/SYN sequence: {0}:{1}' -f $hostname, $port)

   [System.Net.Sockets.TcpClient] $tcpClient = New-Object System.Net.Sockets.TcpClient($hostname, $port)

   ##
   ##

   [System.Net.Security.RemoteCertificateValidationCallback] $certValidationDelegate = [System.Net.Security.RemoteCertificateValidationCallback] {

param(
       $sender, 
       [System.Security.Cryptography.X509Certificates.X509Certificate2] $certificate, 
       [System.Security.Cryptography.X509Certificates.X509Chain] $chain, 
       [System.Net.Security.SslPolicyErrors] $sslPolicyErrors
     )
                                                                                               
  Write-Host ('')
  Write-Host ('Cert validation: {0}' -f $certificate.Thumbprint)
  Write-Host ('Cert validation: subject = {0}' -f $certificate.Subject)
  Write-Host ('Cert validation: issuer  = {0}' -f $certificate.Issuer)
  Write-Host ('Cert validation: expires = {0}' -f $certificate.NotAfter.ToString('yyyy-MM-dd'))
  
  if ($chain.ChainElements.Count -gt 1) {

    for ($i = 1; $i -lt $chain.ChainElements.Count; $i ++) {

      Write-Host ('Cert issuer: {0} | {1}' -f $chain.ChainElements[$i].Certificate.Thumbprint, $chain.ChainElements[$i].Certificate.Subject)
    }
  }
  
  if ($sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None) {

    Write-Host ('Cert validation: error   = {0}' -f $sslPolicyErrors)

  } else {

    Write-Host ('Cert validation: error   = {0}' -f $sslPolicyErrors) -ForegroundColor Red

    if ($chain.ChainStatus.Count -gt 0) { foreach ($oneChainStatus in $chain.ChainStatus) {

      Write-Host ('                           {0}' -f $oneChainStatus.Status) -ForegroundColor Red
    }}
  }

  return $true
}

   [System.Net.Security.SslStream] $sslStream = New-Object System.Net.Security.SslStream ($tcpClient.GetStream(), $true, $certValidationDelegate)

   [System.Security.Authentication.SslProtocols] $tlsVersionTyped = [System.Security.Authentication.SslProtocols] $tlsVersion
   Write-Host ('Start TLS: {0} | checkRevocation = {1} | tls = {2}' -f $hostname, $checkRevocation, $tlsVersionTyped)
   [void] $sslStream.AuthenticateAsClient($hostname, (New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection), $tlsVersionTyped, $checkRevocation)

   Write-Host ('')
   Write-Host ('Server conn: isEncrypted             = {0}' -f $sslStream.IsEncrypted)
   Write-Host ('Server conn: isSigned                = {0}' -f $sslStream.IsSigned)
   Write-Host ('Server conn: isMutuallyAuthenticated = {0}' -f $sslStream.IsMutuallyAuthenticated)
   Write-Host ('Server conn: exchangeAlgo            = {0}' -f $sslStream.KeyExchangeAlgorithm)
   Write-Host ('Server conn: exchangeStrength        = {0}' -f $sslStream.KeyExchangeStrength)
   Write-Host ('Server conn: cipherAlgo              = {0}' -f $sslStream.CipherAlgorithm)
   Write-Host ('Server conn: cipherStrength          = {0}' -f $sslStream.CipherStrength)
   Write-Host ('Server conn: signingAlgo             = {0}' -f $sslStream.HashAlgorithm)
   Write-Host ('Server conn: signingStrength         = {0}' -f $sslStream.HashStrength)

   [System.Security.Cryptography.X509Certificates.X509Certificate2] $tlsCert = $null
   $tlsCert = $sslStream.RemoteCertificate

   if ([string]::IsNullOrEmpty($tlsCert)) {

     throw ('No server certificate obtained from the server connection')
   }

   Write-Host ('')
   Write-Host ('Server cert: {0}' -f $tlsCert.Thumbprint)
   Write-Host ('Server cert: subject = {0}' -f $tlsCert.Subject)
   Write-Host ('Server cert: issuer  = {0}' -f $tlsCert.Issuer)
   Write-Host ('Server cert: expires = {0}' -f $tlsCert.NotAfter.ToString('yyyy-MM-dd'))

   Save-Cert -cert $tlsCert -folderToSave $folder -fileNamePrefixOptional ('{0}-{1}' -f $hostname, $port)

} catch {

  Write-Host ('')
  Write-Host ('Error: {0}' -f $_) -ForegroundColor Red
}


if ([object]::Equals($null, $psISE)) {

  Write-Host ('')
  Read-Host ('Press ENTER to exit')
}


# SIG # Begin signature block
# MIIfYgYJKoZIhvcNAQcCoIIfUzCCH08CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDo+23CXs88S/I2
# XxQ+pmh+fK4emlmartqbL/QFRY9x3aCCGWIwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# 9w0BCQQxIgQgQeliP7BZj01Wm8MpRS4yjWn4HwLhYBcBeidZNcNlPmUwDQYJKoZI
# hvcNAQEBBQAEggEAZXW55e+bfkEUPvRYkVYwPVApFKjW4KT/uxjupg2/gWENf4PI
# oFnkjRwbdhUYc8H7+Y+/hrWOh0M2Y7GUQI3PQpWsZ2KcqNwmojZpXVB4FfjCc/T2
# EXAnoxj/Jx33V5ig13H2fACwKHIsF9vx1g0U/U5NXkKIMTh71kpD3ht84En7tI/a
# IV0DUB22DkEnx+4hBKrz6MCMVIu5q0o1ivGwGYrAMl/E8J/aBold82bnARBZXrWf
# UK6qnqRYrJqB1FdIV5nZETsHH3Bp3TFoOlOudF5vGQ1sHA0jxCD7yKjD6wwOxUiC
# EX8M8WVETIip0eGxwiA04MBqwe6ip+i1WhkiwqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNTEwMTgxMDM5MTZaMC8GCSqGSIb3DQEJBDEiBCDWKdzuJqWFWpW8giLQ
# SJgRBL5ncnTgtgsJnqneJIHAWDANBgkqhkiG9w0BAQEFAASCAgDILLxwvqWAewxq
# 8RlXnf3ArlG/A3YDL6P8dvjzMhNaH86SpzfFwGSGNLvMeXyAatvaPUDi4U3FDK+d
# uCdQz7rYaZAdhb7QD6KsJsUNlbR/QTzPjVmpOetpbO4rS1YQhW2782iHHmXnHgX9
# NgdKwEurJhIiViDk/IK/MdTXVGeaIUf9/6BkaiuwofmqX93PXAjPh3ko4It7RqRh
# Bb2fZvIzZLfQk4IyQnshw1sFZkUgw401iru+EpMWf9Eezg3htPt5J/d3dwC02V3T
# et1ewwxtvMQSrza0IudhQUseHr/ZzEVUV89Hmq8Kk0P45gi+RbWKedap91KM1v7C
# 061WZwh5W4/CFMy4BgaZsU9sUCy/jCfdsDVXayyC/bKoxyIRkwuNkdVISWBRkA+d
# 1rBQKYOl85/8PIFJ+TLK7VlPgFnPFfneVrwDxo0sA6kb8/53jUOnoCFkl/osWJkK
# GiWVUCCm6siBkj4WNe9++1URjx9i+5K/LA1jq9uv7raDugJQIqsaELMaILsAPyyG
# Zcgl8Z6s5VpvOhNl8+mQsvBE7YVzoL0kL5w/o9g2EUM62ZvFvPcRH4CH5gQrwcrU
# RL14RYw/SExvIkLa4jzty0lywD41VkE8zVqsgnYcicDiMIN8fA5CxgVpE6Ur0YOR
# wwt+/isSgIBXbzTIckqBfLkwtJtoNA==
# SIG # End signature block

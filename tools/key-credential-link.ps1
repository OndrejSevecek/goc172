
$global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

##
##

function global:Convert-FromByteString ([string] $byteString)
{
  [byte[]] $byteArray = New-Object byte[] ([Math]::Ceiling((([double] $byteString.Length) / 2)))

  for ($i = 0; $i -lt $byteArray.Length; $i ++) {

    $byteArray[$i] = [int]::Parse($byteString.Substring(($i * 2), ([Math]::Min(2, ($byteString.Length - ($i * 2))))), [System.Globalization.NumberStyles]::HexNumber)
  }

  return $byteArray
}

function global:Convert-FromBinaryTimes ([int] $version, [string] $source, [Int64] $longInt)
{
  if ($version -eq 0x00000000) {

    return (New-Object DateTime $longInt).ToLocalTime()

  } elseif ($version -eq 0x00000100) {

    return ([DateTime]::FromBinary($longInt)).ToLocalTime()

  } elseif ($version -eq 0x00000200) {

    if ($source -eq 'AD') {

      return ([DateTime]::FromFileTime($longInt)).ToLocalTime()

    } else {

      return ([DateTime]::FromBinary($longInt)).ToLocalTime()
    }

  } else {

    throw ('Invalid verstion to parse the binary time: {0}' -f $version)
  }
}

##
##

try {

  Import-Module ActiveDirectory | Out-Null

  Write-Host ('')
  [string] $who = 'miriamg'
  [string] $whoSupplied = Read-Host ('Account SAM or UPN or DN or displayName (default = {0})' -f $who)

  if (-not ([string]::IsNullOrEmpty($whoSupplied))) {

    $who = $whoSupplied.Trim()
  }

  Write-Host ('')

  [Microsoft.ActiveDirectory.Management.ADObject] $foundObject = $null
  if ($who.Contains('@')) {

    Write-Host ('Search AD: userPrincipalName = {0}' -f $who)
    $foundObject = Get-ADObject -LDAPFilter ('(userPrincipalName={0})' -f $who) -Properties sAMAccountName, userPrincipalName, displayName, msDS-DeviceId, 'msDS-KeyCredentialLink' | select -First 1

  } elseif ($who -match '(?i)\ACN\=.+') {

    Write-Host ('Search AD: distinguishedName = {0}' -f $who)
    $foundObject = Get-ADObject -Identity $who -Properties sAMAccountName, userPrincipalName, displayName, msDS-DeviceId, 'msDS-KeyCredentialLink' | select -First 1
  
  } else {

    [string] $ldapFilterMuster = '(&(|(sAMAccountName={0})(displayName={0}))(|(objectClass=user)(objectClass=msDS-Device)))'
    
    if ($who -notmatch '\*|\$\Z') {

      $ldapFilterMuster = '(&(|(sAMAccountName={0})(sAMAccountName={0}$)(displayName={0})(displayName={0}$))(|(objectClass=user)(objectClass=msDS-Device)))'
    }

    Write-Host ('Search AD: ldapFilter = {0}' -f ($ldapFilterMuster -f $who))
    $foundObject = Get-ADObject -LDAPFilter ($ldapFilterMuster -f $who) -Properties sAMAccountName, userPrincipalName, displayName, msDS-DeviceId, 'msDS-KeyCredentialLink' | select -First 1
  }

  Write-Host ('Account:  {0} | {1}' -f $foundObject.ObjectClass, $foundObject.DistinguishedName)
  Write-Host ('Account:  sam =     {0}' -f $foundObject.SamAccountName)
  Write-Host ('Account:  upn =     {0}' -f $foundObject.UserPrincipalName)
  Write-Host ('Account:  display = {0}' -f $foundObject.DisplayName)
  Write-Host ('Creds: #{0}' -f $foundObject.'msDS-KeyCredentialLink'.Count)

  [string] $rxKCL = '(?i)\AB\:\d+\:([a-fA-F0-9]+)\:([^\s].+\=.+[^\s])\Z'

  [Collections.ArrayList] $allCredentials = @()
  if ($foundObject.'msDS-KeyCredentialLink'.Count -gt 0) { foreach ($oneKeyCredentialLink in $foundObject.'msDS-KeyCredentialLink') {

    #$adsiUser = [ADSI] ('LDAP://{0}' -f $foundObject.DistinguishedName)
    #[System.__ComObject[]] $keyCredentialLinks = $adsiUser.Get('msDS-KeyCredentialLink')
    #
    #[Collections.ArrayList] $binaryValues = @()
    #if ($keyCredentialLinks.Length -gt 0) { foreach ($oneKeyCredentialLink in $keyCredentialLinks) {
    #
    #  [byte[]] $binaryValue = [System.__ComObject].InvokeMember('BinaryValue', [System.Reflection.BindingFlags]::GetProperty, $null, $oneKeyCredentialLink, $null)
    #  [void] $binaryValues.Add($binaryValue)
    #}}
  
    if ($oneKeyCredentialLink -notmatch $rxKCL) {

      throw ('Invalid msDS-KeyCredentialLink value: {0}' -f $oneKeyCredentialLink)
    }

    # Note: KEYCREDENTIALLINK_BLOB
    [System.Text.RegularExpressions.Match] $matchKCL = [regex]::Match($oneKeyCredentialLink, $rxKCL)
    [string] $dn = $matchKCL.Groups[2].Value
    [byte[]] $bytes = Convert-FromByteString -byteString $matchKCL.Groups[1].Value

    [psobject] $credentials = New-Object PSObject

    [int] $pointer = 0
    [UInt32] $version = [BitConverter]::ToUInt32($bytes, $pointer); $pointer += 4

    # Note: KEY_CREDENTIAL_LINK_VERSION_2 ... for user accounts
    #       KEY_CREDENTIAL_LINK_VERSION_1 ... for msDS-Device objects
    if (($version -ne 0x00000200) -and ($version -ne 0x00000100)) {

      throw ('Version value is not what was expected: 0x{0:X8}' -f $version)
    }

    Write-Host ('')    
    Write-Host ('Version: 0x{0:X8} | bytes = #{1}' -f $version, $bytes.Length)
    Add-Member -Input $credentials -MemberType NoteProperty -Name dn -Value $dn
    Add-Member -Input $credentials -MemberType NoteProperty -Name version -Value $version
    Add-Member -Input $credentials -MemberType NoteProperty -Name class -Value $foundObject.ObjectClass

    do { 

      # Note: KEYCREDENTIALLINK_ENTRY
      [UInt16] $length = [BitConverter]::ToUInt16($bytes, $pointer); $pointer += 2

      # Note: must be [int] because we use the value to index into the [hashtable]
      [int] $identifier = $bytes[$pointer]; $pointer += 1
      
      # Note: 2.2.20.6 KEYCREDENTIALLINK_ENTRY Identifiers
      [hashtable] $identifierDetails = @{
                                          1 = @(@(16, 32), 'KeyID')          # Note: 16 bytes for msDS-Device, 32 bytes for user accounts
                                          2 = @(@(32), 'KeyHash')
                                          3 = @(@(), 'KeyMaterial')
                                          4 = @(@(1), 'KeyUsage')            # Note: EY_USAGE_NGC = 0x1, KEY_USAGE_FIDO = 0x7, or KEY_USAGE_FEK = 0x8
                                          5 = @(@(1), 'KeySource')           # Note: KEY_SOURCE_AD
                                          6 = @(@(16), 'DeviceId')
                                          7 = @(@(), 'CustomKeyInformation') # Note: CUSTOM_KEY_INFORMATION
                                          8 = @(@(8), 'KeyApproximationLastLogonTimestamp')
                                          9 = @(@(8), 'KeyCreationTime')
                                        }

       if ($identifierDetails.Keys -notcontains $identifier) {

         throw ('Invalid identifier found: id = {0} | len = {1}' -f $identifier, $length)
       }

       $mustLen = $identifierDetails[$identifier][0]
       $name = $identifierDetails[$identifier][1]

       if (($mustLen.Length -gt 0) -and ($mustLen -notcontains $length)) {

         throw ('Invalid data length for an identifier: id = {0} | name = {1} | lenShouldBe = {2} | lenIs = {3}' -f $identifier, $name, ($mustLen -join ','), $length)
       }

       [byte[]] $data = $bytes[$pointer..($pointer + $length - 1)]; $pointer += $length

       Write-Host ('Value: id = {0} | name = {1} | data = #{2}' -f $identifier, $name, $data.Length)

       [string] $strData = $null

       if ($name -eq 'KeyId') {

         $strData = [BitConverter]::ToString($data)

       } elseif ($name -eq 'KeyHash') {

         $strData = [BitConverter]::ToString($data)

       } elseif ($name -eq 'KeyMaterial') {

         $strData = [BitConverter]::ToString($data)

         # Note: RSA OID: 1.2.840.113549.1.1.1 (RSA_SIGN)
         #$publicKey = New-Object System.Security.Cryptography.X509Certificates.PublicKey ((New-Object System.Security.Cryptography.Oid '1.2.840.113549.1.1.1'), ([byte[]] @(5, 0)), $data)
         #$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider $publicKey.Key

       } elseif ($name -eq 'KeyUsage') {

         [int] $keyUsage = $data[0]
         [hashtable] $keyUsages = @{ 0x1 = 'NGC'; 0x2 = 'DeviceTransportKey'; 0x3 = 'BitLocker'; 0x7 = 'FIDO'; 0x8 = 'FEK' }

         if ($keyUsages.Keys -notcontains $keyUsage) {

           throw ('Unknown key usage: 0x{0:X2}' -f $keyUsage)
         }

         $strData = $keyUsages[$keyUsage]

       } elseif ($name -eq 'KeySource') {

         [hashtable] $keySources = @{ 0x0 = 'AD'; 0x1 = 'AAD' }
         [int] $keySource = $data[0]
         if ($keySource -gt 0x1) {

           throw ('Invalid key source value: 0x{0:X2}' -f $keySource)
         }

         $strData = $keySources[$keySource]

       } elseif ($name -eq 'DeviceId') {

         $strData = ([guid] $data).ToString('d')

       } elseif ($name -eq 'CustomKeyInformation') {

         [int] $ckiPointer = 0
         # Note: CUSTOM_KEY_INFORMATION
         [byte] $ckiVersion = $data[$ckiPointer]; $ckiPointer += 1

         if ($ckiVersion -ne 0x1) {

           throw ('Invalid version of the CUSTOM_KEY_INFORMATION structure: 0x{0:X2} | {1}' -f $ckiVersion, ([BitConverter]::ToString($data)))
         }

         # Note: 0x0 = none
         #       0x1 = CUSTOMKEYINFO_FLAGS_ATTESTATION
         #       0x2 = CUSTOMKEYINFO_FLAGS_MFA_NOT_USED
         [hashtable] $ckiFlagsValues = @{ 0x0 = 'none'; 0x1 = 'attestation'; 0x2 = 'MFA not used' }
         [byte] $ckiFlags = $data[$ckiPointer]; $ckiPointer += 1

         if ($ckiFlags -band (-bnot 0x3)) {

           throw ('Unknown flags value of the CUSTOM_KEY_INFORMATION structure: 0x{0:X2} | {1}' -f $ckiFlags, ([BitConverter]::ToString($data)))
         }

         [string] $ckiFlagsStr = ($ckiFlagsValues.Keys | ? { $ckiFlags -band $_ } | % { $ckiFlagsValues[$_] }) -join '+'

         if ([string]::IsNullOrEmpty($ckiFlagsStr)) {

           $ckiFlagsStr = $ckiFlagsValues[0]
         }

         # Note: the structure as documented is either 2 bytes long or variably longer but
         #       then must contain all the remaining fields

         if ($ckiPointer -ge $data.Length) {

           $strData = 'version:0x{0:X2}|flags:{1}' -f $ckiVersion, $ckiFlagsStr

         } else {

           [hashtable] $ckiVolTypes = @{ 0x0 = 'none'; 0x1 = 'OS volume'; 0x2 = 'fixed data volume'; 0x3 = 'removable data volume' }
           [int] $ckiVolType = $data[$ckiPointer]; $ckiPointer += 1

           if ($ckiVolTypes.Keys -notcontains $ckiVolType) {

             throw ('Unknown volume type of the CUSTOM_KEY_INFORMATION structure: 0x{0:X2} | {1}' -f $ckiVolType, ([BitConverter]::ToString($data)))
           }

           [byte] $ckiNotificationSupported = $data[$ckiPointer]; $ckiPointer += 1
           
           if (@(0, 1) -notcontains $ckiNotificationSupported) {
            
             throw ('Invalid notification spec in the CUSTOM_KEY_INFORMATION structure: 0x{0:X2} | {1}' -f $ckiNotificationSupported, ([BitConverter]::ToString($data)))
           }

           [byte] $ckiFEKKeyVersion = $data[$ckiPointer]; $ckiPointer += 1

           # Note: according to documentation it should be always 1
           #       but our investigation sees 0
           if ($ckiFEKKeyVersion -gt 1) {
           
             throw ('Unkonwn FEK key version field in the CUSTOM_KEY_INFORMATION structure: 0x{0:X2} | {1}' -f $ckiFEKKeyVersion, ([BitConverter]::ToString($data)))
           }

           [hashtable] $ckiKeyStrengths = @{ 0x0 = 'unknown'; 0x1 = 'weak'; 0x2 = 'normal' }
           [int] $ckiKeyStrength = $data[$ckiPointer]; $ckiPointer += 1
           
           if ($ckiKeyStrengths.Keys -notcontains $ckiKeyStrength) {

             throw ('Unknown NGC key strength field in the CUSTOM_KEY_INFORMATION structure: 0x{0:X2} | {1}' -f $ckiKeyStrength, ([BitConverter]::ToString($data)))
           }

           # Note: reserved bytes, sometimes 9 only
           $ckiPointer += 10

           $strData = 'version:0x{0:X2}|flags:{1}|volume:{2}|notificationSupport:{3}|fekVersion:{4}|keyStrength:{5}' -f `
                                  $ckiVersion, `
                                  $ckiFlagsStr, `
                                  $ckiVolTypes[$ckiVolType], `
                                  ([bool] $ckiNotificationSupported), `
                                  $ckiFEKKeyVersion, `
                                  $ckiKeyStrengths[$ckiKeyStrength]
                                  
           # Note: EncodedExtendedCKI
           if ($ckiPointer -lt $data.Length) {

             $ckiExtended = $data[$ckiPointer..($data.Length - 1)]
             $strData += [BitConverter]::ToString($ckiExtended)
           }
         }

       } elseif ($name -eq 'KeyApproximationLastLogonTimestamp') {

         [Int64] $fileTime = [BitConverter]::ToInt64($data, 0)

         if ($fileTime -gt 0) {

           $strData = (Convert-FromBinaryTimes -version $credentials.version -source $credentials.KeySource -longInt $fileTime).ToString('yyyy-MM-dd HH:mm:ss')
         }

       } elseif ($name -eq 'KeyCreationTime') {

         [Int64] $fileTime = [BitConverter]::ToInt64($data, 0)
    
         if ($fileTime -gt 0) {

           $strData = (Convert-FromBinaryTimes -version $credentials.version -source $credentials.KeySource -longInt $fileTime).ToString('yyyy-MM-dd HH:mm:ss')
         }

       } else {

         throw ('Invalid name internal error: {0} | {1}' -f $identifier, $name)
       }

       Write-Host ('Data: {0}' -f $strData)
       Add-Member -Input $credentials -MemberType NoteProperty -Name $name -Value $strData

    } while ($pointer -lt $bytes.Length)

    [void] $allCredentials.Add($credentials)

  }} else {

    throw ('No msDS-KeyCredentialLink value on the object')
  }

  ##
  ##

  Write-Host ('')
  Write-Host ("Credentials: #{0} | -->`r`n{1}" -f $allCredentials.Count, ($allCredentials | fl * | Out-String))

  ##
  ##

} catch {

  Write-Host ('')
  Write-Host ('Error: {0}' -f $_) -Fore Red
}

if ([object]::Equals($psISE, $null)) {

  Write-Host ('')
  Read-Host ('Press ENTER to exit') | Out-Null
}



# SIG # Begin signature block
# MIIfJQYJKoZIhvcNAQcCoIIfFjCCHxICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDdq2Tm5Eqf9RTP
# 6d4mZhVRhA0BEGIS0txs+0VVPCUK8qCCGSswggWNMIIEdaADAgECAhAOmxiO+dAt
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
# BCDX5JlTAUlD8Ygas9NLz4UzU0icfgxmJYkW8buAUi+blTANBgkqhkiG9w0BAQEF
# AASCAQAsJXxm7dU2vVxSmMgVCLZD09aAzUtK23Tu+G808JFQs/azPW75ZDQPACH8
# hWZ72qmTHwFqseYpuPz5DB1AJdfhNvh+w8JY+PP2E9QFA3Q+Z5omwF4kKvdjjHCn
# d7J+zs8ynwbHfIcIu8p2vggBUNPdr60CrjaY2xizLRnURMMHMmO3fOEVkUToT97Q
# SZN6VXEUoBFB4afiwMEboZQfF+9vi3jqnzb86iIGbJtHaR5iIQ7azj20K8zMQINV
# 9H9DX32qMryZKVIXHeRuvEAZxVhexSlorI4d4s86Fats0CDRmRNxNqMJdwsKqjkD
# 7gW2AbYkOBpQ7MaXtv/GtnC+l8rRoYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJ
# AgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTsw
# OQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVT
# dGFtcGluZyBDQQIQC65mvFq6f5WHxvnpBOMzBDANBglghkgBZQMEAgEFAKBpMBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDIyNjA4
# NDYxOVowLwYJKoZIhvcNAQkEMSIEINrMS9ZE6PY6gbJcvi5WDglKfNjLljh51xWI
# NfD4mfWfMA0GCSqGSIb3DQEBAQUABIICAKE+j33yM/w8lXpYJ5YFHFAVwu221qhT
# HZwSy/uhvAipPCB3P1FeV8USPFBj31Y/eeDV2ZkJFuesG6X2fPiEiep0V/cpx2YI
# icxLuPxmxpJC5zxmTcIngsZAgwGCjrYK3eWVVsCpDZQbSSTIHdXE0NDZoC2NQQD/
# BhFuy6O0OqkgGkakEoKcaxE6AOhrpkfBuubTbvFN/XsGGHWmZNGTuGxklbxMbrDH
# GeXGHWWL3sY3ANtfZImDbcW+CBsmlZo5S4YAS7uzQQTbJm7fPf15p5d1hog4pQIl
# miH3rmiau41TlQWMVfcr+26o/OsgHtspp5TL1HA0cfEKYxP9QRDOu8/O22LevqYA
# OBgIoCTtkkIEfDqRtqs6RCM7hOfuI/rJkoltZcqDtCiExLq78opxErhvZniq3WFu
# xMtPatHtN+noyejYv2DFJJBPB6SQKf4h//LaT/Y8dV/8XWp0pGoNWmP+d/rSLvWn
# smaozFEE85vzNyqKBiO1DUJLvR67ITiqfT8BIHS2mchzByG6DhcdVkF7XOLC/x3Z
# MqguktTebfOeqPEhkYHfxYF4wr6Y7RsvnOT6TyeoUCdG0IdFhV60fdvCDIlzSB0e
# OxNFjbFbq+Wagm18Wz2eNaQIcLobUyLibl6lTIbLvvrvNEKv5SqJYVCUCORhbrep
# e5ZEKvBUN4p1
# SIG # End signature block

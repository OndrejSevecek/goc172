
param(
  [string] $prmLogin,
  [string] $prmPassword
  )

$global:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
[string] $baseFolder = Split-Path -Parent $MyInvocation.MyCommand.Definition

[string] $rxCurrentUPNsToUpdate = '(?i)(.+?)([^@]*?)(?:\.|)(onmicrosoft\.com)\Z'
[string] $rxCurrentUPNsToUpdateWithCustomDomain = '(?i)(.+?)([^@]*?(?:\.|)onmicrosoft\.com)(\Z)'
[string] $rxCurrentUPNsToUpdateStaticUPNMuster = '(?i)([^@]+@)({0})(\Z)'
[string] $rxUPN = '(?i)([^@]+@)([a-zA-Z0-9\-.]+)(\Z)'

##
##

[bool] $adPowerShellExists = $false
try { $adPowerShellExists = (Get-WindowsFeature RSAT-AD-PowerShell).Installed } catch { $error.Clear() }

if (-not $adPowerShellExists) {

  Write-Host ('')
  Write-Host ('Install AD PowerShell module: RSAT-AD-PowerShell')

  Add-WindowsFeature RSAT-AD-PowerShell | Out-Null
}

##
##

Write-Host ('')

[string] $fullDomainFQDN = 'ondrejsevecek202210.onmicrosoft.com'
[string] $replaceGroup2 = $fullDomainFQDN
[string] $suppliedLogin = $null

if (-not ([string]::IsNullOrEmpty($prmLogin))) {

  $replaceGroup2 = $prmLogin

} else {

  [string] $replaceGroup2Supplied = Read-Host ('Domain or UPN login to apply (default = {0})' -f $replaceGroup2)

  if (-not ([string]::IsNullOrEmpty($replaceGroup2Supplied))) {

    $replaceGroup2 = $replaceGroup2Supplied.Trim() -replace '\Amailto\:', ''

    if ($replaceGroup2 -notmatch '\A[a-zA-Z0-9@\-._]+\Z') {

      Write-Host ('')
      throw ('Invalid domain or UPN login supplied: {0}' -f $replaceGroup2)
    }
  }
}

if ($replaceGroup2 -match '\A[^@]+@[a-zA-Z0-9\-.]+\Z') {

  $suppliedLogin = $replaceGroup2
}

$replaceGroup2 = $replaceGroup2.TrimEnd('.')

if ($replaceGroup2 -like '*@*') {

  $replaceGroup2 = $replaceGroup2.Substring(($replaceGroup2.LastIndexOf('@') + 1))
}

$fullDomainFQDN = $replaceGroup2

if ($replaceGroup2 -like '?*.onmicrosoft.com') {

  $replaceGroup2 = $replaceGroup2.Substring(0, ($replaceGroup2.Length - 16))
}

if ($replaceGroup2.Contains('.')) {

  $rxCurrentUPNsToUpdate = $rxCurrentUPNsToUpdateWithCustomDomain
}

##
##

Write-Host ('')

[string] $rxCurrentUPNsToUpdateSupplied = Read-Host ('REGEX to find UPN suffixes or an exact UPN suffix (default = {0})' -f $rxCurrentUPNsToUpdate)

if (-not ([string]::IsNullOrEmpty($rxCurrentUPNsToUpdateSupplied))) {

  $rxCurrentUPNsToUpdate = $rxCurrentUPNsToUpdateSupplied.Trim()
}

if ($rxCurrentUPNsToUpdate -match '(?i)\A(@|)[a-zA-Z0-9\-.]+\Z') {

  $rxCurrentUPNsToUpdate = $rxCurrentUPNsToUpdateStaticUPNMuster -f ([regex]::Escape(($rxCurrentUPNsToUpdate -replace '\A@|\.\Z', '')))
  $replaceGroup2 = $fullDomainFQDN
}

Write-Host ('REGEX updated if it was needed at all: {0}' -f $rxCurrentUPNsToUpdate)
Write-Host ('NORMALIZED replacement string for regex group 2: {0}' -f $replaceGroup2)

##
##

Write-Host ('')

[bool] $resetPasswords = $true -or (-not ([string]::IsNullOrEmpty($prmPassword)))
[string] $resetPasswordsSupplied = Read-Host ('Reset passwords in AD (default = {0}) [yes/y/true/t/1/no/n/false/f/0]' -f $resetPasswords)

if (-not ([string]::IsNullOrEmpty($resetPasswordsSupplied))) {

  $resetPasswords = @('yes', 'y', 'true', 't', '1') -contains $resetPasswordsSupplied.Trim()
}

##
##

[string] $passwordToSet = 'Subjelort33'

if ($resetPasswords) {

  if (-not ([string]::IsNullOrEmpty($prmPassword))) {

    $passwordToSet = $prmPassword
  }

  [string] $passwordToSetSupplied = (New-Object Management.Automation.PSCredential ('DummyLogin', (Read-Host ('Password to set (default = {0})' -f $passwordToSet) -AsSecureString))).GetNetworkCredential().Password

  if (-not ([string]::IsNullOrEmpty($passwordToSetSupplied))) {

    $passwordToSet = $passwordToSetSupplied.Trim()
  }
}

##
##

$rootDSE = [ADSI] 'LDAP://RootDSE'

[string] $domainDN = $rootDSE.Properties['defaultNamingContext'].Value
[string] $configDN = $rootDSE.Properties['configurationNamingContext'].Value

[Collections.ArrayList] $domainDNSs = @()

([string[]] (Get-ADForest).Domains) | % { $_.Trim() } | sort | select -Unique | % { [void] $domainDNSs.Add($_) }

[Collections.ArrayList] $originalUPNSuffixes = @()
[Collections.ArrayList] $newUPNSuffixes = @()
[Collections.ArrayList] $removedUPNSuffixes = @()

Write-Host ('')

if ($domainDNSs.Count -gt 0) { foreach ($oneDomainDNS in $domainDNSs) {

  [Microsoft.ActiveDirectory.Management.ADUser[]] $adUsers = Get-ADUser -Filter * -Properties UserPrincipalName, SamAccountName, DisplayName -Server $oneDomainDNS | ? UserPrincipalName -like '?*@?*'
  Write-Host ('Accounts from domain: #{0} | {1}' -f $adUsers.Length, $oneDomainDNS)

  if ($adUsers.Length -gt 0) { foreach ($oneUser in $adUsers) {

        $originalUPNSuffix = $oneUser.UserPrincipalName.Substring(($oneUser.UserPrincipalName.LastIndexOf('@') + 1)).Trim('.')

        if ($oneUser.UserPrincipalName -match $rxCurrentUPNsToUpdate) {
    
          Write-Host ('Update: {0} | {1} | {2}' -f $oneUser.SamAccountName, $oneUser.UserPrincipalName, $oneUser.DisplayName, $oneUser.DistinguishedName)
          Write-Host ('        {0}' -f $oneUser.DistinguishedName)
          $newUPN = $oneUser.UserPrincipalName -replace $rxCurrentUPNsToUpdate, ('${{1}}{0}.${{3}}' -f $replaceGroup2)
          $newUPN = $newUPN.TrimEnd('.')
          $newUPNSuffix = $newUPN.Substring(($newUPN.LastIndexOf('@') + 1)).Trim('.')
          Write-Host ('        newUPN = {0}' -f $newUPN)
      
          Set-ADUser $oneUser -UserPrincipalName $newUPN -Server $oneDomainDNS

          if ($resetPasswords) {

            Write-Host ('        reset password = #{0}' -f $passwordToSet.Length)
            Set-ADAccountPassword -Identity $oneUser.DistinguishedName -Reset -NewPassword (ConvertTo-SecureString $passwordToSet -AsPlainText -Force) -Server $oneDomainDNS
          }

          if ([string]::IsNullOrEmpty($suppliedLogin)) {

            $suppliedLogin = 'admin@{0}' -f [regex]::Match($newUPN, $rxUPN).Groups[2].Value
          }

          if ($removedUPNSuffixes -notcontains $originalUPNSuffix) {

            [void] $removedUPNSuffixes.Add($originalUPNSuffix)
          }

        } else {

          $newUPNSuffix = $originalUPNSuffix
        }

        if ($newUPNSuffixes -notcontains $newUPNSuffix) {

          [void] $newUPNSuffixes.Add($newUPNSuffix)
        }

        if ($originalUPNSuffixes -notcontains $originalUPNSuffix) {

          [void] $originalUPNSuffixes.Add($originalUPNSuffix)
        }
  }}
}}

$partitionsCnt = Get-ADObject -Identity ('CN=Partitions,{0}' -f $configDN) -Properties uPNSuffixes
[string[]] $forestUPNSuffixes = $partitionsCnt.uPNSuffixes | sort | select -Unique

Write-Host ('')
Write-Host ('Current forest domains: #{0} | {1}' -f $domainDNSs.Count, ($domainDNSs -join ', '))
Write-Host ('Current forest UPN suffixes: #{0} | {1}' -f $forestUPNSuffixes.Length, ($forestUPNSuffixes -join ', '))
Write-Host ('Removed user UPN suffixes: #{0} | {1}' -f $removedUPNSuffixes.Count, ($removedUPNSuffixes -join ', '))
Write-Host ('Current user UPN suffixes: #{0} | {1}' -f $newUPNSuffixes.Count, ($newUPNSuffixes -join ', '))

[Collections.ArrayList] $allUPNSuffixes = @()
[void] $allUPNSuffixes.AddRange($forestUPNSuffixes)
[void] $allUPNSuffixes.AddRange($newUPNSuffixes)

[Collections.ArrayList] $updatedForestUPNSuffixes = @()
foreach ($oneForestUPNSuffix in $allUPNSuffixes) {

  $oneForestUPNSuffix = $oneForestUPNSuffix.Trim('.')
  #if (($originalUPNSuffixes -notcontains $oneForestUPNSuffix) -and ($domainDNSs -notcontains $oneForestUPNSuffix) -and ($updatedForestUPNSuffixes -notcontains $oneForestUPNSuffix)) {
  if (($removedUPNSuffixes -notcontains $oneForestUPNSuffix) -and ($domainDNSs -notcontains $oneForestUPNSuffix) -and ($updatedForestUPNSuffixes -notcontains $oneForestUPNSuffix)) {

    [void] $updatedForestUPNSuffixes.Add($oneForestUPNSuffix)
  }

  if (($newUPNSuffixes -contains $oneForestUPNSuffix) -and ($domainDNSs -notcontains $oneForestUPNSuffix) -and ($updatedForestUPNSuffixes -notcontains $oneForestUPNSuffix)) {

    [void] $updatedForestUPNSuffixes.Add($oneForestUPNSuffix)
  }
}

Write-Host ('')
Write-Host ('Correct list of forest UPN suffixes: #{0} | {1}' -f$updatedForestUPNSuffixes.Count, ($updatedForestUPNSuffixes -join ', '))

Write-Host ('')
[string] $updateUPNSuffixes = Read-Host ('Do you want to update forest UPN suffixes (default = yes)')

if (('', 't', 'y', 'a', '1', 'true', 'yes', 'ano') -contains $updateUPNSuffixes.Trim()) {

  Set-ADObject $partitionsCnt -Replace @{ uPNsuffixes = ([string[]] $updatedForestUPNSuffixes) }
}

##
##

Write-Host ('')

[bool] $resetPasswordsInAAD = $false -and $resetPasswords -and (-not ([string]::IsNullOrEmpty($suppliedLogin)))
[string] $resetPasswordsInAADSupplied = Read-Host ('Reset passwords in AAD/EntraID (default = {0}) [yes/y/true/t/1/no/n/false/f/0]' -f $resetPasswordsInAAD)

if (-not ([string]::IsNullOrEmpty($resetPasswordsInAADSupplied))) {

  $resetPasswordsInAAD = @('yes', 'y', 'true', 't', '1') -contains $resetPasswordsInAADSupplied.Trim()
}

if ($resetPasswordsInAAD) {

  Write-Host ('')
  Write-Host ('Reset AAD/EntraId passwords')

  [string] $dnsRefreshPS = Join-Path $baseFolder 'azure-DNS-refresh.ps1'
  if (Test-Path $dnsRefreshPS) {

    & $dnsRefreshPS -auto -tenantDomain $fullDomainFQDN -others 'Install-Module and Install-PackageProvider'
  }

  # Note: error: Function Invoke-MgGraphGroupDrive cannot be created because function capacity 4096 has been exceeded for this scope
  #       working solution appears to be to upgrade the $MaximumFunctionCount value
  $global:MaximumFunctionCount = 32768

  [System.Management.Automation.FunctionInfo] $mgUserExists = $null
  try { $mgUserExists = Get-Command Get-MgUser } catch { $error.Clear() }

  if ([object]::Equals($mgUserExists, $null)) {

    Write-Host ('Assert and/or install AzureAD/EntraID modules')

    $nugetInstallRes = Install-PackageProvider Nuget -Scope AllUsers -Force
    Write-Host ('Nuget: {0}' -f $nugetInstallRes.Version)

    # Note: Get-MgUser
    #Install-Module Microsoft.Graph.Users -Scope AllUsers -Force
    # Note: Get-MgDomain
    #Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope AllUsers -Force
    # Note: Get-MgUserAuthenticationPasswordMethod
    #Install-Module Microsoft.Graph.Identity.SignIns -Scope AllUsers -Force
    # Note: Reset-MgUserAuthenticationMethodPassword
    #Install-Module Microsoft.Graph.Users.Actions -Scope AllUsers -Force
    Install-Module Microsoft.Graph -Scope AllUsers -Repository PSGallery -Force
  }

  [bool] $reconnectMg = $false
  do {

    $reconnectMg = $false
    #Connect-MgGraph -Scopes User.ReadWrite.All, Directory.AccessAsUser.All, UserAuthenticationMethod.Read.All -NoWelcome
    # Note: Directory.AccessAsUser.All required for Update-MgUser -PasswordProfile
    # Note: Domain.Read.All required for Get-MgDomain
    [bool] $repeatConnect = $true
    do { 
    
      try { 
    
        Connect-MgGraph -Scopes User.ReadWrite.All, Directory.AccessAsUser.All, Domain.Read.All -NoWelcome
        $repeatConnect = $false
      
      } catch {

        Write-Host ('')
        Write-Host ('Error: {0}' -f $_) -Fore Red

        Write-Host ('')
        [string] $repeatConnectSupplied = Read-Host ('Try again (default = {0}) [yes/y/true/t/1/no/n/false/f/0]' -f $repeatConnect)

        if (-not ([string]::IsNullOrEmpty($repeatConnectSupplied))) {

          $repeatConnect = @('yes', 'y', 'true', 't', '1') -contains $repeatConnectSupplied.Trim()
        }
      } 
    
    } while ($repeatConnect)

    [Microsoft.Graph.PowerShell.Authentication.AuthContext] $mgContext = Get-MgContext
    [string] $accountDomain = [regex]::Match($mgContext.Account, $rxUPN).Groups[2].Value
    [string[]] $cloudDomains = Get-MgDomain | select -Expand Id

    Write-Host ('')
    Write-Host ('Connected as: {0} | {1}' -f $mgContext.Account, $accountDomain)
    Write-Host ('Connected to: tenant = {0}' -f $mgContext.TenantId)
    Write-Host ('Connected to: domains = {0}' -f ($cloudDomains -join ', '))

    if (($cloudDomains -notcontains $fullDomainFQDN) -or ($accountDomain -ne $fullDomainFQDN) -or ((-not ([string]::IsNullOrEmpty($suppliedLogin))) -and ($suppliedLogin -ne $mgContext.Account))) {

      Write-host ('Originally supplied login: {0}' -f $suppliedLogin)
      Write-host ('Domain FQDN updated in AD: {0}' -f $fullDomainFQDN)

      Write-Host ('')

      [bool] $reauthenticateWithDifferentTenantAdmin = $true
      [string] $reauthenticateWithDifferentTenantAdminSupplied = Read-Host ('Don''t you want to use a different account (default = {0}) [yes/y/true/t/1/no/n/false/f/0]' -f $reauthenticateWithDifferentTenantAdmin)

      if (-not ([string]::IsNullOrEmpty($reauthenticateWithDifferentTenantAdminSupplied))) {

        $reauthenticateWithDifferentTenantAdmin = @('yes', 'y', 'true', 't', '1') -contains $reauthenticateWithDifferentTenantAdminSupplied.Trim()
      }

      if ($reauthenticateWithDifferentTenantAdmin) {

        $disconnectResult = Disconnect-MgGraph
        $reconnectMg = $true
      }
    }

  } while ($reconnectMg)

  # Note: yes the onPremises properties must be explicitly named to be downloaded
  # Note: all really synced accounts have OnPremisesImmutableId valid
  #       while the Sync_ account does not have this property logically but 
  #       the Sync_ account also has the OnPremisesSyncEnabled set to $true
  [Microsoft.Graph.PowerShell.Models.MicrosoftGraphUser[]] $aadUsers = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, OnPremisesImmutableId, OnPremisesSyncEnabled, LastPasswordChangeDateTime

  Write-Host ('')
  Write-Host ('AAD/EntraId users: all = {0}' -f $aadUsers.Length)
  Write-Host ('AAD/EntraId users: nonSynced = {0}' -f ($aadUsers | ? { -not $_.OnPremisesSyncEnabled } | measure | select -Expand Count))

  Write-Host ('')
  if ($aadUsers.Length -gt 0) { foreach ($oneAADUser in $aadUsers) {

    if (-not $oneAADUser.OnPremisesSyncEnabled) {

      Write-Host ('User: {0} | {1} | {2}' -f $oneAADUser.Id, $oneAADUser.UserPrincipalName, $oneAADUser.DisplayName)
      # Note: nonsense using the method
      #$passwordMethod = Get-MgUserAuthenticationPasswordMethod -UserId $oneAADUser.Id
      #Write-Host ('      password = {0}' -f $passwordMethod.CreatedDateTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'))
      Write-Host ('      password = {0}' -f $oneAADUser.LastPasswordChangeDateTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'))

      # Note: the Reset-MgUserAuthenticationMethodPassword would always require the user to change the password
      #       at the next sign-in without any apparent way to disable this requirement
      #Reset-MgUserAuthenticationMethodPassword -UserId $oneAADUser.Id -AuthenticationMethodId $passwordMethod.Id -NewPassword $passwordToSet

      $newPasswordProfile = @{ ForceChangePasswordNextSignIn = $false
                               ForceChangePasswordNextSignInWithMfa = $false
                               Password = $passwordToSet
                             }

      Update-MgUser -UserId $oneAADUser.Id -PasswordProfile $newPasswordProfile #-PasswordPolicies DisablePasswordExpiration
    }
  }}
}

##
##

Write-Host ('')



# SIG # Begin signature block
# MIIfYgYJKoZIhvcNAQcCoIIfUzCCH08CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDy6CpFhJGgMX+R
# HkIj+AYp8u5Lt3EaZB7dCp7L8B73pqCCGWIwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# 9w0BCQQxIgQghZamEHv3pkCOyzqgBp4SAr21ubLKsGUAfsERe5GdvZcwDQYJKoZI
# hvcNAQEBBQAEggEApZPAxABa28QjGm/f0VvXoyMBXsFQFosy5MPcHz1lM2RQHUhN
# OiMwYzTisGxpoirpRNlmy/egELQUd+BzLeVbL6FTXBfhO+PBFx7XVrnuIMmtH1tQ
# vBG37t2fm4zb1mR9USCGDt7dBWiJ3C3zqYMx0ivtzhF7Ssc+7s26fwKhXm2b3Mlg
# p8cAA94x2uDpqR+mH87hfVn3BJUsWfvF059mx7r8net+P4GQZKIHW809da58miiG
# IT4su+z/QdbN8WMLcqoWirJE+5aj/Id0+8wBoru1k6kpFudW11Xbs6rjRQg7MQeq
# l8P5XGeLXL7rj/HUvOwb/hQQtnC0OEcRVIGOkqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAzMTgwNzUwMTdaMC8GCSqGSIb3DQEJBDEiBCCzwV0YPQRhom1D9x4e
# 0xqNcgpTETjOKisdFoDImkeChjANBgkqhkiG9w0BAQEFAASCAgC+bYn03pKGJRP9
# VjVNj3pN3uNV8c8xdvO+tchegq9mJo2CajI96D07/XfEvwWZ8crbPrvxFIK5d+4F
# VVHrovnS8EYqQk89cL4BT79XPW1tTYLF2hhpf/dikxEvvUBVbV7WbVpGODnB3+l+
# 1gaNmrrF2fvSM13T+5yJVftm/Q5TuDFVuyQ4lBCBhGtWCUYKOloFoGha8M9BObb3
# Zc55rVOEDNHjTQtgGOR1YtLGr+FG0keJjgdiIMGJRLWXzwTazsxMteNUAdotpYNf
# 7EWg/hJZKkGIm8S6EKisZKd2g2CXGBB+GgtkYB/pFC1mIU3nKTRCbfyuAzieIJJI
# 8CN6lQedNomx7PLw+7SvSqQAOVHcOeyc+PQvlbBH0VBuQK0e9TPBRPZ3VFdmDKFr
# wrelbOT1uJv15VcrlZgXhhWVKS+l1Odk9hC+KBlsndMdSEdHgSgaZLYTHapA8Vm/
# FEwZJeXICxEH1+HshdJzRMRp/SWXdX7JMe/pcigg3dfAuxmsSEsyGeP1GJyD25Q1
# H1qnOagD+ovj1pUqCbcXqDmxWjGvgSE/qbIavjJJzqAX8l2YBZcWnqBvcfSKR0Te
# XR2srnX2t3X+yVjkH+GbYDeZDpqbweO7X0xuzz2FLUShQHFIZQiRGctU98zxJd+Q
# BjuN8neJP3pmDTIQnScnsIwfaSHNnw==
# SIG # End signature block

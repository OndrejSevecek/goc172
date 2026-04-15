
$ErrorActionPreference = 'Stop'

[string] $thisScript = $MyInvocation.MyCommand.Definition
[string] $thisFolder = $env:TEMP

if ((-not ([string]::IsNullOrEmpty($thisScript))) -and ($thisScript -match '(?i)\A[a-z]\:\\[^\\]+|\A\\\\[^\\]+\\[^\\]+\\[^\\]+')) {

  $thisFolder = Split-Path -Parent $thisScript
}

##
##

function global:Get-IssuerCert([System.Security.Cryptography.X509Certificates.X509Certificate2] $cert)
{
   [System.Security.Cryptography.X509Certificates.X509Certificate2] $issuer = $null

   if ((-not ([object]::Equals($cert, $null))) -and ($cert.Subject -ne $cert.Issuer)) {

     [System.Security.Cryptography.X509Certificates.X509Chain] $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
     $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
     [void] $chain.Build($cert)
     
     if ($chain.ChainElements.Count -gt 1) {

       $issuer = $chain.ChainElements[1].Certificate
     }
   }

   if (-not ([object]::Equals($issuer, $null))) {

     Write-Host ('')
     Write-Host ('Issuer: child  = {0} | {1}' -f $cert.Thumbprint, $cert.Subject)
     Write-Host ('Issuer: parent = {0} | {1}' -f $issuer.Thumbprint, $issuer.Subject)
   }

   return $issuer
}

function global:Save-Cert ([System.Security.Cryptography.X509Certificates.X509Certificate2] $cert, [string] $folderToSave, [string] $fileNameOptional, [string] $fileNamePrefixOptional)
{
  if ([string]::IsNullOrEmpty($fileNameOptional)) {

    #[string] $rxCN = '(?i)CN\s*=\s*((?:\\\,|[^\,])+)(?:\Z|\,)'
    [string] $rxCN = '(?i)\s*CN\s*=\s*(.+?)(?:(?:\s*(?<=[^\\])\,)\s*|\s*(?<=(?<!\\)(?:\\{2})+)\,\s*|\s*\Z)'
    [string] $cnNormalized = [regex]::Match($cert.Subject, $rxCN).Groups[1].Value -replace '[\W_\-\s.]', '_'

    if ([string]::IsNullOrEmpty($cnNormalized)) {

      if ($cert.DnsNameList.Count -gt 0) {

        $cnNormalized = $cert.DnsNameList[0] -replace '[\W_\-\s.]', '_'
      }
    }

    $fileNameOptional = '{0}.cer' -f $cnNormalized
  }

  if (-not ([string]::IsNullOrEmpty($fileNamePrefixOptional))) {

    if (-not ([string]::IsNullOrEmpty($fileNameOptional))) {

      $fileNameOptional = '{0}-{1}' -f $fileNamePrefixOptional, $fileNameOptional

    } else {

      $fileNameOptional = '{0}.cer' -f $fileNamePrefixOptional
    }
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

function global:Install-CEPClient (
  [Parameter(Mandatory = $true)] [string] $url,
  [Parameter(Mandatory = $true)] [string] $login,
  [Parameter(Mandatory = $true)] [string] $password,
                                 [switch] $reinstall
  )
{
  [__ComObject] $cepWebService = $null
  [__ComObject] $cepHelper = $null
  [__ComObject] $cepTemplates = $null
  [__ComObject] $ekus = $null
  [Security.Cryptography.SHA1Managed] $sha = New-Object Security.Cryptography.SHA1Managed

  [hashtable] $templates = @{}

  try {

    Write-Host ('Connect to Certificate Enrollment Policy (CEP) web service: {0} | {1}' -f $login, $url)

    # Note: not available on 2003/XP-
    $cepWebService = New-Object -ComObject X509Enrollment.CX509EnrollmentPolicyWebService
    # Note: X509EnrollmentAuthFlags.UserName = 4
    [void] $cepWebService.SetCredential($null, 4, $login, $password)

    # Note: X509EnrollmentAuthFlags.UserName = 4
    #       $false - isUntrusted
    #       X509CertificateEnrollmentContext.ContextMachine = 2 (.ContextUser = 1)
    [void] $cepWebService.Initialize($url, $null, 4, $false, 2)

    # Note:  X509EnrollmentPolicyLoadOption.LoadOptionDefault = 0
    # Note:  X509EnrollmentPolicyLoadOption.LoadOptionReload = 2
    #try { 
    [void] $cepWebService.LoadPolicy(2)
    # } catch { [void] $cepWebService.LoadPolicy(0) }

    [UInt32] $cepCost = $cepWebService.Cost
    [string] $cepId = $cepWebService.GetPolicyServerId()
    [string] $cepFriendlyName = $cepWebService.GetFriendlyName()

    [guid] $tryGuid = New-Object Guid
    if (-not ([guid]::TryParse($cepId, ([ref] $tryGuid)))) {

      throw ('Invalid data obtained from the CEP web service: {0} | {1}' -f $cepId, $cepFriendlyName)
    }

    $cepTemplates = $cepWebService.GetTemplates()
    if ($cepTemplates.Count -gt 0) { foreach ($oneTemplate in $cepTemplates) {

      [PSObject] $newTemplate = New-Object PSObject
      Add-Member -Input $newTemplate -MemberType NoteProperty -Name name -Value $oneTemplate.Property(1)       # Note: EnrollmentTemplateProperty.TemplatePropCommonName = 1
      Add-Member -Input $newTemplate -MemberType NoteProperty -Name display -Value $oneTemplate.Property(2)    # Note: EnrollmentTemplateProperty.TemplatePropFriendlyName = 2
      Add-Member -Input $newTemplate -MemberType NoteProperty -Name oid -Value $oneTemplate.Property(12).Value # Note: EnrollmentTemplateProperty.TemplatePropOID = 12
      Add-Member -Input $newTemplate -MemberType NoteProperty -Name keySize -Value $oneTemplate.Property(11)   # Note: EnrollmentTemplateProperty.TemplatePropMinimumKeySize = 11
      
      [int] $keySpecInt = $oneTemplate.Property(7)                                                             # Note: EnrollmentTemplateProperty.TemplatePropKeySpec = 7
      [string] $hashAlgo = $null
      [string[]] $csps = $null
      $ekus = $null
      
      # Note: not present on templates v1/v2
      try { $hashAlgo = $oneTemplate.Property(22) } catch { $error.Clear() }                                   # Note: EnrollmentTemplateProperty.TemplatePropHashAlgorithm = 22
      # Note: if any CSP then the property is empty
      try { $csps = $oneTemplate.Property(4) } catch { $error.Clear() }                                        # Note: EnrollmentTemplateProperty.TemplatePropCryptoProviders = 4
      try { $ekus = $oneTemplate.Property(3) } catch { $error.Clear() }                                        # Note: EnrollmentTemplateProperty.TemplatePropEKUs = 3

      # Note: AT_KEYEXCHANGE = 1
      #       AT_SIGNATURE = 2
      if ($keySpecInt -eq 1) {

        [string] $keySpec = 'exchange'

      } elseif ($keySpecInt -eq 2) {

        [string] $keySpec = 'signature'

      } else {

        throw ('Unknown key spec on a certificate template: {0} | {1}' -f $newTemplate.name, $keySpecInt)
      }

      if ([string]::IsNullOrEmpty($hashAlgo)) {

        $hashAlgo = 'SHA1'
      }

      [Collections.ArrayList] $ekuOIDs = @()
      [Collections.ArrayList] $ekuNames = @()

      if ($ekus.Count -gt 0) { foreach ($oneEKU in $ekus) { 
      
        [void] $ekuOIDs.Add($oneEKU.Value)

        if ($global:adscannerCertOIDs.Keys -contains $oneEKU.Value) {

          [void] $ekuNames.Add(($global:adscannerCertOIDs[$oneEKU.Value]))
        }
      }}

      Add-Member -Input $newTemplate -MemberType NoteProperty -Name hash -Value $hashAlgo
      Add-Member -Input $newTemplate -MemberType NoteProperty -Name keySpec -Value $keySpec
      Add-Member -Input $newTemplate -MemberType NoteProperty -Name csps -Value $csps
      Add-Member -Input $newTemplate -MemberType NoteProperty -Name ekuOIDs -Value $ekuOIDs
      Add-Member -Input $newTemplate -MemberType NoteProperty -Name ekuNames -Value $ekuNames

      Write-Host ('Certificate template: {0} | {1} | {2}' -f $newTemplate.name, $newTemplate.keySpec, ($newTemplate.ekuNames -join ','))
      [void] $templates.Add($newTemplate.name, $newTemplate)
    }}

    Write-Host ('Verify installation of the CEP in registry: {0} | {1}' -f $cepFriendlyName, $cepId)
    
    # Note: the .Initialize method raises ACCESS_DENIED for some unknown reason
    #       so we go the direct registry way instead
    #       Without calling the .Initialize(2) the AddPolicyServer would work
    #       but would add the registration into HKCU instead of the HKLM
    #$cepHelper = New-Object -ComObject X509Enrollment.CX509EnrollmentHelper
    # Note: X509CertificateEnrollmentContext.ContextMachine = 2 (.ContextUser = 1)
    #[void] $cepHelper.Initialize(2)
    # Note: PolicyServerUrlFlags.PsfNone = 0
    #       X509EnrollmentAuthFlags.UserName = 4
    #[void] $cepHelper.AddPolicyServer($url, $cepId, 0, 4, $login, $password)

    [string] $cepKeyBase = 'HKLM:\SOFTWARE\Microsoft\Cryptography\PolicyServers'

    # Note: according to [MS-CAESO] the <keyName> can be any string
    #       according to debugging the SHA1 value is computed from the lowercase URL
    #[string] $cepKeyName = ('{0}{1}' -f ([guid]::NewGuid().ToString('n')), ([guid]::NewGuid().ToString('n'))).SubString(0, 40)
    $sha = New-Object Security.Cryptography.SHA1Managed
    [string] $cepKeyName = [BitConverter]::ToString($sha.ComputeHash(([Text.Encoding]::Unicode.GetBytes($url.ToLower())))).Replace('-', '').ToLower()
    
    [bool] $alreadyInstalled = $false

    if (Test-Path $cepKeyBase) {

      [Microsoft.Win32.RegistryKey[]] $cepKeys = Get-ChildItem $cepKeyBase

      if ($cepKeys.Length -gt 0) { foreach ($oneCepKey in $cepKeys) {

        try {

          if (($oneCepKey.GetValue('PolicyID') -eq $cepId) -and ($oneCepKey.GetValue('URL') -eq $url)) {

            $cepKeyName = Split-Path -Leaf $oneCepKey.Name
            $alreadyInstalled = $true
            break
          }

        } catch {

          $error.Clear()
        }
      }}
    }

    if ((-not $alreadyInstalled) -or ($reinstall)) {

      [string] $cepKeyPath = ('{0}\{1}' -f $cepKeyBase, $cepKeyName)

      if (-not (Test-Path $cepKeyPath)) {

        New-Item -Path $cepKeyPath -Force | Out-Null
      }
    
      Set-ItemProperty -Path $cepKeyPath -Name URL -Value $url -Force | Out-Null
      Set-ItemProperty -Path $cepKeyPath -Name PolicyID -Value $cepId -Force | Out-Null
      Set-ItemProperty -Path $cepKeyPath -Name FriendlyName -Value $cepFriendlyName -Force | Out-Null
      Set-ItemProperty -Path $cepKeyPath -Name Flags -Value 0x20 -Force | Out-Null
      Set-ItemProperty -Path $cepKeyPath -Name AuthFlags -Value 4 -Force | Out-Null
      Set-ItemProperty -Path $cepKeyPath -Name Cost -Value $cepCost -Type DWord -Force | Out-Null
    }

  } finally {

    if (-not ([object]::Equals($cepHelper, $null))) { [void] [Runtime.Interopservices.Marshal]::ReleaseComObject($cepHelper) }
    if (-not ([object]::Equals($ekus, $null))) { [void] [Runtime.Interopservices.Marshal]::ReleaseComObject($ekus) }
    if (-not ([object]::Equals($cepTemplates, $null))) { [void] [Runtime.Interopservices.Marshal]::ReleaseComObject($cepTemplates) }
    if (-not ([object]::Equals($cepWebService, $null))) { [void] [Runtime.Interopservices.Marshal]::ReleaseComObject($cepWebService) }
    if (-not ([object]::Equals($sha, $null))) { $sha.Dispose() }
  }
}

##
##

try {

  [string] $pkiDistroUrl = 'http://pki.gopas.cz/CA/GOPAS Root Online CA.crt'
  # $pkiDistroUrl = 'http://pki.sevecek.com/CA/Sevecek Enterprise Root CA(1).crt'
  [string] $pkiDistroUrlSupplied = Read-Host ('CA certificate to DOWNLOAD or open from FILE (default = {0})' -f $pkiDistroUrl)

  if (-not ([string]::IsNullOrEmpty($pkiDistroUrlSupplied))) {

    $pkiDistroUrl = ($pkiDistroUrlSupplied -replace '\A[\s"'']+', '') -replace '[\s"'']+\Z', ''
  }

  [string] $folderToSave = 'C:\TEMP'
  [string] $folderToSaveSupplied = Read-Host ('Save downloaded certificate into folder (default = {0})' -f $folderToSave)

  if (-not ([string]::IsNullOrEmpty($folderToSaveSupplied))) {

    $folderToSave = $folderToSaveSupplied
  }

  ##
  ##

  [bool] $openFromFile = ($pkiDistroUrl -match '(?i)\A[a-z]\:\\[^\\]') -or ($pkiDistroUrl -match '(?i)\A\\\\[^\\]+\\[^\\]+')

  [System.Security.Cryptography.X509Certificates.X509Certificate2] $downloadedCert = $null

  if ($openFromFile) {

    Write-Host ('')
    Write-Host ('Load certificate from a file: {0}' -f $pkiDistroUrl)
    $downloadedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $pkiDistroUrl

  } else {

    Write-Host ('')
    Write-Host ('Download certificate from an URL: {0}' -f $pkiDistroUrl)
    [Microsoft.PowerShell.Commands.WebResponseObject] $certDownloaded = $null
    $certDownloaded = Invoke-WebRequest -Uri $pkiDistroUrl

    if (([object]::Equals($certDownloaded, $null)) -or ($certDownloaded.StatusCode -ne 200) -or ($certDownloaded.Content.Length -lt 500) -or (($certDownloaded.Headers['Content-Type'] -ne 'application/x-x509-ca-cert') -and ($certDownloaded.Headers['Content-Type'] -ne 'application/pkix-cert'))) {

      throw ('The CA certificate cannot be downloaded: {0} | {1} | len = {2} | mime = {3}' -f $pkiDistroUrl, $certDownloaded.StatusCode, $certDownloaded.Content.Length, $certDownloaded.Headers['Content-Type'])
    }

    $downloadedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$certDownloaded.Content)
  }

  Write-Host ('')
  Write-Host ('DownloadedCA: thumbprint = {0}' -f $downloadedCert.Thumbprint)
  Write-Host ('DownloadedCA: subject    = {0}' -f $downloadedCert.Subject)
  Write-Host ('DownloadedCA: validity   = {0}' -f $downloadedCert.NotAfter.ToString('yyyy-MM-dd'))
  
  [bool] $isDownloadedRootCA = $downloadedCert.Subject -eq $downloadedCert.Issuer
  Write-Host ('DownloadedCA: isRoot     = {0}' -f $isDownloadedRootCA)

  ##
  ##

  [string] $downloadedCertFileName = Split-Path -Leaf $pkiDistroUrl

  if (($downloadedCertFileName -notlike '*.cer') -and ($downloadedCertFileName -notlike '*.crt')) {

    $downloadedCertFileName = '{0}.cer' -f $downloadedCertFileName
  }

  Save-Cert -cert $downloadedCert -folderToSave $folderToSave -fileNameOptional $downloadedCertFileName

  ##
  ##

  [System.Security.Cryptography.X509Certificates.X509Certificate2] $rootCert = $null

  if (-not $isDownloadedRootCA) {

    $parentCert = $downloadedCert

    $i = 1
    do {

      $parentCert = Get-IssuerCert $parentCert
      
      if (-not ([object]::Equals($parentCert, $null))) {

        $rootCert = $parentCert
        Save-Cert -cert $rootCert -folderToSave $folderToSave -fileNamePrefixOptional ('{0}-issuer{1:D2}' -f $downloadedCertFileName, $i)
      } 

      $i ++

    } while (-not ([object]::Equals($parentCert, $null)))
  }
  
  if ([object]::Equals($rootCert, $null)) {
  
    $rootCert = $downloadedCert
  }

  ##
  ##

  Write-Host ('')
  Write-Host ('RootCA: thumbprint = {0}' -f $rootCert.Thumbprint)
  Write-Host ('RootCA: subject    = {0}' -f $rootCert.Subject)
  Write-Host ('RootCA: validity   = {0}' -f $rootCert.NotAfter.ToString('yyyy-MM-dd'))

  [bool] $isRootCA = $rootCert.Subject -eq $rootCert.Issuer
  Write-Host ('RootCA: isRoot     = {0}' -f $isRootCA)

  $regRootCAKey = Join-Path HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates $rootCert.Thumbprint
  [Security.Cryptography.X509Certificates.X509Certificate2] $regRootCACert = $null

  if (Test-Path $regRootCAKey) {

    try {

      $regRootCACert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,(Get-ItemProperty $regRootCAKey Blob -ErrorAction SilentlyContinue).Blob)
          
    } catch { $error.Clear() }
  }

  $regThirdPartyCAKey = Join-Path HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates $rootCert.Thumbprint
  [Security.Cryptography.X509Certificates.X509Certificate2] $regThirdPartyCACert = $null

  if (Test-Path $regThirdPartyCAKey) {

    try {

      $regThirdPartyCACert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,(Get-ItemProperty $regThirdPartyCAKey Blob -ErrorAction SilentlyContinue).Blob)
          
    } catch { $error.Clear() }
  }

  if ($regThirdPartyCACert.Thumbprint -eq $rootCert.Thumbprint) {

    Write-Host ('RootCA: trusted    = third-party CA trust already')
  }

  if ($regRootCACert.Thumbprint -ne $rootCert.Thumbprint) {

    Write-Host ('')
    [string] $acceptRoot = Read-Host ('Do you want to make the root CA certificate trusted? (yes/y/1/true/t/no/n/0/false/f) (default = {0})' -f $isRootCA)

    if (@('yes', 'y', '1', 'true', 't', '') -contains $acceptRoot) {

      New-Item -Path $regRootCAKey -ItemType Key -Force | Out-Null
      Set-ItemProperty -Path $regRootCAKey -Name Blob -Value $rootCert.Export(([Security.Cryptography.X509Certificates.X509ContentType]::SerializedCert))
      Write-Host ('RootCA: trusted    = installed now')
    }
  
  } else {

    Write-Host ('RootCA: trusted    = yes')
  }

  ##
  ##

  [System.Security.Cryptography.X509Certificates.X509Certificate2] $ntauthCert = $downloadedCert

  ##
  ##

  Write-Host ('')
  Write-Host ('NTAuthCA: thumbprint = {0}' -f $ntauthCert.Thumbprint)
  Write-Host ('NTAuthCA: subject    = {0}' -f $ntauthCert.Subject)
  Write-Host ('NTAuthCA: validity   = {0}' -f $ntauthCert.NotAfter.ToString('yyyy-MM-dd'))

  $regNTAuthCAKey = Join-Path HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\NTAuth\Certificates $ntauthCert.Thumbprint
  [Security.Cryptography.X509Certificates.X509Certificate2] $regNTAuthCACert = $null

  if (Test-Path $regNTAuthCAKey) {

    try {

      $regNTAuthCACert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,(Get-ItemProperty $regNTAuthCAKey Blob -ErrorAction SilentlyContinue).Blob)
        
    } catch { $error.Clear() }
  }

  if ($regNTAuthCACert.Thumbprint -ne $ntauthCert.Thumbprint) {

    Write-Host ('')
    [string] $acceptNTAuth = Read-Host ('Do you want to make the downloaded CA certificate NTAuth CA? (yes/y/1/true/t/no/n/0/false/f) (default = {0})' -f ((-not $isDownloadedRootCA) -or ($ntauthCert.Thumbprint -eq $rootCert.Thumbprint)))

    if (@('yes', 'y', '1', 'true', 't', '') -contains $acceptNTAuth) {

      New-Item -Path $regNTAuthCAKey -ItemType Key -Force | Out-Null
      Set-ItemProperty -Path $regNTAuthCAKey -Name Blob -Value $ntauthCert.Export(([Security.Cryptography.X509Certificates.X509ContentType]::SerializedCert))
      Write-Host ('NTAuthCA: trusted    = installed now')
    }
  
  } else {

    Write-Host ('NTAuthCA: trusted    = yes')
  }

  ##
  ##

  $rxHTTPHostName = '(?i)\Ahttp(?:s|)\:\/\/([^\/]+)'
  if ((-not $openFromFile) -and ($pkiDistroUrl -match $rxHTTPHostName)) {

    Write-Host ('')
    [bool] $installCEP = $true
    [string] $installCEPSupplied = Read-Host ('Do you want to install CEP client (yes/y/1/true/t/no/n/0/false/f) (default = {0})' -f $installCEP)

    $installCEP = @('yes', 'y', '1', 'true', 't', '') -contains $installCEPSupplied

    if ($installCEP) {

      [string] $cepURL = 'https://{0}/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP' -f ([regex]::Match($pkiDistroUrl, $rxHTTPHostName).Groups[1].Value)
      [string] $cepURLSupplied = Read-Host ('CEP service URL (default = {0})' -f $cepURL)

      if (-not ([string]::IsNullOrEmpty($cepURLSupplied))) {

        $cepURL = $cepURLSupplied
      }

      [bool] $installCEPReally = $true
      [string] $regPolicyServersKey = 'HKLM:\SOFTWARE\Microsoft\Cryptography\PolicyServers'

      if (Test-Path $regPolicyServersKey) {

        [Microsoft.Win32.RegistryKey[]] $regPolicyServersRegistered = Get-ChildItem $regPolicyServersKey

        if ($regPolicyServersRegistered.Length -gt 0) { foreach ($oneRegPolicyServerRegistered in $regPolicyServersRegistered) {

          if ((-not ([string]::IsNullOrEmpty($oneRegPolicyServerRegistered.GetValue('URL')))) -and (-not ([string]::IsNullOrEmpty($oneRegPolicyServerRegistered.GetValue('PolicyID')))) -and (-not ([string]::IsNullOrEmpty($oneRegPolicyServerRegistered.GetValue('FriendlyName')))) -and ($oneRegPolicyServerRegistered.GetValue('URL') -eq $cepURL)) {

            Write-Host ('')
            Write-Host ('CEP client already installed: {0} | serverID = {1} | policyID = {2}' -f $oneRegPolicyServerRegistered.GetValue('FriendlyName'), $oneRegPolicyServerRegistered.GetValue('Name'), $oneRegPolicyServerRegistered.GetValue('PolicyID'))
            $installCEPReally = $false
          }
        }}

      } else {

        #Write-Host ('')
        #Write-Host ('Create new PolicyServers registry key: {0}' -f $regPolicyServersKey)
        #New-Item $regPolicyServersKey -Force | Out-Null
        #Set-ItemProperty -Path $regPolicyServersKey -Name Flags -Value 0 -Type Dword -Force
      }

      if ($installCEPReally) {

        [string] $cepUserName = 'srv-admin@gopas.virtual'
        [string] $cepPassword = 'Pa$$w0rd'

        [string] $cepUserNameSupplied = Read-Host ('CEP login (default = {0})' -f $cepUserName)
        
        if (-not ([string]::IsNullOrEmpty($cepUserNameSupplied))) {

          $cepUserName = $cepUserNameSupplied.Trim()
        }
        
        [string] $cepPasswordSupplied = (New-Object Management.Automation.PSCredential ('DummyLogin', (Read-Host ('CEP password (default = {0})' -f $cepPassword) -AsSecureString))).GetNetworkCredential().Password

        if (-not ([string]::IsNullOrEmpty($cepPasswordSupplied))) {

          $cepPassword = $cepPasswordSupplied
        }

        ##
        ##

        Write-Host ('')
        Write-Host ('Verify CEP policy server connectivity: {0} | {1}' -f $cepURL, $cepUserName)

        [string[]] $certutilOut = certutil -f -policy -PolicyServer $cepURL -UserName $cepUserName -p $cepPassword | % { $_.Trim() } | ? { -not ([string]::IsNullOrEmpty($_)) }
        
        Write-Host ('')
        Write-Host ("CERTUTIL output: -->`r`n{0}" -f ($certutilOut | Out-String))

        if ($LASTEXITCODE -ne 0) { throw ('Error checking CEP connection with CERTUTIL: {0} = 0x{1:X8}' -f $LASTEXITCODE, $LASTEXITCODE) }

        ##
        ##

        Write-Host ('')
        Write-Host ('Register the CEP policy server: {0} | {1}' -f $cepURL, $cepUserName)

        [System.Management.Automation.CmdletInfo] $cmdletExists = $null
        try { $cmdletExists = Get-Command Add-CertificateEnrollmentPolicyServer -ErrorAction SilentlyContinue } catch { $error.Clear() }
        
        if (-not ([object]::Equals($cmdletExists, $null))) {
        
          $cepCred = New-Object Management.Automation.PSCredential ($cepUserName, (ConvertTo-SecureString $cepPassword -AsPlainText -Force))
          $cepRegistrationResult = Add-CertificateEnrollmentPolicyServer -Url $cepURL -Context Machine -AutoEnrollmentEnabled:$false -Credential $cepCred
        
          Write-Host ('CEP policy ID: {0}' -f $cepRegistrationResult.Id)
          Write-Host ('CEP URL:       {0}' -f $cepRegistrationResult.Url)

        } else {
        
          Write-Host ('The cmdlet Add-CertificateEnrollmentPolicyServer is not available, will use the COM/registry method')
          Install-CEPClient -url $cepURL -login $cepUserName -password $cepPassword -reinstall:$false
        }

        ##
        ##

        Write-Host ('')
        Write-Host ('Flush CEP policy caches')

        [string[]] $certutilOut = certutil -f -PolicyServer * -PolicyCache delete | % { $_.Trim() } | ? { -not ([string]::IsNullOrEmpty($_)) }
        
        Write-Host ('')
        Write-Host ("CERTUTIL output: -->`r`n{0}" -f ($certutilOut | Out-String))

        if ($LASTEXITCODE -ne 0) { throw ('Error flushing CEP policy caches with CERTUTIL: {0} = 0x{1:X8}' -f $LASTEXITCODE, $LASTEXITCODE) }

        ##
        ##

        Write-Host ('')
        Write-Host ('Refresh CEP policy cache finally')

        [string[]] $certutilOut = certutil -f -policy -PolicyServer $cepURL -UserName $cepUserName -p $cepPassword | % { $_.Trim() } | ? { -not ([string]::IsNullOrEmpty($_)) }
        
        Write-Host ('')
        Write-Host ("CERTUTIL output: -->`r`n{0}" -f ($certutilOut | Out-String))

        if ($LASTEXITCODE -ne 0) { throw ('Error updating CEP policy cache with CERTUTIL: {0} = 0x{1:X8}' -f $LASTEXITCODE, $LASTEXITCODE) }

        ##
        ## 

        # Note: yes, after installing/refreshing the CEP client the basic credentials remain in memory until logoff
        Read-Host ('Press ENTER to FLUSH CEP CREDENTIALS from MEMORY') | Out-Null
        [string] $cepFlushPS1 = Join-Path $thisFolder 'templates-ceps-ces-refresh-pulse.ps1'

        if (-not (Test-Path $cepFlushPS1)) { throw ('Cannot find the CEP CACHE FLUSH script file: {0}' -f $cepFlushPS1) }

        & $cepFlushPS1
      }
    }
  }
}

catch {

  Write-Host ('')
  Write-Host ('Error: {0}' -f $_) -ForegroundColor Red
}

finally {

}

Write-Host ('')
Read-Host ('Press ENTER to exit') | Out-Null


# SIG # Begin signature block
# MIIfJQYJKoZIhvcNAQcCoIIfFjCCHxICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC7Jh8/pWkihLur
# G46UvQJuDq3QIuA3pmfSombsNya7k6CCGSswggWNMIIEdaADAgECAhAOmxiO+dAt
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
# BCASAeAtZScpEnM20vbxWBNuv7nb1qoy6N/yvdSjKFRcAjANBgkqhkiG9w0BAQEF
# AASCAQAVL6WLp1rkuIXq1inDcLP1QU/fIWb2mopb9OzfXv3U1uG3PuT4d/QUOHnm
# VwFDEWTu7rCSB8vMPz5UREbMf80gjvuBd5pbwuGdgFhHq/2V71QWj/cCr5oC0oTf
# npEeJ+IvSPm00mUZskXKtdSNvjg084SglaKK+P2jL3cKzmLH5KfuKWTgupVQViw8
# Wse9yPfCQDWMLfoenn209T2hZojnm+1MSeQmyz7lM+/lr61vJWvfpvIb6QhgJeU3
# Yqjm5IdB4cRzitbTkBjJbBj+N8qwplvkYzlM+JIDs05eOIOKYfpnVRUrei+vm3YS
# SCSBD+T/ZWxkyxeX3Anw97J+BGoKoYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJ
# AgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTsw
# OQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVT
# dGFtcGluZyBDQQIQC65mvFq6f5WHxvnpBOMzBDANBglghkgBZQMEAgEFAKBpMBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI0MTAxNTE0
# MzQwNlowLwYJKoZIhvcNAQkEMSIEIFPwl+OUo3oT1QPtsKFZH0lhllasom0t8DZH
# Edwv8KdzMA0GCSqGSIb3DQEBAQUABIICAGBO3zFDx7njMy8X/M93v/iK989HN2kk
# PSOdZt0+b1enItf5HzepmCGxv/Cbj1gOWVyDiFjc8fy2pJZ7YuqGvk+pliv0mGC2
# JoqdUi61WGEumO16toTPikihQt+XCXGtikq/nFRKvmft5Pe0cNa9Ot71DQgOZFU5
# BOiEbcvkm/Eo8fb8eAs+G2+Mgq74bmxQP9h9TS+trNhurPNGzDeAZd3BlcukHwe2
# 08FFubmc+Oj4HHdycYEE1ZkjQ+ifzhHj+RbMYWviIGtNV2ZfYG3c/Oe9W90vpMpR
# 2FILBm2nIVkviAAnPmEt4SyUr+3MQh7IypBd4+deXCuiu0Bpf1Sp+HISYqihG4IX
# W1KGoi99ao8hBTHcPdN85kqgu0+ShrkAuXiM2jSdMsoYtiS2uTWWNQeYNfdecdwD
# 9KIWuoZbtuvNeBF9o0uPCKR4WVk6bMFKYGn74eniboaOjy/0Bc0rz/37Ed4rsunX
# PYmF+f7DWfl+pG7H4wjA2HYpS1Xctk8w84OIx3u+1ZXsOAIDc2Mzn+LymskkVzdn
# goVuAauent5YxomEUS1mPqllJmI/YQJ50oz02KaI4Ahd9is3vUjEvXxz2HNjE/g6
# W7qHA5x4CZCBUNGDIqZQJa1CW/1Uhne3oQ0y3lNRCSMOucVJ0kKpM/NVEE3O0gkC
# jssJZQIi3IHH
# SIG # End signature block

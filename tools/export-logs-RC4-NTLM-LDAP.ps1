
param(
  [switch] $automatic,
  [int] $queryLastHours = 144,
  [string] $querySet = 'rc4Logons',
  [string] $delimiter = "`t",
  [string] $outputFolderName
  )

$global:ErrorActionPreference = [Management.Automation.ActionPreference]::Continue
$error.Clear()

##
##

[string] $scriptFile = $MyInvocation.MyCommand.Definition
[string] $scriptFileName = $null
[string] $scriptFolder = $null

if ((-not ([string]::IsNullOrEmpty($scriptFile))) -and (Test-Path $scriptFile)) {

  $scriptFileName = [IO.Path]::GetFileNameWithoutExtension($scriptFile)
  $scriptFolder = Split-Path -Parent $scriptFile

} else {

  $scriptFile = $null
  $scriptFileName = $null
  $scriptFolder = $null
}

##
##

$localhostDCOnly = $false
[int] $lastHours = $queryLastHours

if (-not $automatic) {

  Write-Host ('')
  [string] $lastHoursSpecified = Read-Host ('Number of hours backwards to obtain the logs (default = {0})' -f $lastHours)

  if (-not ([string]::IsNullOrEmpty($lastHoursSpecified))) {

    $lastHours = [int] $lastHoursSpecified
  }
}

[int] $lastHoursMilSec = $lastHours * (3600 * 1000)

##
##

[string] $outFolder = $outputFolderName
if ([string]::IsNullOrEmpty($outFolder)) {

  $baseOutputFolderName = 'parsed-log-files'
  $outFolder = Join-Path $env:TEMP $baseOutputFolderName

  if (-not ([string]::IsNullOrEmpty($scriptFolder))) {

    $outFolder = Join-Path $scriptFolder $baseOutputFolderName

    $rxNameVersion = '(?i)\-v\d+\Z'
    if ($scriptFileName -match $rxNameVersion) {

      $outFolder = '{0}{1}' -f $outFolder, ([regex]::Match($scriptFileName, $rxNameVersion).Value)
    }
  }

  $outFolder = '{0}-{1}-{2}hours' -f $outFolder, (Get-Date).ToString('yyyyMMdd-HHmmss'), $lastHours

} else {

  if (-not ([IO.Path]::IsPathRooted($outFolder))) {

    if (-not ([string]::IsNullOrEmpty($scriptFolder))) {
  
      $outFolder = Join-Path $scriptFolder $outFolder

    } else {

      $outFolder = Join-Path $env:TEMP $outFolder
    }
  }
}

##
##

Write-Host ('')
Write-Host ('Script file: {0}' -f $scriptFile)
Write-Host ('Script folder: {0}' -f $scriptFolder)
Write-Host ('Output folder: {0}' -f $outFolder)
Write-Host ('Last hours: {0} hours | {1} milliseconds' -f $lastHours, $lastHoursMilSec)

if (Test-Path $outFolder) {

  Get-ChildItem $outFolder -Force -Recurse | select -Expand FullName | sort -Descending | % { Remove-Item $_ -Recurse -Force }
}

if (-not (Test-Path $outFolder)) {

  New-Item -Path $outFolder -ItemType Directory -Force | Out-Null
}

##
##

[hashtable] $dnsTranslates = @{}

function Translate-IPv4ToHostName ([string] $possibleIPv4)
{
  [string] $result = $possibleIPv4

  if ($possibleIPv4 -match '\A\d+\.\d+\.\d+\.\d+\Z') {

    if ($dnsTranslates.Keys -contains $possibleIPv4) {
    
      $result = $dnsTranslates[$possibleIPv4]

    } else {    
  
      [string] $translated = $null
      try { $translated = ([Net.Dns]::Resolve($possibleIPv4) | select -Expand HostName | ? { (-not ([string]::IsNullOrEmpty($_))) -and ($_ -ne $possibleIPv4) } | select -First 1) -replace '\..*', '' } catch { $error.Clear() }

      if (-not ([string]::IsNullOrEmpty($translated))) {

        [void] $dnsTranslates.Add($possibleIPv4.ToLower(), $translated)
        $result = $translated
      
      } else {

        [void] $dnsTranslates.Add($possibleIPv4.ToLower(), $result)
      }
    }
  }

  return $result
}

function global:Count-FileLines ([string] $file)
{
  [int] $lineCount = 0
  [System.IO.FileStream] $openedFile = $null
  
  try {
  
    $openedFile = New-Object System.IO.FileStream $file, ([System.IO.FileMode]::Open)

    [bool] $lastHitNewLine = $false

    do {  
  
      [int] $byte = $openedFile.ReadByte()

      if ($byte -eq 10) { 
      
        $lineCount ++
        $lastHitNewLine = $true
      
      } else {

        $lastHitNewLine = $false
      }

    } while ($byte -ge 0)

    if (-not $lastHitNewLine) { $lineCount ++ }

  } finally {

    if (-not ([object]::Equals($openedFile, $null))) {

      $openedFile.Close()
      $openedFile.Dispose()
    }
  } 

  return $lineCount
}

##
##

# Note: the XML queries used directly by WEVTUTIL must use only single quotes (') and not double quotes (")
# Note: 9007199254740992 = 0x0020000000000000 = Audit Success

[hashtable] $queryLibrary = @{

  'userFromComputer' = 
    
    [hashtable] @{
      '11-kerberos-tgt|Security' =                @{ query = "*[System[Task=14339 and (band(Keywords,9007199254740992)) and TimeCreated[timediff(@SystemTime)<=$lastHoursMilSec]]]";                                                                                                                                 results = 'Event/EventData/Data[@Name="TargetUserName" or @Name="IpAddress"]';                         names = @('user', 'from', 'display');   exec = @($null, { (Translate-IPv4ToHostName (($theValue -replace '\A\:\:ffff\:', '') -replace '\A\:\:1\Z', $theDC)) }, { $global:userLoginsBySAM[$newEvent.user].display });  conditions = @( { $global:computerLoginsBySAM.Keys -notcontains $theValue }, $null); }
      '12-ntlm-credentials-validation|Security' = @{ query = "*[System[Task=14336 and (band(Keywords,9007199254740992)) and TimeCreated[timediff(@SystemTime)<=$lastHoursMilSec]] and EventData/Data[@Name='PackageName']='MICROSOFT_AUTHENTICATION_PACKAGE_V1_0']";                                                 results = 'Event/EventData/Data[@Name="TargetUserName" or @Name="Workstation"]';                       names = @('user', 'from', 'display');   exec = @($null, $null, { $global:userLoginsBySAM[$newEvent.user].display });                                                                                                  conditions = @( { $global:computerLoginsBySAM.Keys -notcontains $theValue }, $null); }
      '99-wrap-final' =                           @{ key = 'user'; columns = @('display', 'from'); delimiter = ',' }
    }

  'rc4Logons' = 

    [hashtable] @{
      '11-ntlm-credentials-validation|Security' =            @{ query = "*[System[Task=14336 and (band(Keywords,9007199254740992)) and TimeCreated[timediff(@SystemTime)<=$lastHoursMilSec]] and EventData/Data[@Name='PackageName']='MICROSOFT_AUTHENTICATION_PACKAGE_V1_0']";                                      results = 'Event/EventData/Data[@Name="TargetUserName" or @Name="Workstation"]';                       names = @('user', 'from');              exec = @($null, $null);                                                                                                  conditions = @($null, $null); }
      '12-kerberos-tgt-rc4|Security' =                       @{ query = "*[System[Task=14339 and (band(Keywords,9007199254740992)) and TimeCreated[timediff(@SystemTime)<=$lastHoursMilSec]] and (EventData/Data[@Name='TicketEncryptionType']='0x17' or EventData/Data[@Name='SessionKeyEncryptionType']='0x17')]"; results = 'Event/EventData/Data[@Name="TargetUserName" or @Name="IpAddress"]';                         names = @('user', 'from');              exec = @($null, { (Translate-IPv4ToHostName (($theValue -replace '\A\:\:ffff\:', '') -replace '\A\:\:1\Z', $theDC)) });  conditions = @($null, $null); }
      '13-kerberos-tgs-rc4|Security' =                       @{ query = "*[System[Task=14337 and (band(Keywords,9007199254740992)) and TimeCreated[timediff(@SystemTime)<=$lastHoursMilSec]] and (EventData/Data[@Name='TicketEncryptionType']='0x17' or EventData/Data[@Name='SessionKeyEncryptionType']='0x17')]"; results = 'Event/EventData/Data[@Name="ServiceName" or @Name="IpAddress"]';                            names = @('service', 'from');           exec = @($null, { (Translate-IPv4ToHostName (($theValue -replace '\A\:\:ffff\:', '') -replace '\A\:\:1\Z', $theDC)) });  conditions = @($null, $null); } 
      '21-nltm-servers|Microsoft-Windows-NTLM/Operational' = @{ query = "*[System[EventID=8004 and TimeCreated[timediff(@SystemTime)<=$lastHoursMilSec]]]";                                                                                                                                                          results = 'Event/EventData/Data[@Name="SChannelName" or @Name="UserName" or @Name="WorkstationName"]'; names = @('server', 'account', 'from'); exec = @($null, $null, $null);                                                                                           conditions = @($null, $null); }
      '31-nltm-to-dc|Microsoft-Windows-NTLM/Operational' =   @{ query = "*[System[EventID=8002 and TimeCreated[timediff(@SystemTime)<=$lastHoursMilSec]]]";                                                                                                                                                          results = 'Event/EventData/Data[@Name="ClientUserName"]';                                              names = @('account');                   exec = @($null);                                                                                                         conditions = @($null, $null); }
      '41-ldap-simple-bind|Directory Service' =              @{ query = "*[System[EventID=2889 and TimeCreated[timediff(@SystemTime)<=$lastHoursMilSec]]]";                                                                                                                                                          results = 'Event/EventData/Data';                                                                      names = @('from', 'account');           exec = @({ $theValue -replace '\:\d+\Z', '' }, $null);                                                                   conditions = @($null, $null); }
    }
}

##
##

Write-Host ('')
Write-Host ('Queries available: #{0}' -f $queryLibrary.Count)

if ($queryLibrary.Count -gt 0) { foreach ($oneQueryLibrary in $queryLibrary.Keys) {

Write-Host ('                   {0}' -f $oneQueryLibrary)
}}

Write-Host ('')
[string] $querySelected = $querySet #([string[]] $queryLibrary.Keys)[0]

if (-not $automatic) {
  
  do {

    [string] $querySelectedSupplied = Read-Host ('Which query set do you want to use (default = {0})' -f $querySelected)

    if (-not ([string]::IsNullOrEmpty($querySelectedSupplied))) {

      $querySelected = $querySelectedSupplied.Trim()
    }

  } while ($queryLibrary.Keys -notcontains $querySelected)
}
 
$queries = $queryLibrary[$querySelected]
  
##
##

[Collections.ArrayList] $dcs = @()
[string] $localhostDC = $null

try { $localhostDC = Get-ADDomainController -Server localhost | select -Expand Name } catch {}

if (-not ([string]::IsNullOrEmpty($localhostDC))) {

  [void] $dcs.Add($localhostDC)
}

if (-not $localhostDCOnly) {

  Get-ADDomainController -Filter * | sort HostName | select -Expand Name | ? { $dcs -notcontains $_ } | % { [void] $dcs.Add($_) }
}

if (-not $automatic) {

  Write-Host ('')
  [string] $dcsSupplied = Read-Host ('Obtain logs from DCs (default = {0})' -f ($dcs -join ', '))

  if (-not ([string]::IsNullOrEmpty($dcsSupplied))) {

    $dcs = [string[]] ($dcsSupplied -split '\s|;|,|\|' | ? { -not ([string]::IsNullOrEmpty($_)) })
  }

  [string] $dcsExcludedSupplied = Read-Host ('Exclude some DCs, use wildcards if necessary')

  if (-not ([string]::IsNullOrEmpty($dcsExcludedSupplied))) { 

    [Collections.ArrayList] $dcsNotExcluded = @()

    if ($dcs.Count -gt 0) { foreach ($oneDC in $dcs) {
  
      [bool] $excludeThisOne = $false
      foreach ($oneDCExcludedSupplied in $dcsExcludedSupplied) {

        if ($oneDC -like $oneDCExcludedSupplied) {

          $excludeThisOne = $true
          break
        }
      }

      if (-not $excludeThisOne) {

        [void] $dcsNotExcluded.Add($oneDC)
      }
    }}

    $dcs = $dcsNotExcluded
  }
}

[string] $globalCatalog = $null
$globalCatalog = $dcs | % { Get-ADDomainController -Identity $_ } | ? { $_.IsGlobalCatalog } | select -First 1 | select -Expand Name

Write-Host ('')
Write-Host ('Query set loaded: {0}' -f $querySelected)
Write-Host ('Will process logs from the following DCs: {0}' -f ($dcs -join ', '))
Write-Host ('Global catalog determined: {0}' -f $globalCatalog)

if (-not $automatic) {

  Write-Host ('')
  Read-Host ('Press ENTER to start downloading the logs') | Out-Null
}

##
##

Write-Host ('')
Write-Host ('Obtain computer, user and service logins from the AD first')

[hashtable] $global:userLoginsBySAM = @{}
[hashtable] $global:userLoginsByUPN = @{}
[hashtable] $global:computerLoginsBySAM = @{}
[hashtable] $global:computerLoginsByFQDN = @{}
[hashtable] $global:svcLoginsBySAM = @{}

function global:Insert-AccountHash ([ref] $rfHash, [string] $key, [PSObject] $object)
{
  if (-not ([string]::IsNullOrEmpty($key))) {

    [hashtable] $hash = $rfHash.Value

    if ($hash.Keys -notcontains $key) {

      $newDNList = New-Object System.Collections.ArrayList
      [void] $newDNList.Add($object)
      [void] $hash.Add($key, $newDNList)

    } else {

      [void] $hash[$key].Add($object)
    }
  }
}

Get-ADObject -LDAPFilter '(objectCategory=computer)' -Server ('{0}:3268' -f $globalCatalog) -Properties sAMAccountName, dNSHostName | % {

    Insert-AccountHash -rfHash ([ref] $computerLoginsBySAM) -key $_.sAMAccountName -object @{ dn = $_.DistinguishedName; dns = $_.dNSHostName }
    Insert-AccountHash -rfHash ([ref] $computerLoginsByFQDN) -key $_.dNSHostName -object @{ dn = $_.DistinguishedName; dns = $_.dNSHostName }
  }

Write-Host ('Computers by SAM: #{0}' -f $computerLoginsBySAM.Count)
Write-Host ('Computers by DNS: #{0}' -f $computerLoginsByFQDN.Count)

Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user))' -Server ('{0}:3268' -f $globalCatalog) -Properties sAMAccountName, userPrincipalName, displayName | % {

    Insert-AccountHash -rfHash ([ref] $userLoginsBySAM) -key $_.sAMAccountName -object @{ dn = $_.DistinguishedName; display = $_.displayName }
    Insert-AccountHash -rfHash ([ref] $userLoginsByUPN) -key $_.userPrincipalName -object @{ dn = $_.DistinguishedName; display = $_.displayName }
  }

Write-Host ('Users by SAM:     #{0}' -f $userLoginsBySAM.Count)
Write-Host ('Users by UPN:     #{0}' -f $userLoginsByUPN.Count)

Get-ADObject -LDAPFilter '(|(objectCategory=msDS-GroupManagedServiceAccount)(objectCategory=msDS-ManagedServiceAccount))' -Server ('{0}:3268' -f $globalCatalog) -Properties sAMAccountName | % {

    Insert-AccountHash -rfHash ([ref] $svcLoginsBySAM) -key $_.sAMAccountName -object @{ dn = $_.DistinguishedName }
  }

Write-Host ('Services by SAM:  #{0}' -f $svcLoginsBySAM.Count)

##
##

[Collections.ArrayList] $finalCSVs = @()

Write-Host ('')
foreach ($oneQuery in ($queries.Keys | sort)) {

  if ($oneQuery -eq '99-wrap-final') {

    continue
  }

  [string] $queryId = $oneQuery.Substring(0, $oneQuery.IndexOf('|'))
  [string] $oneLogToQuery = $oneQuery.Substring(($oneQuery.IndexOf('|') + 1))

  [string] $oneXmlQuery = $queries[$oneQuery].query
  [string] $oneSelectValues = $queries[$oneQuery].results
  [string[]] $oneColumnList = $queries[$oneQuery].names
  [ScriptBlock[]] $oneExecuteList = $queries[$oneQuery].exec
  [ScriptBlock[]] $oneConditionList = $queries[$oneQuery].conditions

  if ($queryId -notmatch '\A\d+') {

    if (-not $automatic) {
    
      Read-Host ('Do you want to proceed with a disabled event query: {0}' -f $oneQuery) | Out-Null
    
    } else {

      continue
    }
  }

  ##
  ##

  Write-Host ('Load from DCs: #{0} | {1}' -f $dcs.Count, ($dcs -join ', '))
  if ($dcs.Count -gt 0) {

    foreach ($oneDC in $dcs) {

      Write-Host ('')
      Write-Host ('Obtain: {0} | dc = {1} | {2} | {3}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $oneDC, $queryId, $oneLogToQuery)
      Write-Host ('        {0}' -f $oneXmlQuery)
      Write-Host ('        {0}' -f $oneSelectValues)
      Write-Host ('        {0}' -f ($oneColumnList -join ','))

      [Collections.ArrayList] $events = @()
      [hashtable] $newestEvents = @{}

      $rawEventFile = Join-Path $outFolder ('{0}_raw.txt' -f (('{0}_{1}_{2}_{3}' -f $queryId, $oneDC, $oneLogToQuery, (Get-Date).ToString('yyyy-MM-dd-HH-mm-ss')) -replace '\s+|\.+|\\+|\/+', '-'))
      if (Test-Path $rawEventFile) { Remove-Item $rawEventFile }

      Write-Host ('')
      Write-Host ('Raw event file: {0}' -f $rawEventFile)

      $dtStart = Get-Date
      # Note: WEVTUTIL since 2022 sometimes returns results in the form of a single line which contains more <Event> elements
      #       that is the reason why we use the bookmark file since then
      wevtutil qe $oneLogToQuery /f:XML /r:$oneDC /q:$oneXmlQuery > $rawEventFile
      $dtEnd = Get-Date
      Write-Host ('WEVTUTIL took: {0:N1} min' -f (($dtEnd - $dtStart).TotalMinutes))

      ##
      ##

      [int] $eventLines = Count-FileLines -file $rawEventFile
      Write-Host ('Reload the events from XML: lines = #{0}' -f $eventLines)
      #Write-Host ('Reload the events from XML')

      $evNumber = 0
      $dtStart = Get-Date

      & { 
      
        BEGIN { 
        
          $reader = New-Object System.IO.StreamReader($rawEventFile)
          $oneEvent = New-Object Text.StringBuilder
        } 
      
        PROCESS { 
        
          while (-not $reader.EndOfStream) { 
        
            [void] $oneEvent.Append(([char] $reader.Read()))

            if ($oneEvent.ToString() -match '</Event\s*\>\Z') {

              Write-Output ($oneEvent.ToString())
              $oneEvent = New-Object Text.StringBuilder
            }
          } 
        } 
      
        END { $reader.Close(); $reader.Dispose(); $reader = $null }
      
      } | % { 

        $eventStr = $_.Replace('http://schemas.microsoft.com/win/2004/08/events/event', '') -replace '(?i)xmlns\s*\=\s*[\''\"]{2}', ''
        $xmlEvent = $null
        $xmlEvent = ([XML] $eventStr)
        
        if (-not ([object]::Equals($xmlEvent, $null))) {

          [object[]] $eventValues = $xmlEvent.SelectNodes($oneSelectValues) | % { [string] $_.'#text' }
          [string] $eventLogged = $xmlEvent.SelectSingleNode('Event/System/TimeCreated[@SystemTime]').SystemTime

          $newEvent = New-Object PSObject
          #Add-Member -Input $newEvent -MemberType NoteProperty -Name dc -Value $oneDC
          Add-Member -Input $newEvent -MemberType NoteProperty -Name when -Value ([DateTime]::Parse($eventLogged)).ToString('s')

          [bool] $conditionsOK = $true
          $eventHash = New-Object Text.StringBuilder
          for ($i = 0; $i -lt $oneColumnList.Length; $i ++) {

            [string] $theValue = $eventValues[$i]
            [string] $theDC = $oneDC

            if (-not ([object]::Equals($oneExecuteList[$i], $null))) {

              $theValue = Invoke-Command $oneExecuteList[$i]
            }

            if (-not ([object]::Equals($oneConditionList[$i], $null))) {

              $conditionsOK = $conditionsOK -and (Invoke-Command $oneConditionList[$i])
            }

            Add-Member -Input $newEvent -MemberType NoteProperty -Name $oneColumnList[$i] -Value $theValue
            [void] $eventHash.Append(('{{{0}:{1}}}' -f $oneColumnList[$i], $theValue))
          }

          if ($conditionsOK) {

            [void] $events.Add($newEvent)
        
            if ($newestEvents.Keys -contains $eventHash.ToString()) {

              if ($newestEvents[$eventHash.ToString()].when -lt $newEvent.when) {

                $newestEvents[$eventHash.ToString()] = $newEvent
              }

            } else {

              [void] $newestEvents.Add($eventHash.ToString(), $newEvent)
            }
          }
        
        } else {

          break
        }

        $evNumber ++
        if (($evNumber % 1000) -eq 0) { 
        
          #Write-Host ('Progress at: #{0,6:D} of {1} ({2,3:D} %) after {3:N1} min' -f $evNumber, $eventLines, ($evNumber / $eventLines * 100), ((([DateTime]::Now) - $dtStart).TotalMinutes))
          Write-Host ('Progress at: #{0,6:D} after {1:N1} min' -f $evNumber, ((([DateTime]::Now) - $dtStart).TotalMinutes))
        }
      }
      
      $csvFile = Join-Path $outFolder ('{0}.csv' -f (('{0}_{1}_{2}_{3}' -f $queryId, $oneDC, $oneLogToQuery, (Get-Date).ToString('yyyy-MM-dd-HH-mm-ss')) -replace '\s+|\.+|\\+|\/+', '-'))
      $csvFileNewest = Join-Path $outFolder ('{0}.csv' -f (('{0}_{1}_{2}_{3}_newest' -f $queryId, $oneDC, $oneLogToQuery, (Get-Date).ToString('yyyy-MM-dd-HH-mm-ss')) -replace '\s+|\.+|\\+|\/+', '-'))
      
      #$eventsUnique = $events | select -Unique $oneColumnList | sort $oneColumnList[0]
      #$eventsUnique | Export-Csv -Path $csvFile -Encoding UTF8 -Delimiter $delimiter -NoTypeInformation -Force
    
      $events | sort $oneColumnList[0] | Export-Csv -Path $csvFile -Encoding UTF8 -Delimiter $delimiter -NoTypeInformation -Force
      $newestEvents.Values | sort when | Export-Csv -Path $csvFileNewest -Encoding UTF8 -Delimiter $delimiter -NoTypeInformation -Force

      Write-Host ("Obtained: allEvents = {0} | {1}" -f $evNumber, $csvFile)

      $dtEnd = Get-Date
      Write-Host ('XML parsing took: {0:N1} min' -f (($dtEnd - $dtStart).TotalMinutes))
    }
  }

  ##
  ##

  Write-Host ('')

  [string[]] $queryOutputs = Get-ChildItem $outFolder -Force -Recurse | ? { $_.Name -like ('{0}_?*_newest.csv' -f $queryId) } | select -Expand FullName | sort
  Write-Host ('Reparse again: #{0} | {1}' -f $queryOutputs.Length, $queryId)

  if ($queryOutputs.Length -gt 0) {

    [Collections.ArrayList] $queryStats = @()
    foreach ($oneQueryOutput in $queryOutputs) {

      Import-Csv $oneQueryOutput -Encoding UTF8 -Delimiter $delimiter | % { [void] $queryStats.Add($_) }
    }

    $csvFile = Join-Path $outFolder ('{0}.csv' -f (('final_{0}_{1}' -f $queryId, $oneLogToQuery, (Get-Date).ToString('yyyy-MM-dd-HH-mm-ss')) -replace '\s+|\.+|\\+|\/+', '-'))
      
    [Collections.ArrayList] $eventsUnique = @()
    $queryStats | select -Unique $oneColumnList | sort $oneColumnList[0] | % { [void] $eventsUnique.Add($_) }
    $eventsUnique | Export-Csv -Path $csvFile -Encoding UTF8 -Delimiter $delimiter -NoTypeInformation -Force
    
    Write-Host ("Reparsed: uniqueEvents = #{0} | {1} | -->`r`n{2}" -f $eventsUnique.Count, $csvFile, ($eventsUnique | ft -Auto | Out-String))
    [void] $finalCSVs.Add($csvFile)

  } else {

    Write-Host ('Reparsed: uniqueEvents = #0')
  }
}

##
##

if (($queries.Keys -contains '99-wrap-final') -and ($finalCSVs.Count -gt 0)) {

  Write-Host ('')
  Write-Host ('Recombine all final CSVs: #{0}' -f $finalCSVs.Count)

  [string] $combineKeyColumn = $queries['99-wrap-final'].key
  [string[]] $combineColumns = $queries['99-wrap-final'].columns
  [string] $combineDelimiter = $queries['99-wrap-final'].delimiter

  [hashtable] $combinedInfos = @{}

  if ($finalCSVs.Count -gt 0) { foreach ($oneFinalCSV in $finalCSVs) {

    Write-Host ('                          {0}' -f $oneFinalCSV)
    [object[]] $finalInfos = Import-Csv $oneFinalCSV -Encoding UTF8 -Delimiter $delimiter
    Write-Host ('                          items = #{0}' -f $finalInfos.Length)

    if ($finalInfos.Length -gt 0) { foreach ($oneFinalInfo in $finalInfos) {

      [PSObject] $combinedItem = $null

      if ($combinedInfos.Keys -contains $oneFinalInfo.$combineKeyColumn) {

        $combinedItem = $combinedInfos[$oneFinalInfo.$combineKeyColumn]

      } else {

        $combinedItem = New-Object PSObject
        Add-Member -Input $combinedItem -MemberType NoteProperty -Name $combineKeyColumn -Value $oneFinalInfo.$combineKeyColumn

        if ($combineColumns.Length -gt 0) { foreach ($oneCombineColumn in $combineColumns) {

          Add-Member -Input $combinedItem -MemberType NoteProperty -Name $oneCombineColumn -Value ([string] '')
        }}

        [void] $combinedInfos.Add($oneFinalInfo.$combineKeyColumn, $combinedItem)
      }

      if ($combineColumns.Length -gt 0) { foreach ($oneCombineColumn in $combineColumns) {

        $combinedItem.$oneCombineColumn = ((([string[]] $combinedItem.$oneCombineColumn.Split($combineDelimiter)) + ([string] $oneFinalInfo.$oneCombineColumn)) | ? { -not ([string]::IsNullOrEmpty($_)) } | sort | select -Unique) -join $combineDelimiter
      }}
    }}
  }}

  Write-Host ('')

  [string] $combinedCSV = Join-Path $outFolder 'combined.csv'
  Write-Host ('Recombined CSV: items = #{0} | {1}' -f $combinedInfos.Count, $combinedCSV)
  $combinedInfos.Values | Export-Csv -Path $combinedCSV -Encoding UTF8 -Delimiter $delimiter -NoTypeInformation -Force
}

##
##

if ($error.Count -gt 0) {

  Write-Host ('')
  Write-Host ('Some errors occured during processing: #{0}' -f $error.Count) -ForegroundColor Red
  foreach ($oneError in $error) {

    Write-Host ('Error: {0}' -f $oneError) -ForegroundColor Red
  }
}

Write-Host ('')
Write-Host ('Finished')
Start-Sleep -Seconds 2

Write-Host ('')
if (-not $automatic) {

  Read-Host ('Press ENTER to exit') | Out-Null
}


# SIG # Begin signature block
# MIIfJQYJKoZIhvcNAQcCoIIfFjCCHxICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDTAeM2TClBGgvA
# 06ByRN4d2b/sQ6O4XG12BwBEMh/3l6CCGSswggWNMIIEdaADAgECAhAOmxiO+dAt
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
# BCCtz+97yj31zwNez/9rEcvLgB5mY4BaprmWb5cb4BmlOzANBgkqhkiG9w0BAQEF
# AASCAQBlBfkTe5W1nDcqau9/IpVKnAKmZWhc5U5hG2aZqv70CziW3M9eEbgWNSKQ
# 0R+mD7D6KUnA4G8z7aJzdMIXd/mFOC3DQyxWtipagM2barYtIgEVgspEQZOhYplV
# RA/6H40PfSosSqWD5RTIYeWzeZjf9iiMK21+Eaj8TjIXaYjFB7RkqxmTZMKi1GDS
# xP81QEkmY4Ogj35OSf2sBKFWXIaLrCNQkD+o5HgQDlGmTUI3M5N9zQEuMUIUiuXM
# BTv7AVc5IQ5eN3JhmX9kHuZXfaR8KwtQYJZ91IYrJAgMHUr1nqvIng1qTHqteJAu
# 6QzajJoaMrSbiAFeF6ECNtMdKYp3oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJ
# AgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTsw
# OQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVT
# dGFtcGluZyBDQQIQC65mvFq6f5WHxvnpBOMzBDANBglghkgBZQMEAgEFAKBpMBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDIyNzE1
# MTAzM1owLwYJKoZIhvcNAQkEMSIEIKkaKK0Rp1rtsp0uXRsHNnPw5VTxadgM6Toz
# TWcfzR8RMA0GCSqGSIb3DQEBAQUABIICAKXXASAbKC3mvht06QQeXSiRINsNdm8b
# fZ4zCu2JGbPKV8XpcQ0k5MzeuYCvrPKyoVniF1BRfMDikGfxU/+IUSORFEuFxj4Z
# ZeKSylCjsuuB727kI0GQU00r6tJQDobwpWN6XII8WFayd1PKy1hdrBcvkzRMbv7E
# vvcLKSh2LY2T97NSf7cyKOqJ7IGpRUcZBxOPh7WT1fBqL5+BMBboIpmYD78Sdrl+
# M3E/QzjavZowPGl0xDFgpn7qVvZ2Aj8l2TeeX8Vcnra5q8GBZ/Aly5FXSc0aiYYi
# fEkpQK0NtX8MAcIfhrj0yGHGocYJMI9L12uIovRNmhJmfwDxBs+ibIijJdoYOGDn
# 8RnB0jHTzUxsH3P8pDg2+z/SjdiMfmerjNwA1skK+/I9C6ylrCeD0vImHWDzIFb2
# 2F+6PMTMLZg2PcU7di9zb+YG38RVfG3KWlCaAlPEHxUZV+82i65WCo72uge6cR39
# JODisWUfDJkDcuspMFbnLlMONi1M0rNUsizTlLNksSBwNCWZuWCKQ4/Pti+521CJ
# ZpxL5tNioED8VPlnSqWCexdSaw07llpAglMT1JQpGoaEsW6zAwQYiT2oHMm9cOhZ
# C7Jy+eCcFcijGY+I+KwmXnIWNqwXHhPxPHQVhaoXbMnXHoj/0kHPwdxbCr8W5mUO
# OwYWO/BS1xUG
# SIG # End signature block

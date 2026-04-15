
[string] $domain = 'gopas.virtual'
[string] $gmsa = 'gsvc-*'

##
##

[string] $global:scriptFile = Split-Path -leaf $MyInvocation.MyCommand.Definition
[string] $global:logFile = Join-Path $env:TEMP ('{0}-{1}.txt' -f ([IO.Path]::GetFileNameWithoutExtension($global:scriptFile)), (Get-Date).ToString('yyyyMMddHHmmss'))

function global:Log ([string] $what)
{
  Write-Host ($what)
  if (-not ([string]::IsNullOrEmpty($global:logFile))) {

    ('{0}: {1}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $what) | Out-File $global:logFile -Encoding UTF8 -Append -Force
  }
}

function global:MD4 ([byte[]] $sourceBytes)
{
  # Note: taken from SaphaLib

  $md4Implemented = @'

using System;

namespace Sevecek
{
  public class Bitwise
  {
    public static byte[] ExtractBuffer(byte[] buffer, long offset, long count, bool bigEndian)
    {
      byte[] reversedIfNecessary = new byte[count];

      for (long i = 0; i < count; i++)
      {
        if (bigEndian)
        {
          reversedIfNecessary[i] = buffer[offset + count - i - 1];
        }
        else
        {
          reversedIfNecessary[i] = buffer[offset + i];
        }
      }

      return reversedIfNecessary;
    }

    public static UInt64 LoadUInt64(byte[] data, long offset, bool bigEndian) { UInt64 res = BitConverter.ToUInt64(ExtractBuffer(data, offset, 8, bigEndian), 0); return res; }
    public static UInt32 LoadUInt32(byte[] data, long offset, bool bigEndian) { UInt32 res = BitConverter.ToUInt32(ExtractBuffer(data, offset, 4, bigEndian), 0); return res; }
    public static UInt16 LoadUInt16(byte[] data, long offset, bool bigEndian) { UInt16 res = BitConverter.ToUInt16(ExtractBuffer(data, offset, 2, bigEndian), 0); return res; }
    public static Guid LoadGuid(byte[] data, long offset, bool bigEndian) { Guid res = new Guid(ExtractBuffer(data, offset, 16, bigEndian)); return res; }
    public static DateTime LoadFILETIME(byte[] data, long offset, bool bigEndian) { return DateTime.FromFileTime(checked((long)LoadUInt64(data, offset, bigEndian))); }
    public static byte[] LoadBytes(byte[] data, long offset, long count) { byte[] bytes = new byte[count]; Array.Copy(data, offset, bytes, 0, count); offset += count; return bytes; }

    public static byte ShiftLeft(byte what, int bits) { return (byte)(what << bits); }
    public static byte ShiftRight(byte what, int bits) { return (byte)(what >> bits); }

    public static UInt32 RotateLeft(UInt32 what, int bits)
    {
      return (what << bits) | (what >> (32 - bits));
    }

    public static UInt32 RotateRight(UInt32 what, int bits)
    {
      return (what >> bits) | (what << (32 - bits));
    }
  }

  public class MD4
  {
    // Note: this implements RFC1320

    private static UInt32 AuxF(UInt32 x, UInt32 y, UInt32 z)
    {
      // Note: ... "We first define three auxiliary functions" ...
      return ((x & y) | ((~x) & z));
    }

    private static UInt32 AuxG(UInt32 x, UInt32 y, UInt32 z)
    {
      // Note: ... "We first define three auxiliary functions" ...
      return ((x & y) | (x & z) | (y & z));
    }

    private static UInt32 AuxH(UInt32 x, UInt32 y, UInt32 z)
    {
      // Note: ... "We first define three auxiliary functions" ...
      return (x ^ y ^ z);
    }

    private static void RoundF(ref UInt32 a, ref UInt32 b, ref UInt32 c, ref UInt32 d, UInt32 k, int s, UInt32[] processingBuffer)
    {
      a = Bitwise.RotateLeft((a + AuxF(b, c, d) + processingBuffer[k]), s);
    }

    private static void RoundG(ref UInt32 a, ref UInt32 b, ref UInt32 c, ref UInt32 d, UInt32 k, int s, UInt32[] processingBuffer)
    {
      a = Bitwise.RotateLeft(a + AuxG(b, c, d) + processingBuffer[k] + 0x5A827999, s);
    }

    private static void RoundH(ref UInt32 a, ref UInt32 b, ref UInt32 c, ref UInt32 d, UInt32 k, int s, UInt32[] processingBuffer)
    {
      a = Bitwise.RotateLeft(a + AuxH(b, c, d) + processingBuffer[k] + 0x6ED9EBA1, s);
    }

    public static byte[] Compute(byte[] message)
    {
      // Note: ... "The message is "padded" (extended) so that its length (in bits) is congruent to 448, modulo 512." ...
      int messageLenBit = message.Length * 8;

      int paddedLenBit = (messageLenBit / 512) * 512 + 448;
      if (paddedLenBit <= messageLenBit) { paddedLenBit += 512; }

      // Note: ... "A 64-bit representation of b (the length of the message before the padding bits were added) is appended to the result of the previous step" ...
      byte[] paddedMessage = new byte[(paddedLenBit + 64) / 8];

      Array.Copy(message, 0, paddedMessage, 0, message.Length);
      // Note: ... "a single "1" bit is appended to the message" ...
      // Note: as the RFC defines, a byte is a sequence of bits with the highest order bit going first
      paddedMessage[message.Length] = 0x80;

#if DEBUG
      //Console.WriteLine(String.Format("NetFx: ComputeMD4: message = {0} (#{1} bytes, #{2} bits)", BitConverter.ToString(message), message.Length, messageLenBit));
#endif

      byte[] uint64messageLen = BitConverter.GetBytes((UInt64)messageLenBit);
      Array.Copy(uint64messageLen, 0, paddedMessage, paddedMessage.Length - uint64messageLen.Length, uint64messageLen.Length);

      int paddedMessageWords = paddedMessage.Length / 4;
      int paddedMessage16WordBlocks = paddedMessageWords / 16;

#if DEBUG
      //Console.WriteLine(String.Format("NetFx: ComputeMD4: paddedFull = {0} (#{1}, #{2} in 32bit words, #{3} in 16 word blocks)", BitConverter.ToString(paddedMessage), paddedMessage.Length, paddedMessageWords, paddedMessage16WordBlocks));
#endif

      // Note: ... "These registers are initialized to the following values in hexadecimal" ...
      UInt32 regA = 0x67452301;
      UInt32 regB = 0xEFCDAB89;
      UInt32 regC = 0x98BADCFE;
      UInt32 regD = 0x10325476;

      UInt32[] processingBuffer = new UInt32[16];

      // Note: ... "Process each 16-word block" ...
      for (int i = 0; i < paddedMessage16WordBlocks; i++)
      {
        for (int j = 0; j < 16; j++)
        {
          processingBuffer[j] = Bitwise.LoadUInt32(paddedMessage, (i * 16 + j) * 4, false);
        }

#if DEBUG
        StringBuilder dbgProcessingBufferStr = new StringBuilder();
        for (int k = 0; k < processingBuffer.Length; k++)
        {
          if (k > 0)
          {
            dbgProcessingBufferStr.Append(" | ");
          }

          dbgProcessingBufferStr.Append(BitConverter.ToString(BitConverter.GetBytes(processingBuffer[k])));
        }
        //Console.WriteLine(String.Format("NetFx: ComputeMD4: processingBuffer = {0}", dbgProcessingBufferStr.ToString()));
#endif

        UInt32 saveA = regA;
        UInt32 saveB = regB;
        UInt32 saveC = regC;
        UInt32 saveD = regD;

        //
        // Note: ... "Round 1" ...

        RoundF(ref regA, ref regB, ref regC, ref regD, 0, 3, processingBuffer);
        RoundF(ref regD, ref regA, ref regB, ref regC, 1, 7, processingBuffer);
        RoundF(ref regC, ref regD, ref regA, ref regB, 2, 11, processingBuffer);
        RoundF(ref regB, ref regC, ref regD, ref regA, 3, 19, processingBuffer);

        RoundF(ref regA, ref regB, ref regC, ref regD, 4, 3, processingBuffer);
        RoundF(ref regD, ref regA, ref regB, ref regC, 5, 7, processingBuffer);
        RoundF(ref regC, ref regD, ref regA, ref regB, 6, 11, processingBuffer);
        RoundF(ref regB, ref regC, ref regD, ref regA, 7, 19, processingBuffer);

        RoundF(ref regA, ref regB, ref regC, ref regD, 8, 3, processingBuffer);
        RoundF(ref regD, ref regA, ref regB, ref regC, 9, 7, processingBuffer);
        RoundF(ref regC, ref regD, ref regA, ref regB, 10, 11, processingBuffer);
        RoundF(ref regB, ref regC, ref regD, ref regA, 11, 19, processingBuffer);

        RoundF(ref regA, ref regB, ref regC, ref regD, 12, 3, processingBuffer);
        RoundF(ref regD, ref regA, ref regB, ref regC, 13, 7, processingBuffer);
        RoundF(ref regC, ref regD, ref regA, ref regB, 14, 11, processingBuffer);
        RoundF(ref regB, ref regC, ref regD, ref regA, 15, 19, processingBuffer);

        //
        // Note: ... "Round 2" ...

        RoundG(ref regA, ref regB, ref regC, ref regD, 0, 3, processingBuffer);
        RoundG(ref regD, ref regA, ref regB, ref regC, 4, 5, processingBuffer);
        RoundG(ref regC, ref regD, ref regA, ref regB, 8, 9, processingBuffer);
        RoundG(ref regB, ref regC, ref regD, ref regA, 12, 13, processingBuffer);

        RoundG(ref regA, ref regB, ref regC, ref regD, 1, 3, processingBuffer);
        RoundG(ref regD, ref regA, ref regB, ref regC, 5, 5, processingBuffer);
        RoundG(ref regC, ref regD, ref regA, ref regB, 9, 9, processingBuffer);
        RoundG(ref regB, ref regC, ref regD, ref regA, 13, 13, processingBuffer);

        RoundG(ref regA, ref regB, ref regC, ref regD, 2, 3, processingBuffer);
        RoundG(ref regD, ref regA, ref regB, ref regC, 6, 5, processingBuffer);
        RoundG(ref regC, ref regD, ref regA, ref regB, 10, 9, processingBuffer);
        RoundG(ref regB, ref regC, ref regD, ref regA, 14, 13, processingBuffer);

        RoundG(ref regA, ref regB, ref regC, ref regD, 3, 3, processingBuffer);
        RoundG(ref regD, ref regA, ref regB, ref regC, 7, 5, processingBuffer);
        RoundG(ref regC, ref regD, ref regA, ref regB, 11, 9, processingBuffer);
        RoundG(ref regB, ref regC, ref regD, ref regA, 15, 13, processingBuffer);

        //
        // Note: ... "Round 3" ...

        RoundH(ref regA, ref regB, ref regC, ref regD, 0, 3, processingBuffer);
        RoundH(ref regD, ref regA, ref regB, ref regC, 8, 9, processingBuffer);
        RoundH(ref regC, ref regD, ref regA, ref regB, 4, 11, processingBuffer);
        RoundH(ref regB, ref regC, ref regD, ref regA, 12, 15, processingBuffer);

        RoundH(ref regA, ref regB, ref regC, ref regD, 2, 3, processingBuffer);
        RoundH(ref regD, ref regA, ref regB, ref regC, 10, 9, processingBuffer);
        RoundH(ref regC, ref regD, ref regA, ref regB, 6, 11, processingBuffer);
        RoundH(ref regB, ref regC, ref regD, ref regA, 14, 15, processingBuffer);

        RoundH(ref regA, ref regB, ref regC, ref regD, 1, 3, processingBuffer);
        RoundH(ref regD, ref regA, ref regB, ref regC, 9, 9, processingBuffer);
        RoundH(ref regC, ref regD, ref regA, ref regB, 5, 11, processingBuffer);
        RoundH(ref regB, ref regC, ref regD, ref regA, 13, 15, processingBuffer);

        RoundH(ref regA, ref regB, ref regC, ref regD, 3, 3, processingBuffer);
        RoundH(ref regD, ref regA, ref regB, ref regC, 11, 9, processingBuffer);
        RoundH(ref regC, ref regD, ref regA, ref regB, 7, 11, processingBuffer);
        RoundH(ref regB, ref regC, ref regD, ref regA, 15, 15, processingBuffer);

        //
        //

        regA += saveA;
        regB += saveB;
        regC += saveC;
        regD += saveD;
      }


      byte[] hash = new byte[16];
      Array.Copy(BitConverter.GetBytes(regA), 0, hash, 0, 4);
      Array.Copy(BitConverter.GetBytes(regB), 0, hash, 4, 4);
      Array.Copy(BitConverter.GetBytes(regC), 0, hash, 8, 4);
      Array.Copy(BitConverter.GetBytes(regD), 0, hash, 12, 4);

      return hash;
    }
  }
}

'@

  if (-not ('Sevecek.MD4' -as [Type])) {

    Add-Type $md4Implemented | Out-Null
  }

  [byte[]] $hashBytes = [Sevecek.MD4]::Compute($sourceBytes)

  [Text.StringBuilder] $outString = New-Object Text.StringBuilder
  for ($i = 0; $i -lt $hashBytes.Length; $i ++) {

    [void] $outString.Append(('{0:X2}' -f $hashBytes[$i]))
  }
  
  return $outString.ToString()
}

try {

  [WMI] $wmiComp = gwmi Win32_ComputerSystem

  if (-not ([string]::IsNullOrEmpty($wmiComp.Domain))) {

    $domain = $wmiComp.Domain
  }

  Log ('')
  [string] $domainSupplied = Read-Host ('Domain or DC (default = {0})' -f $domain)

  if (-not ([string]::IsNullOrEmpty($domainSupplied))) {

    $domain = $domainSupplied.Trim()
  }

  $rootDSE = [ADSI] ('LDAP://{0}/RootDSE' -f $domain)
  [string] $domainDN = $rootDSE.Properties['defaultNamingContext'].Value
  [string] $dcFQDN = $rootDSE.Properties['dNSHostName'].Value
  [string] $configDN = $rootDSE.Properties['configurationNamingContext'].Value

  $domainDE = New-Object System.DirectoryServices.DirectoryEntry
  $domainDE.Path = 'LDAP://{0}/{1}' -f $dcFQDN, $domainDN
  $domainDE.AuthenticationType = ([System.DirectoryServices.AuthenticationTypes]::Secure) -bor `
                                 ([System.DirectoryServices.AuthenticationTypes]::Sealing) -bor `
                                 ([System.DirectoryServices.AuthenticationTypes]::Signing) -bor `
                                 ([System.DirectoryServices.AuthenticationTypes]::ServerBind)

  [void] $domainDE.RefreshCache('msDS-PrincipalName')
  [string] $domainNetBIOS = $domainDE.Get('msDS-PrincipalName').Trim('\')

  $configDE = New-Object System.DirectoryServices.DirectoryEntry
  $configDE.Path = 'LDAP://{0}/{1}' -f $dcFQDN, $configDN
  $configDE.AuthenticationType = ([System.DirectoryServices.AuthenticationTypes]::Secure) -bor `
                                 ([System.DirectoryServices.AuthenticationTypes]::Sealing) -bor `
                                 ([System.DirectoryServices.AuthenticationTypes]::Signing) -bor `
                                 ([System.DirectoryServices.AuthenticationTypes]::ServerBind)

  Log ('')
  Log ('Machine:   {0} | {1}' -f $wmiComp.DNSHostName, $wmiComp.Domain)
  Log ('Domain:    {0} | {1}' -f $domainNetBIOS, $domainDN)
  Log ('DC FQDN:   {0}' -f $dcFQDN)
  Log ('Config DN: {0}' -f $configDN)

  ##
  ##

  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.Filter = '(objectClass=msKds-ProvRootKey)'
  $searcher.SearchRoot = $configDE
  $searcher.SearchScope = 'Subtree'
  $searcher.PageSize = 1
  $searcher.PropertiesToLoad.AddRange(@('distinguishedname', 'name', 'mskds-usestarttime'))

  $searcherRes = $searcher.FindAll()

  Log ('')

  [hashtable] $foundKDSKeys = @{}
  if ($searcherRes.Count -gt 0) { foreach ($oneSearcherRes in $searcherRes) {

    $kdsRootKey = New-Object PSObject
    Add-Member -Input $kdsRootKey -MemberType NoteProperty -Name id -Value ([guid] $oneSearcherRes.Properties['name'][0])
    Add-Member -Input $kdsRootKey -MemberType NoteProperty -Name since -Value ([DateTime]::Parse('1601-01-01') + [TimeSpan]::FromTicks(([UInt64] $oneSearcherRes.Properties['mskds-usestarttime'][0]))).ToLocalTime()

    [void] $foundKDSKeys.Add($kdsRootKey.id, $kdsRootKey)
  }}

  [int] $idx = 1
  if ($foundKDSKeys.Count -gt 0) { foreach ($oneKdsRootKey in ($foundKDSKeys.Values | sort -Desc since)) {

    Add-Member -Input $oneKdsRootKey -MemberType NoteProperty -Name idx -Value $idx
    Log ('KDS root key: #{0} | {1} | {2}' -f $oneKdsRootKey.idx, $oneKdsRootKey.id, $oneKdsRootKey.since.ToString('yyyy-MM-dd HH:mm:ss'))
    $idx ++
  }}

  ##
  ##

  Log ('')
  [string] $gmsaSupplied = Read-Host ('GMSA wildcard search filter (default = {0})' -f $gmsa)

  if (-not ([string]::IsNullOrEmpty($gmsaSupplied))) {

    $gmsa = $gmsaSupplied.Trim()
  }

  [string] $ldapSearch = '(&(objectClass=msDS-GroupManagedServiceAccount)(|(name={0})(sAMAccountName={0})(sAMAccountName={0}$)(dNSHostName={0}.*)))' -f $gmsa.TrimEnd('$')

  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.Filter = $ldapSearch
  $searcher.SearchRoot = $domainDE
  $searcher.SearchScope = 'Subtree'
  $searcher.PageSize = 1
  $searcher.PropertiesToLoad.AddRange(@('distinguishedname', 'samaccountname', 'dnshostname', 'pwdlastset', 'lastlogontimestamp', 'lockouttime', 'badpasswordtime'))

  $searcherRes = $searcher.FindAll()

  Log ('')

  [Collections.ArrayList] $foundDEs = @()
  [int] $idx = 1
  if ($searcherRes.Count -gt 0) { foreach ($oneSearcherRes in $searcherRes) {

    Log ('{0,2:D}: {1} | {2} | {3}' -f $idx, $oneSearcherRes.Properties['samaccountname'][0], $oneSearcherRes.Properties['dnshostname'][0], $oneSearcherRes.Properties['distinguishedname'][0])

    $loadedDE = $oneSearcherRes.GetDirectoryEntry()
    Add-Member -Input $loadedDE -MemberType NoteProperty -Force -Name svck_pwdLastSet -Value ([DateTime]::Parse('1601-01-01') + [TimeSpan]::FromTicks(([UInt64] $oneSearcherRes.Properties['pwdlastset'][0]))).ToLocalTime()
    Add-Member -Input $loadedDE -MemberType NoteProperty -Force -Name svck_lastLogonTimestamp -Value ([DateTime]::Parse('1601-01-01') + [TimeSpan]::FromTicks(([UInt64] $oneSearcherRes.Properties['lastlogontimestamp'][0]))).ToLocalTime()
    Add-Member -Input $loadedDE -MemberType NoteProperty -Force -Name svck_lockoutTime -Value ([DateTime]::Parse('1601-01-01') + [TimeSpan]::FromTicks(([UInt64] $oneSearcherRes.Properties['lockouttime'][0]))).ToLocalTime()
    Add-Member -Input $loadedDE -MemberType NoteProperty -Force -Name svck_badPasswordTime -Value ([DateTime]::Parse('1601-01-01') + [TimeSpan]::FromTicks(([UInt64] $oneSearcherRes.Properties['badpasswordtime'][0]))).ToLocalTime()

    [void] $foundDEs.Add($loadedDE)

    $idx ++
  }}

  if ($foundDEs.Count -lt 1) {

    throw ('Did not find any GMSA in the domain: {0}' -f $ldapSearch)
  }

  Log ('')
  [int] $gmsaSelected = 1
  [string] $gmsaSelectedSupplied = Read-Host ('Which GMSA are you interested in (default = {0})' -f $gmsaSelected)

  if (-not ([string]::IsNullOrEmpty($gmsaSelectedSupplied))) {

    $gmsaSelected = [int]::Parse($gmsaSelectedSupplied.Trim())
  }

  ##
  ##

  [System.DirectoryServices.DirectoryEntry] $gmsaDE = $foundDEs[($gmsaSelected - 1)]

  ##
  ##
  
  # Note: we read the password first because if the password should already change it gets changed
  #       only when actually read (the constructed attribute refreshed) for the first time after it should have been changed
  # Note: Managed Password Blob: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e
  [void] $gmsaDE.RefreshCache('msDS-ManagedPassword')
  [byte[]] $managedPwd = $gmsaDE.Properties['msDS-ManagedPassword'].Value

  [UInt16] $offsetCurrentPwd = 0
  [UInt16] $offsetPreviousPwd = 0

  if ($managedPwd.Length -gt 12) {

    $offsetCurrentPwd = [BitConverter]::ToUInt16($managedPwd, 8)
    $offsetPreviousPwd = [BitConverter]::ToUInt16($managedPwd, 10)
  }

  [int] $lenCurrentPwd = 0; while (($offsetCurrentPwd -gt 0) -and (([BitConverter]::ToUInt16($managedPwd, ($offsetCurrentPwd + ($lenCurrentPwd * 2)))) -ne 0)) { $lenCurrentPwd ++ }
  [int] $lenPreviousPwd = 0; while (($offsetPreviousPwd -gt 0) -and (([BitConverter]::ToUInt16($managedPwd, ($offsetPreviousPwd + ($lenPreviousPwd * 2)))) -ne 0)) { $lenPreviousPwd ++ }

  [byte[]] $passwordCurrent = New-Object byte[] ($lenCurrentPwd * 2)
  [byte[]] $passwordPrevious = New-Object byte[] ($lenPreviousPwd * 2)

  for ($i = 0; $i -lt $lenCurrentPwd; $i ++) {

    $passwordCurrent[($i * 2)] = $managedPwd[($offsetCurrentPwd + ($i * 2))]
    $passwordCurrent[($i * 2 + 1)] = $managedPwd[($offsetCurrentPwd + ($i * 2) + 1)]
  }

  [string] $md4Current = $null
  if ($passwordCurrent.Length -gt 0) {

    $md4Current = MD4 -sourceBytes $passwordCurrent
  }

  for ($i = 0; $i -lt $lenPreviousPwd; $i ++) {

    $passwordPrevious[($i * 2)] = $managedPwd[($offsetPreviousPwd + ($i * 2))]
    $passwordPrevious[($i * 2 + 1)] = $managedPwd[($offsetPreviousPwd + ($i * 2) + 1)]
  }

  [string] $md4Previous = $null
  if ($passwordPrevious.Length -gt 0) {

    $md4Previous = MD4 -sourceBytes $passwordPrevious
  }

  ##
  ##

  # Note: Group Key Envelope: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/192c061c-e740-4aa0-ab1d-6954fb3e58f7
  #[void] $gmsaDE.RefreshCache('msDS-ManagedPasswordId')
  [byte[]] $pwdId = $gmsaDE.Properties['msDS-ManagedPasswordId'].Value

  [UInt32] $kdsKeyIdFlags = [BitConverter]::ToUInt32($pwdId, 8)
  [UInt32] $kdsKeyIdL0 = [BitConverter]::ToUInt32($pwdId, 12)
  [UInt32] $kdsKeyIdL1 = [BitConverter]::ToUInt32($pwdId, 16)
  [UInt32] $kdsKeyIdL2 = [BitConverter]::ToUInt32($pwdId, 20)
  [guid] $kdsKeyId = [guid] ([byte[]] $pwdId[24..39])

  ##
  ##

  # Note: Group Key Envelope: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/192c061c-e740-4aa0-ab1d-6954fb3e58f7
  #[void] $gmsaDE.RefreshCache('msDS-ManagedPasswordPreviousId')
  [byte[]] $pwdPreviousId = $gmsaDE.Properties['msDS-ManagedPasswordPreviousId'].Value
  [UInt32] $kdsKeyPreviousIdFlags = 0
  [UInt32] $kdsKeyPreviousIdL0 = 0
  [UInt32] $kdsKeyPreviousIdL1 = 0
  [UInt32] $kdsKeyPreviousIdL2 = 0
  [guid] $kdsKeyPreviousId = [guid]::Empty

  try { 
    
    $kdsKeyPreviousId = [guid] ([byte[]] $pwdPreviousId[24..39])
    $kdsKeyPreviousIdFlags = [BitConverter]::ToUInt32($pwdPreviousId, 8)
    $kdsKeyPreviousIdL0 = [BitConverter]::ToUInt32($pwdPreviousId, 12)
    $kdsKeyPreviousIdL1 = [BitConverter]::ToUInt32($pwdPreviousId, 16)
    $kdsKeyPreviousIdL2 = [BitConverter]::ToUInt32($pwdPreviousId, 20)
  
  } catch { $error.Clear() }

  ##
  ##

  [void] $gmsaDE.RefreshCache('msDS-ReplAttributeMetadata')
  [XML] $replMeta = [XML] ('<replMeta>{0}</replMeta>' -f ($gmsaDE.Properties['msDS-ReplAttributeMetadata'].Value -join ''))

  [DateTime] $chng_unicodePwd = [DateTime]::Parse($replMeta.SelectSingleNode('replMeta/DS_REPL_ATTR_META_DATA[pszAttributeName="unicodePwd"]/ftimeLastOriginatingChange').InnerText).ToLocalTime()
  [DateTime] $chng_supplementalCredentials = [DateTime]::Parse($replMeta.SelectSingleNode('replMeta/DS_REPL_ATTR_META_DATA[pszAttributeName="supplementalCredentials"]/ftimeLastOriginatingChange').InnerText).ToLocalTime()
  [DateTime] $chng_msDS_ManagedPasswordId = [DateTime]::Parse($replMeta.SelectSingleNode('replMeta/DS_REPL_ATTR_META_DATA[pszAttributeName="msDS-ManagedPasswordId"]/ftimeLastOriginatingChange').InnerText).ToLocalTime()

  [DateTime] $chng_msDS_ManagedPasswordPreviousId = [DateTime]::Parse('1601-01-01 00:00:00Z')
  try { $chng_msDS_ManagedPasswordPreviousId = [DateTime]::Parse($replMeta.SelectSingleNode('replMeta/DS_REPL_ATTR_META_DATA[pszAttributeName="msDS-ManagedPasswordPreviousId"]/ftimeLastOriginatingChange').InnerText).ToLocalTime() } catch { $error.Clear() }

  ##
  ##

  [bool] $hashPreviousPassword = ($offsetPreviousPwd -ne 0) -or ($pwdPreviousId.Length -gt 0)

  Log ('')
  Log ('DN:                 {0}' -f $gmsaDE.Properties['distinguishedName'].Value)
  Log ('sAMAccountName:     {0}' -f $gmsaDE.Properties['sAMAccountName'].Value)
  Log ('dNSHostName:        {0}' -f $gmsaDE.Properties['dNSHostName'].Value)
  Log ('created:            {0}' -f $gmsaDE.Properties['whenCreated'].Value.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'))
  Log ('changed:            {0}' -f $gmsaDE.Properties['whenChanged'].Value.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'))
  Log ('')
  Log ('pwdLastSet:                     {0}' -f $gmsaDE.svck_pwdLastSet.ToString('yyyy-MM-dd HH:mm:ss'))
  Log ('password interval:              {0}' -f $gmsaDE.Properties['msDS-ManagedPasswordInterval'].Value)
  Log ('next pwd change:                {0}' -f ($gmsaDE.svck_pwdLastSet.AddDays($gmsaDE.Properties['msDS-ManagedPasswordInterval'].Value)).ToString('yyyy-MM-dd HH:mm:ss'))
  Log ('already changed:                {0}' -f $hashPreviousPassword)
  Log ('unicodePwd:                     {0}' -f $chng_unicodePwd.ToString('yyyy-MM-dd HH:mm:ss'))
  Log ('supplementalCredentials:        {0}' -f $chng_supplementalCredentials.ToString('yyyy-MM-dd HH:mm:ss'))
  Log ('')
  Log ('msDS-ManagedPasswordId:         {0}' -f $chng_msDS_ManagedPasswordId.ToString('yyyy-MM-dd HH:mm:ss'))
  Log ('msDS-ManagedPasswordId:         keyId = #{0} | {1} | F = {2:X8} | L0 = {3:X8} | L1 = {4:X8} | L2 = {5:X8}' -f $foundKDSKeys[$kdsKeyId].idx, $kdsKeyId, $kdsKeyIdFlags, $kdsKeyIdL0, $kdsKeyIdL1, $kdsKeyIdL2)
  Log ('msDS-ManagedPassword:           #{0} chars | {1}...' -f $lenCurrentPwd, (([Text.Encoding]::Unicode.GetString($passwordCurrent[0..63])) -replace '[\x00-\x1F]', ' '))
  Log ('msDS-ManagedPassword:           #{0} bytes | {1}...' -f ($lenCurrentPwd * 2), ([BitConverter]::ToString($passwordCurrent[0..31])))
  Log ('msDS-ManagedPassword:           MD4 = {0}' -f $md4Current)
  
  if ($hashPreviousPassword) {

    Log ('')
    Log ('msDS-ManagedPasswordPreviousId: {0}' -f $chng_msDS_ManagedPasswordPreviousId.ToString('yyyy-MM-dd HH:mm:ss'))
    Log ('msDS-ManagedPasswordPreviousId: keyId = #{0} | {1} | F = {2:X8} | L0 = {3:X8} | L1 = {4:X8} | L2 = {5:X8}' -f $foundKDSKeys[$kdsKeyPreviousId].idx, $kdsKeyPreviousId, $kdsKeyPreviousIdFlags, $kdsKeyPreviousIdL0, $kdsKeyPreviousIdL1, $kdsKeyPreviousIdL2)
    Log ('msDS-ManagedPasswordPrevious:   #{0} | {1}...' -f $lenPreviousPwd, (([Text.Encoding]::Unicode.GetString($passwordPrevious[0..63])) -replace '[\x00-\x1F]', ' '))
    Log ('msDS-ManagedPasswordPrevious:   #{0} | {1}...' -f $lenPreviousPwd, ([BitConverter]::ToString($passwordPrevious[0..31])))
    Log ('msDS-ManagedPasswordPrevious:   MD4 = {0}' -f $md4Previous)
  }

  Log ('')
  Log ('lastLogonTimestamp: {0}' -f $gmsaDE.svck_lastLogonTimestamp)
  Log ('badPasswordTime:    #{0} | {1}' -f ([int] $gmsaDE.Properties['badPwdCount'].Value), $gmsaDE.svck_badPasswordTime)
  Log ('lockoutTime:        {0}' -f $gmsaDE.svck_lockoutTime)

  if ($managedPwd.Length -lt 100) { 

    throw ('Managed password inaccessible')
  }

  Log ('')
  Log ('Log file: {0}' -f $global:logFile)
  Log ('')

} catch {

  Log ('Error: {0}' -f $_) -Fore Red
}

# SIG # Begin signature block
# MIIfJQYJKoZIhvcNAQcCoIIfFjCCHxICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDf2ekFrv4b0pPv
# MTqcZxFg3gugOTneeUPkufluTNajDqCCGSswggWNMIIEdaADAgECAhAOmxiO+dAt
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
# BCBhfbzNu4L4rmkGOF22vSfa1YmHmjA1VceOfHJHpuPvYjANBgkqhkiG9w0BAQEF
# AASCAQCFISI7enhsWOiqDG/L25CzhrOA9oFSfmpMDw0KK8UzWVtwMJjV4XoXAhCm
# Kczu7WOtv79XvCw/Re7UPQdI3dMcON8FuULRvAZlTWmeVD+ofduTOHwTtS3xTVBd
# 6fWHs0M6nZzR+hEbRRiQq8NV5yfqlweSRYvSVVB4gPaeXIxTmpkAnl0rbw5jUx2t
# veLnG571DD+RjUjIGKePmkuJdLIXBtMXG0fPP3brWB80yvmCyfLERvXgojJd33pn
# 7fmvT+uNTafXZuykSNcVD0CeHiTlqAWhYh5T2kmNPC0VY0wD0elDltdmAawfZWBW
# VNtBtTWvrNE3n6pomlwZfcj7GrB/oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJ
# AgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTsw
# OQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVT
# dGFtcGluZyBDQQIQC65mvFq6f5WHxvnpBOMzBDANBglghkgBZQMEAgEFAKBpMBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI0MTExODE4
# MTU1MlowLwYJKoZIhvcNAQkEMSIEIEg3Exqh7aP+nWL5ZYpPWcJIuvytmJhYNQiD
# XW6v4XacMA0GCSqGSIb3DQEBAQUABIICALqHxO6dDkAfWJmsGCsITXZXZDyPCKSx
# 4aMyM3EeDcs25FdEH83TWGJFsa4f1n7Vk+F2xtIwLM639KoxwG90/HrHqmFFGS8b
# 1GtDfj9afjKgdfOzRykUvu6g6ZEhNmaBbajdCWgKP/XPbPvIn2xXoNyfE3WFWgTq
# d1g2OszaiL+dMLxtXaVPIXga5qkj1kxRGp5/qCD/q9zjIteQ8hyRYArCt222iooE
# 28I7DOciL8dNZ4wmBt+dpLwuXZwZ/6Iz+59+NT8787VvY7sDWSDRhttNxyXGLigp
# 2TeMT3O8GcuJBOCyMN7vWsZ4pw6ZNDS9rF57wz1sr2PmSCZRCTfIjJkg9NY9V+/f
# PLhqf8azgm/XYFh5Hx/gxClDHFrtDuGL78QwV3+vGoi8FxfqwFT1PDmFDXhDwNiu
# ROTvNgsx95qGXhQopaXLEbJGbwaEXgxDGDo1fTdEn8FhiXV8KRArCrPy2znSRHMa
# 8Gaq2fqaWhu3ZLaCqepVed/kt0q+v6+mOqNMJskDXrNUmfInoh4uMVKrKE+xRFxw
# VUqCZb9r221LLyTtQtuiwqoyyWNoEMi8RRvlZsmwNMoXgI+1oITiFcONvfmYVLAy
# UNbO47Otbj7s4z7UIhbjxP/FIdMM3Z7KYuvRuVkInvA5mDu6pWGnyx9UawMZkcbB
# j+IkKgnIrleU
# SIG # End signature block

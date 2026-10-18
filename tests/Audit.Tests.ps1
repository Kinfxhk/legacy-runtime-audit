# Plain assert-based tests for Invoke-LegacyRuntimeAudit.ps1 (no Pester).
# Throws on the first failure; prints "PASS n/n" when everything passes.

$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\..\src\Invoke-LegacyRuntimeAudit.ps1"

$script:Pass = 0

function Assert-True {
  param([bool]$Condition, [string]$Message)
  if ($Condition) { $script:Pass++ }
  else { throw "FAIL: $Message" }
}

function Assert-Equal {
  param($Expected, $Actual, [string]$Message)
  if ($Expected -ceq $Actual) { $script:Pass++ }
  else { throw "FAIL: $Message (expected '$Expected', got '$Actual')" }
}

function New-FakeInventory {
  param(
    [object[]]$Uninstall = @(),
    [string[]]$Clsid = @(),
    [string[]]$Files = @(),
    [object[]]$RegistryValues = @()
  )
  return [pscustomobject]@{
    Uninstall      = @($Uninstall)
    Clsid          = @($Clsid)
    Files          = @($Files)
    RegistryValues = @($RegistryValues)
  }
}

function New-UninstallEntry {
  param([string]$DisplayName, [string]$Version = '', [string]$Hive = 'HKLM')
  return [pscustomobject]@{
    DisplayName     = $DisplayName
    DisplayVersion  = $Version
    Publisher       = ''
    InstallLocation = ''
    Hive            = $Hive
  }
}

function Find-ForRule {
  param([string]$RuleId, $Inventory)
  $rules = Get-BuiltinRules
  $result = Find-LegacyRuntime -Inventory $Inventory -Rules $rules
  $found = @($result.Findings | Where-Object { $_.RuleId -eq $RuleId })
  return ,$found
}

function Find-Info {
  param($Inventory)
  $rules = Get-BuiltinRules
  $result = Find-LegacyRuntime -Inventory $Inventory -Rules $rules
  $info = @($result.Info)
  return ,$info
}

# --- 1. Read-only hard rule: no forbidden cmdlets/tokens in the scanner. ---
$scriptPath = "$PSScriptRoot\..\src\Invoke-LegacyRuntimeAudit.ps1"
$src = Get-Content -Raw $scriptPath
$forbidden = @(
  'Remove-Item', 'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty',
  'Start-Process', 'msiexec', 'reg add', 'reg delete', 'Uninstall-'
)
foreach ($f in $forbidden) {
  if ($src -match [regex]::Escape($f)) {
    throw "FAIL: scanner source contains forbidden token: $f"
  }
  $script:Pass++
}

# --- 2. Rules table shape. ---
$rules = @(Get-BuiltinRules)
Assert-Equal 9 $rules.Count 'rules table must contain exactly 9 rules'
foreach ($r in $rules) {
  Assert-True (($r.Id -ne $null) -and ($r.Id -ne '')) "rule '$($r.Name)' has an Id"
  Assert-True (($r.Name -ne $null) -and ($r.Name -ne '')) 'rule has a Name'
  Assert-True (($r.WhyZh -ne $null) -and ($r.WhyZh -ne '')) "rule '$($r.Id)' has WhyZh"
  Assert-True (($r.WhyEn -ne $null) -and ($r.WhyEn -ne '')) "rule '$($r.Id)' has WhyEn"
  Assert-True (($r.Advice -ne $null) -and ($r.Advice -match 'https?://')) "rule '$($r.Id)' Advice carries an official URL"
}

# --- 3. Clean machine -> no findings, no info. ---
$clean = New-FakeInventory
$cleanResult = Find-LegacyRuntime -Inventory $clean -Rules $rules
Assert-Equal 0 @($cleanResult.Findings).Count 'clean machine has zero findings'
Assert-Equal 0 @($cleanResult.Info).Count 'clean machine has zero info'

# --- 4. QuickTime: uninstall + CLSID. ---
$qt = Find-ForRule 'QT' (New-FakeInventory -Uninstall @(New-UninstallEntry 'QuickTime 7.7.9' '7.7.9'))
Assert-Equal 1 $qt.Count 'QuickTime uninstall matched'
Assert-Equal '7.7.9' $qt[0].Version 'QuickTime version read from inventory'
$qtClsid = Find-ForRule 'QT' (New-FakeInventory -Clsid @('02BF25D5-8C17-4B23-BC80-D3488ABDDC6B'))
Assert-Equal 1 $qtClsid.Count 'QuickTime CLSID matched'

# --- 5. Silverlight: uninstall + CLSID. ---
$sl = Find-ForRule 'SL' (New-FakeInventory -Uninstall @(New-UninstallEntry 'Microsoft Silverlight' '5.1.50918.0'))
Assert-Equal 1 $sl.Count 'Silverlight uninstall matched'
$slClsid = Find-ForRule 'SL' (New-FakeInventory -Clsid @('DFEAF541-F3E1-4c24-ACAC-99C30715084A'))
Assert-Equal 1 $slClsid.Count 'Silverlight CLSID matched'

# --- 6. Flash: uninstall + CLSID + file. ---
$flash = Find-ForRule 'FLASH' (New-FakeInventory -Uninstall @(New-UninstallEntry 'Adobe Flash Player 32 NPAPI' '32.0.0.371'))
Assert-Equal 1 $flash.Count 'Flash uninstall matched'
$flashClsid = Find-ForRule 'FLASH' (New-FakeInventory -Clsid @('D27CDB6E-AE6D-11cf-96B8-444553540000'))
Assert-Equal 1 $flashClsid.Count 'Flash CLSID matched'
$flashFile = Find-ForRule 'FLASH' (New-FakeInventory -Files @('C:\Windows\System32\Macromed\Flash\Flash32.ocx'))
Assert-Equal 1 $flashFile.Count 'Flash System32 ocx matched'
$flashFile2 = Find-ForRule 'FLASH' (New-FakeInventory -Files @('C:\Windows\SysWOW64\Macromed\Flash\FlashUtil32.ocx'))
Assert-Equal 1 $flashFile2.Count 'Flash SysWOW64 ocx matched'

# --- 7. Shockwave: uninstall + CLSID. ---
$shock = Find-ForRule 'SHOCK' (New-FakeInventory -Uninstall @(New-UninstallEntry 'Adobe Shockwave Player' '12.3.4.204'))
Assert-Equal 1 $shock.Count 'Shockwave uninstall matched'
$shockClsid = Find-ForRule 'SHOCK' (New-FakeInventory -Clsid @('166B1BCA-3F9C-11CF-8075-444553540000'))
Assert-Equal 1 $shockClsid.Count 'Shockwave CLSID matched'

# --- 8. TrueCrypt: uninstall + file. ---
$tc = Find-ForRule 'TRUECRYPT' (New-FakeInventory -Uninstall @(New-UninstallEntry 'TrueCrypt' '7.1a'))
Assert-Equal 1 $tc.Count 'TrueCrypt uninstall matched'
$tcFile = Find-ForRule 'TRUECRYPT' (New-FakeInventory -Files @('C:\Program Files\TrueCrypt\TrueCrypt.exe'))
Assert-Equal 1 $tcFile.Count 'TrueCrypt exe matched'
$tcFileNoMatch = Find-ForRule 'TRUECRYPT' (New-FakeInventory -Files @('C:\Program Files (x86)\TrueCrypt\TrueCrypt.exe'))
Assert-Equal 0 $tcFileNoMatch.Count 'TrueCrypt x86 exe not matched by Program Files rule'

# --- 9. Java SE 6/7: both DisplayName forms. ---
$j1 = Find-ForRule 'JAVA67' (New-FakeInventory -Uninstall @(New-UninstallEntry 'Java(TM) 6 Update 45' '6.0.450'))
Assert-Equal 1 $j1.Count 'Java(TM) 6 matched'
$j2 = Find-ForRule 'JAVA67' (New-FakeInventory -Uninstall @(New-UninstallEntry 'Java 7 Update 80' '7.0.800'))
Assert-Equal 1 $j2.Count 'Java 7 matched'
$j3 = Find-ForRule 'JAVA67' (New-FakeInventory -Uninstall @(New-UninstallEntry 'Java SE Runtime Environment 6' '6.0.0'))
Assert-Equal 1 $j3.Count 'Java SE Runtime Environment 6 matched'
$jNo = Find-ForRule 'JAVA67' (New-FakeInventory -Uninstall @(New-UninstallEntry 'Java 8 Update 401' '8.0.4010'))
Assert-Equal 0 $jNo.Count 'Java 8 NOT flagged'

# --- 10. Reader: 9 / X / XI and 2015/2017 Classic; DC continuous NOT flagged. ---
foreach ($dn in @('Adobe Reader 9.5.5 MUI', 'Adobe Reader X (10.1.16)', 'Adobe Reader XI (11.0.23)', 'Adobe Acrobat Reader 2015 MUI', 'Adobe Acrobat Reader 2017 MUI')) {
  $r = Find-ForRule 'READER' (New-FakeInventory -Uninstall @(New-UninstallEntry $dn))
  Assert-Equal 1 $r.Count "Reader '$dn' flagged"
}
$rNo = Find-ForRule 'READER' (New-FakeInventory -Uninstall @(New-UninstallEntry 'Adobe Acrobat Reader DC' '25.1.0'))
Assert-Equal 0 $rNo.Count 'Reader DC continuous NOT flagged'

# --- 11. Python 2.7. ---
$py = Find-ForRule 'PY27' (New-FakeInventory -Uninstall @(New-UninstallEntry 'Python 2.7.18 (64-bit)' '2.7.18150'))
Assert-Equal 1 $py.Count 'Python 2.7 flagged'
$pyNo = Find-ForRule 'PY27' (New-FakeInventory -Uninstall @(New-UninstallEntry 'Python 3.12.4 (64-bit)' '3.12.4150'))
Assert-Equal 0 $pyNo.Count 'Python 3 NOT flagged'

# --- 12. IE mode site list marker -> INFO, not a finding. ---
$ie = New-FakeInventory -RegistryValues @(
  [pscustomobject]@{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'InternetExplorerIntegrationSiteList'; Value = 'https://example.com/sitelist.xml' }
)
$ieFindings = Find-ForRule 'IEMODE' $ie
$ieInfo = Find-Info $ie
Assert-Equal 0 $ieFindings.Count 'IE mode marker is NOT a finding'
Assert-Equal 1 $ieInfo.Count 'IE mode marker reported as info'
Assert-Equal 'IEMODE' $ieInfo[0].RuleId 'IE mode info carries the IEMODE rule id'

Write-Host ''
Write-Host "PASS $script:Pass/$script:Pass" -ForegroundColor Green

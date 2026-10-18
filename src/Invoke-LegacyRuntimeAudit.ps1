<#
.SYNOPSIS
  Read-only scanner for dead, unsafe Windows runtimes (QuickTime, Silverlight,
  Flash, Shockwave, TrueCrypt, Java SE 6/7, old Adobe Reader, Python 2.7, and an
  IE-mode ActiveX dependency marker).

.DESCRIPTION
  STRICTLY READ-ONLY. This script never writes the registry, never deletes,
  uninstalls or changes anything. The only files it writes are the reports you
  explicitly request with -Markdown and/or -Json.

  Compatible with Windows PowerShell 5.1 and PowerShell 7. No modules, no dotnet.

  Exit codes: 0 = no findings, 1 = findings present, 2 = script error.
#>

[CmdletBinding()]
param(
  [string]$Markdown,
  [string]$Json,
  [switch]$IncludeComputerName
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Rules table (data-driven). Each rule carries its own matchers so the matcher
# logic in Find-LegacyRuntime stays pure and tests can feed fake inventory.
# ---------------------------------------------------------------------------
function Get-BuiltinRules {
  return @(
    @{
      Id                = 'QT'
      Name              = 'Apple QuickTime for Windows'
      WhyZh             = 'Apple 已於 2016 年停止支援 Windows 版 QuickTime，不再提供安全性更新。'
      WhyEn             = 'Apple ended support for QuickTime for Windows in 2016 and no longer ships security updates.'
      Advice            = '請解除安裝 QuickTime for Windows，改用系統內建或其他仍受支援的播放器。官方說明：https://support.apple.com/en-us/106375'
      UninstallPatterns = @('^QuickTime')
      Clsids            = @('{02BF25D5-8C17-4B23-BC80-D3488ABDDC6B}')
      FilePatterns      = @()
      RegistryValues    = @()
      IsInfo            = $false
    },
    @{
      Id                = 'SL'
      Name              = 'Microsoft Silverlight'
      WhyZh             = 'Microsoft 已於 2021 年 10 月 12 日終止 Silverlight 的支援。'
      WhyEn             = 'Microsoft ended support for Silverlight on October 12, 2021.'
      Advice            = '請解除安裝 Silverlight，並改用 HTML5 等現代網頁標準。官方說明：https://learn.microsoft.com/en-us/lifecycle/announcements/silverlight-end-of-support'
      UninstallPatterns = @('Silverlight')
      Clsids            = @('{DFEAF541-F3E1-4c24-ACAC-99C30715084A}')
      FilePatterns      = @()
      RegistryValues    = @()
      IsInfo            = $false
    },
    @{
      Id                = 'FLASH'
      Name              = 'Adobe Flash Player'
      WhyZh             = 'Adobe 已於 2020 年 12 月 31 日停止支援 Flash Player，並於 2021 年 1 月 12 日起封鎖其執行。'
      WhyEn             = 'Adobe ended support for Flash Player on December 31, 2020 and blocked it from running on January 12, 2021.'
      Advice            = 'Adobe 強烈建議立即解除安裝 Flash Player，改用 HTML5 / WebGL / WebAssembly。官方說明：https://www.adobe.com/products/flashplayer/end-of-life-alternative.html'
      UninstallPatterns = @('Adobe Flash Player')
      Clsids            = @('{D27CDB6E-AE6D-11cf-96B8-444553540000}')
      FilePatterns      = @('System32\Macromed\Flash\*.ocx', 'SysWOW64\Macromed\Flash\*.ocx')
      RegistryValues    = @()
      IsInfo            = $false
    },
    @{
      Id                = 'SHOCK'
      Name              = 'Adobe Shockwave Player'
      WhyZh             = 'Adobe 已於 2019 年 4 月 9 日終止 Shockwave Player 的生命週期。'
      WhyEn             = 'Adobe discontinued Shockwave Player effective April 9, 2019.'
      Advice            = '請解除安裝 Shockwave Player。官方說明：https://helpx.adobe.com/shockwave/shockwave-end-of-life-faq.html'
      UninstallPatterns = @('Shockwave')
      Clsids            = @('{166B1BCA-3F9C-11CF-8075-444553540000}')
      FilePatterns      = @()
      RegistryValues    = @()
      IsInfo            = $false
    },
    @{
      Id                = 'TRUECRYPT'
      Name              = 'TrueCrypt'
      WhyZh             = 'TrueCrypt 開發已於 2014 年終止，不再收到安全性更新。'
      WhyEn             = 'TrueCrypt development was abandoned in 2014 and it no longer receives security updates.'
      Advice            = 'VeraCrypt 能以 TrueCrypt 模式掛載 TrueCrypt 磁碟區，請遷移至 VeraCrypt。官方說明：https://veracrypt.io/en/TrueCrypt%20Support.html'
      UninstallPatterns = @('^TrueCrypt')
      Clsids            = @()
      FilePatterns      = @('Program Files\TrueCrypt\TrueCrypt.exe')
      RegistryValues    = @()
      IsInfo            = $false
    },
    @{
      Id                = 'JAVA67'
      Name              = 'Java SE 6/7 runtime'
      WhyZh             = 'Oracle 已停止 Java SE 6/7 的公開更新，不再提供免費安全性修補。'
      WhyEn             = 'Oracle ended public updates for Java SE 6/7 and no longer ships free security patches.'
      Advice            = '請升級至受支援的 Java LTS（例如 Java 17/21 或 OpenJDK）。官方支援時程：https://www.oracle.com/java/technologies/java-se-support-roadmap.html'
      UninstallPatterns = @('^Java(\(TM\))? (6|7)', '^Java SE Runtime Environment (6|7)')
      Clsids            = @()
      FilePatterns      = @()
      RegistryValues    = @()
      IsInfo            = $false
    },
    @{
      Id                = 'READER'
      Name              = 'Adobe Reader (out-of-support versions)'
      WhyZh             = 'Adobe 已停止支援 Reader 9 / X / XI 及 Reader 2015 / 2017 Classic 版本。'
      WhyEn             = 'Adobe ended support for Reader 9/X/XI and the Reader 2015/2017 Classic track.'
      Advice            = '請升級至最新 Adobe Acrobat Reader DC。官方支援版本：https://helpx.adobe.com/support/programs/adobe-support-policies-supported-product-versions.html'
      UninstallPatterns = @('^Adobe Reader (9|X)', '^Adobe Acrobat Reader (DC )?201[57]')
      Clsids            = @()
      FilePatterns      = @()
      RegistryValues    = @()
      IsInfo            = $false
    },
    @{
      Id                = 'PY27'
      Name              = 'Python 2.7'
      WhyZh             = 'Python 2 已於 2020 年 1 月 1 日停止支援，不再收到安全性修正。'
      WhyEn             = 'Python 2 reached end of life on January 1, 2020 and no longer receives security fixes.'
      Advice            = '請升級至 Python 3，並參考官方移轉指南。官方說明：https://www.python.org/doc/sunset-python-2/'
      UninstallPatterns = @('^Python 2\.')
      Clsids            = @()
      FilePatterns      = @()
      RegistryValues    = @()
      IsInfo            = $false
    },
    @{
      Id                = 'IEMODE'
      Name              = 'Internet Explorer ActiveX dependency marker (IE mode site list)'
      WhyZh             = '偵測到 Edge IE 模式網站清單政策，表示系統可能仍依賴 IE / ActiveX 元件。'
      WhyEn             = 'An Edge IE-mode site list policy is configured, which may indicate a continuing IE/ActiveX dependency.'
      Advice            = '此項為資訊提示（非漏洞）。請規劃將 ActiveX 應用程式現代化。官方說明：https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/internetexplorerintegrationsitelist'
      UninstallPatterns = @()
      Clsids            = @()
      FilePatterns      = @()
      RegistryValues    = @(
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'InternetExplorerIntegrationSiteList' }
      )
      IsInfo            = $true
    }
  )
}

# ---------------------------------------------------------------------------
# Inventory collection (reads the real system; produces plain objects).
# ---------------------------------------------------------------------------
function Resolve-FilePattern {
  param([string]$Pattern)
  if ($Pattern -like 'System32\*' -or $Pattern -like 'SysWOW64\*') {
    return (Join-Path $env:WINDIR $Pattern)
  }
  if ($Pattern -like 'Program Files\*' -or $Pattern -like 'Program Files (x86)\*') {
    return (Join-Path $env:SystemDrive $Pattern)
  }
  return $Pattern
}

function Get-UninstallEntries {
  $hives = @(
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';              Name = 'HKLM' },
    @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall';  Name = 'HKLM WOW6432Node' },
    @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';              Name = 'HKCU' }
  )
  $out = @()
  foreach ($h in $hives) {
    if (-not (Test-Path $h.Path)) { continue }
    $keys = Get-ChildItem -Path $h.Path -ErrorAction SilentlyContinue
    foreach ($k in $keys) {
      $item = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
      if ($null -eq $item) { continue }
      $name = [string]$item.DisplayName
      if ($name -eq '') { continue }
      $out += [pscustomobject]@{
        DisplayName     = $name
        DisplayVersion  = [string]$item.DisplayVersion
        Publisher       = [string]$item.Publisher
        InstallLocation = [string]$item.InstallLocation
        Hive            = $h.Name
      }
    }
  }
  return ,$out
}

function Get-Inventory {
  param(
    [Parameter(Mandatory = $true)] $Rules
  )

  $uninstall = Get-UninstallEntries

  # CLSIDs referenced by the rules.
  $clsidProbe = @($Rules | ForEach-Object { $_.Clsids } | Select-Object -Unique)
  $clsidPresent = @()
  foreach ($c in $clsidProbe) {
    $guid = $c.Trim('{}').ToUpperInvariant()
    $path = "Registry::HKEY_CLASSES_ROOT\CLSID\{$guid}"
    if (Test-Path $path) { $clsidPresent += $guid }
  }

  # File paths referenced by the rules.
  $fileProbe = @($Rules | ForEach-Object { $_.FilePatterns } | Select-Object -Unique)
  $files = @()
  foreach ($fp in $fileProbe) {
    $full = Resolve-FilePattern $fp
    $found = @(Get-ChildItem -Path $full -ErrorAction SilentlyContinue)
    foreach ($f in $found) { $files += $f.FullName }
  }

  # Registry values referenced by the rules (INFO markers).
  $regProbe = @($Rules | ForEach-Object { $_.RegistryValues } | Select-Object -Unique)
  $regValues = @()
  foreach ($rv in $regProbe) {
    $item = Get-ItemProperty -Path $rv.Path -ErrorAction SilentlyContinue
    if ($null -eq $item) { continue }
    $prop = $item.PSObject.Properties[$rv.Name]
    if ($null -ne $prop) {
      $regValues += [pscustomobject]@{
        Path  = $rv.Path
        Name  = $rv.Name
        Value = [string]$prop.Value
      }
    }
  }

  return [pscustomobject]@{
    Uninstall      = @($uninstall)
    Clsid          = @($clsidPresent)
    Files          = @($files)
    RegistryValues = @($regValues)
  }
}

# ---------------------------------------------------------------------------
# Pure matching: takes inventory + rules, returns findings and info. No system
# access, so tests can feed a fake inventory.
# ---------------------------------------------------------------------------
function Find-LegacyRuntime {
  param(
    [Parameter(Mandatory = $true)] $Inventory,
    [Parameter(Mandatory = $true)] $Rules
  )

  $findings = @()
  $info = @()

  foreach ($rule in $Rules) {
    if ($rule.IsInfo) {
      foreach ($rv in $rule.RegistryValues) {
        foreach ($present in @($Inventory.RegistryValues)) {
          if ($present.Path -ieq $rv.Path -and $present.Name -ieq $rv.Name) {
            $info += [pscustomobject]@{
              RuleId    = $rule.Id
              RuleName  = $rule.Name
              WhyZh     = $rule.WhyZh
              WhyEn     = $rule.WhyEn
              Advice    = $rule.Advice
              FoundItem = $present.Value
              Version   = ''
              Evidence  = "registry policy value $($rv.Path)\$($rv.Name)"
            }
          }
        }
      }
      continue
    }

    # Uninstall entries (matched by DisplayName regex).
    foreach ($u in @($Inventory.Uninstall)) {
      foreach ($p in $rule.UninstallPatterns) {
        if ([string]$u.DisplayName -match $p) {
          $findings += [pscustomobject]@{
            RuleId    = $rule.Id
            RuleName  = $rule.Name
            WhyZh     = $rule.WhyZh
            WhyEn     = $rule.WhyEn
            Advice    = $rule.Advice
            FoundItem = [string]$u.DisplayName
            Version   = [string]$u.DisplayVersion
            Evidence  = "uninstall ($($u.Hive))"
          }
          break
        }
      }
    }

    # COM/ActiveX CLSIDs.
    foreach ($c in $rule.Clsids) {
      $guid = $c.Trim('{}').ToUpperInvariant()
      if (@($Inventory.Clsid) -contains $guid) {
        $findings += [pscustomobject]@{
          RuleId    = $rule.Id
          RuleName  = $rule.Name
          WhyZh     = $rule.WhyZh
          WhyEn     = $rule.WhyEn
          Advice    = $rule.Advice
          FoundItem = "{$guid}"
          Version   = ''
          Evidence  = 'COM/ActiveX CLSID registered'
        }
      }
    }

    # Known file paths.
    foreach ($fp in $rule.FilePatterns) {
      $match = "*\$fp"
      foreach ($f in @($Inventory.Files)) {
        if ([string]$f -like $match) {
          $findings += [pscustomobject]@{
            RuleId    = $rule.Id
            RuleName  = $rule.Name
            WhyZh     = $rule.WhyZh
            WhyEn     = $rule.WhyEn
            Advice    = $rule.Advice
            FoundItem = [string]$f
            Version   = ''
            Evidence  = 'file present'
          }
        }
      }
    }
  }

  return [pscustomobject]@{
    Findings = @($findings)
    Info     = @($info)
  }
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
function Pad {
  param([string]$S, [int]$W)
  $s = [string]$S
  if ($s.Length -ge $W) { return $s.Substring(0, $W) }
  return $s + (' ' * ($W - $s.Length))
}

function Show-ConsoleReport {
  param($Result, [int]$FindingsCount, [int]$InfoCount)

  Write-Host ''
  Write-Host '== Legacy Runtime Audit ==' -ForegroundColor White
  Write-Host ''

  if ($FindingsCount -eq 0 -and $InfoCount -eq 0) {
    Write-Host 'No legacy runtimes found.' -ForegroundColor Green
  }
  else {
    $rw = 26; $iw = 40; $vw = 22; $ew = 26
    $header = '{0} {1} {2} {3}' -f (Pad 'Rule' $rw), (Pad 'Found item' $iw), (Pad 'Version' $vw), (Pad 'Evidence' $ew)
    Write-Host $header -ForegroundColor White
    Write-Host ('-' * ($rw + $iw + $vw + $ew + 3)) -ForegroundColor DarkGray

    foreach ($f in @($Result.Findings)) {
      $ver = [string]$f.Version
      if ($ver -eq '') { $ver = '-' }
      $line = '{0} {1} {2} {3}' -f (Pad $f.RuleName $rw), (Pad $f.FoundItem $iw), (Pad $ver $vw), (Pad $f.Evidence $ew)
      Write-Host $line -ForegroundColor Red
    }
    foreach ($i in @($Result.Info)) {
      $line = '{0} {1} {2} {3}' -f (Pad $i.RuleName $rw), (Pad $i.FoundItem $iw), (Pad '-' $vw), (Pad $i.Evidence $ew)
      Write-Host $line -ForegroundColor Cyan
    }
  }

  Write-Host ''
  Write-Host "findings=$FindingsCount info=$InfoCount" -ForegroundColor Yellow
}

function Write-MarkdownReport {
  param($Result, [int]$FindingsCount, [int]$InfoCount, [string]$Path, [bool]$IncludeComputer)

  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('# Legacy Runtime Audit 報告 / Legacy Runtime Audit Report')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("產生時間 Generated at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
  if ($IncludeComputer) {
    [void]$sb.AppendLine("電腦名稱 Computer Name: $env:COMPUTERNAME")
  }
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine('## 摘要 / Summary')
  [void]$sb.AppendLine('')
  [void]$sb.AppendLine("- 發現 Findings: $FindingsCount")
  [void]$sb.AppendLine("- 資訊 Info: $InfoCount")
  [void]$sb.AppendLine('')

  if ($FindingsCount -gt 0) {
    [void]$sb.AppendLine('## 發現 / Findings')
    [void]$sb.AppendLine('')
    foreach ($f in @($Result.Findings)) {
      $ver = [string]$f.Version
      if ($ver -eq '') { $ver = '-' }
      [void]$sb.AppendLine("### $($f.RuleName) [$($f.RuleId)]")
      [void]$sb.AppendLine('')
      [void]$sb.AppendLine("- 找到的項目 Found item: ``$($f.FoundItem)``")
      [void]$sb.AppendLine("- 版本 Version: $ver")
      [void]$sb.AppendLine("- 證據 Evidence: $($f.Evidence)")
      [void]$sb.AppendLine("- 原因 Why (繁中): $($f.WhyZh)")
      [void]$sb.AppendLine("- 原因 Why (English): $($f.WhyEn)")
      [void]$sb.AppendLine("- 建議 Advice: $($f.Advice)")
      [void]$sb.AppendLine('')
    }
  }

  if ($InfoCount -gt 0) {
    [void]$sb.AppendLine('## 資訊 / Info')
    [void]$sb.AppendLine('')
    foreach ($i in @($Result.Info)) {
      [void]$sb.AppendLine("### $($i.RuleName) [$($i.RuleId)]")
      [void]$sb.AppendLine('')
      [void]$sb.AppendLine("- 值 Value: ``$($i.FoundItem)``")
      [void]$sb.AppendLine("- 證據 Evidence: $($i.Evidence)")
      [void]$sb.AppendLine("- 說明 Why (繁中): $($i.WhyZh)")
      [void]$sb.AppendLine("- 說明 Why (English): $($i.WhyEn)")
      [void]$sb.AppendLine("- 建議 Advice: $($i.Advice)")
      [void]$sb.AppendLine('')
    }
  }

  if ($FindingsCount -eq 0 -and $InfoCount -eq 0) {
    [void]$sb.AppendLine('沒有發現過時執行環境。No legacy runtimes found.')
    [void]$sb.AppendLine('')
  }

  [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}

function Get-JsonReport {
  param($Result, [int]$FindingsCount, [int]$InfoCount, [bool]$IncludeComputer)

  $obj = [ordered]@{}
  $obj['generatedAt'] = (Get-Date).ToString('o')
  if ($IncludeComputer) { $obj['computerName'] = $env:COMPUTERNAME }
  $obj['findings'] = $FindingsCount
  $obj['info'] = $InfoCount

  $results = @()
  foreach ($f in @($Result.Findings)) {
    $results += [ordered]@{
      kind      = 'finding'
      ruleId    = $f.RuleId
      ruleName  = $f.RuleName
      foundItem = [string]$f.FoundItem
      version   = [string]$f.Version
      evidence  = [string]$f.Evidence
      whyZh     = $f.WhyZh
      whyEn     = $f.WhyEn
      advice    = $f.Advice
    }
  }
  foreach ($i in @($Result.Info)) {
    $results += [ordered]@{
      kind      = 'info'
      ruleId    = $i.RuleId
      ruleName  = $i.RuleName
      foundItem = [string]$i.FoundItem
      version   = ''
      evidence  = [string]$i.Evidence
      whyZh     = $i.WhyZh
      whyEn     = $i.WhyEn
      advice    = $i.Advice
    }
  }
  $obj['results'] = $results

  return ($obj | ConvertTo-Json -Depth 6)
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
function Invoke-AuditMain {
  param(
    [string]$Markdown,
    [string]$Json,
    [switch]$IncludeComputerName
  )

  $rules = Get-BuiltinRules
  $inv = Get-Inventory -Rules $rules
  $result = Find-LegacyRuntime -Inventory $inv -Rules $rules
  $findingsCount = @($result.Findings).Count
  $infoCount = @($result.Info).Count

  Show-ConsoleReport -Result $result -FindingsCount $findingsCount -InfoCount $infoCount

  if ($Markdown) {
    Write-MarkdownReport -Result $result -FindingsCount $findingsCount -InfoCount $infoCount -Path $Markdown -IncludeComputer $IncludeComputerName
  }
  if ($Json) {
    $jsonText = Get-JsonReport -Result $result -FindingsCount $findingsCount -InfoCount $infoCount -IncludeComputer $IncludeComputerName
    [System.IO.File]::WriteAllText($Json, $jsonText, (New-Object System.Text.UTF8Encoding($false)))
  }

  if ($findingsCount -gt 0) { return 1 }
  return 0
}

# Only auto-run when invoked directly (skipped when dot-sourced by the tests).
if ($MyInvocation.InvocationName -ne '.') {
  try {
    $code = Invoke-AuditMain @PSBoundParameters
    exit $code
  }
  catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
  }
}

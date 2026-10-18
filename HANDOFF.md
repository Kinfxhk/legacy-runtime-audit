# Handoff — legacy-runtime-audit v1.0.0

## What was built

A single read-only PowerShell scanner `src/Invoke-LegacyRuntimeAudit.ps1` (compatible
with Windows PowerShell 5.1 and PowerShell 7, no modules, no dotnet) plus an
assert-based test suite and a packaging script:

- `src/Invoke-LegacyRuntimeAudit.ps1` — the scanner. Rules table (9 rules, data-driven
  hashtables) + `Get-Inventory` (reads system) + `Find-LegacyRuntime` (pure) +
  console/Markdown/JSON reporting.
- `tests/Audit.Tests.ps1` — plain assert script, 86 asserts, no Pester. Includes the
  required read-only hard-rule grep for forbidden cmdlets/tokens.
- `build.ps1` — runs tests in the current host, then packages
  `dist/legacy-runtime-audit-v1.0.0.zip` (scanner + README + LICENSE + notices).

## Simplest-option decisions (per task instruction to note them)

- `Get-Inventory -Rules $rules` takes the rules so it only probes the CLSIDs, file
  globs and registry values the rules actually reference; uninstall entries are always
  fully enumerated. `Find-LegacyRuntime -Inventory $inv -Rules $rules` is pure (no
  system access) so tests can feed fake inventory.
- Console evidence strings are kept ASCII (English) so PS 5.1 OEM-codepage redirection
  does not garble the table; the bilingual 繁中 + English content lives in the Markdown
  report (and the 繁中 "why" fields in JSON), where the spec requires it.
- The `.ps1` files are saved UTF-8 **with BOM** so Windows PowerShell 5.1 reads the 繁中
  rule data correctly (PS 7 needs no BOM; PS 5.1 does).
- Reader rule DisplayName regexes: `^Adobe Reader (9|X)` (covers Reader 9, X=10, XI=11)
  and `^Adobe Acrobat Reader (DC )?201[57]` (covers Reader 2015/2017 Classic under either
  naming). Reader DC continuous (`Adobe Acrobat Reader DC`) is intentionally NOT flagged.
- Exit-code semantics: info items (the IE-mode ActiveX marker) never count toward
  `findings`, so a machine with only the IE-mode marker exits 0.

## Commands run (real output)

- Tests, PowerShell 7: `pwsh -File tests/Audit.Tests.ps1` → `PASS 86/86` (exit 0).
- Tests, PowerShell 5.1: `powershell -File tests/Audit.Tests.ps1` → `PASS 86/86` (exit 0).
- Build, PowerShell 7: `pwsh -File build.ps1` → tests `PASS 86/86`,
  `OK ... dist/legacy-runtime-audit-v1.0.0.zip (9794 bytes)` (exit 0).
- Build, PowerShell 5.1: `powershell -File build.ps1` → tests `PASS 86/86`,
  `OK ... dist/legacy-runtime-audit-v1.0.0.zip (9644 bytes)` (exit 0).
  (Zip size differs only because PS 5.1 / PS 7 use different .NET zip compressors.)
- Real check on this PC (no `-IncludeComputerName`): scanner run under both 5.1 and 7 with
  `-Markdown evidence/this-pc.md -Json evidence/this-pc.json`; console output captured to
  `evidence/run-ps51.txt` (UTF-16) and `evidence/run-ps7.txt` (UTF-8). Both exits 0;
  result `findings=0 info=0` (this machine has none of the tracked runtimes).
- Packaged-artifact smoke test: extracted `dist/*.zip` to scratch and ran the extracted
  `Invoke-LegacyRuntimeAudit.ps1` under PowerShell 5.1 → `findings=0 info=0`, exit 0.

## What could NOT be verified

- GitHub Actions CI (`.github/workflows/build.yml`) was written per spec (no setup-dotnet,
  two build steps: pwsh + powershell) but NOT executed remotely — pushing is forbidden by
  the common spec; the reviewer publishes.
- The finding-rendering path (coloured table, Markdown/JSON with findings) was exercised
  offline via a scratch probe feeding a fake Flash + IE-mode inventory (rendered correctly:
  `findings=3 info=1`), because this real machine contains none of the tracked runtimes.
- Nothing deletes or uninstalls anything; the read-only hard rule is enforced by a test
  that greps the scanner for `Remove-Item`, `Set-ItemProperty`, `New-ItemProperty`,
  `Remove-ItemProperty`, `Start-Process`, `msiexec`, `reg add`, `reg delete`, `Uninstall-`
  (test passed on both engines).

## Known limits

- CLSID detection checks only the CLSIDs the rules reference (via `Test-Path` under
  `Registry::HKEY_CLASSES_ROOT\CLSID\{...}`), not a full CLSID enumeration.
- File detection resolves each rule's glob (System32/SysWOW64 under `$env:WINDIR`,
  Program Files under `$env:SystemDrive`) and matches by `-like` suffix.
- Only the 9 rules listed in the task are checked; other EOL software is out of scope.
- `-Markdown`/`-Json` write UTF-8 (no BOM); `-IncludeComputerName` defaults off for privacy.


## Reviewer verification (it-dog)

- KinTest VM (release zip only): clean scan exit 0; with a temporary HKCU uninstall key `Microsoft Silverlight` the scan reported 1 finding and exit 1; key removed afterwards. Same positive check done on the dev PC with `QuickTime 7` under PowerShell 5.1 and 7. Evidence: `evidence/vm/`, `evidence/positive-ps51.txt`.

# Changelog

## 1.0.0 - 2026-10-19

- Read-only scanner for dead/unsafe Windows runtimes (PowerShell 5.1 + 7, no modules, no dotnet).
- 9 data-driven rules: QuickTime, Silverlight, Flash Player, Shockwave Player, TrueCrypt, Java SE 6/7, out-of-support Adobe Reader, Python 2.7, and an IE-mode ActiveX dependency marker (reported as info).
- Evidence sources: uninstall registry entries (HKLM / WOW6432Node / HKCU), COM/ActiveX CLSIDs, and known file paths.
- Output: colour console table + `findings=N info=N` summary, `-Markdown`, `-Json`, optional `-IncludeComputerName`.
- Exit codes 0 (no findings) / 1 (findings) / 2 (error).
- Assert-based test suite (`tests/Audit.Tests.ps1`) including a read-only hard-rule scan for forbidden cmdlets.
- `build.ps1` runs tests and packages `dist/legacy-runtime-audit-v1.0.0.zip`.

# Legacy Runtime Audit

A strictly read-only Windows scanner that finds dead and unsafe runtimes — Apple QuickTime, Microsoft Silverlight, Adobe Flash/Shockwave, TrueCrypt, Java SE 6/7, out-of-support Adobe Reader, and Python 2.7 — plus an Internet Explorer ActiveX dependency marker. It replaces manual, error-prone checks for these retired components.

## Features

- 9 data-driven rules, each with an ID, a name, a one-sentence "why" (繁體中文 + English) and an official migration URL.
- Detects via three kinds of evidence:
  - Uninstall entries (HKLM, HKLM WOW6432Node, HKCU `...\CurrentVersion\Uninstall\*`), matched by DisplayName regex, reading DisplayVersion / Publisher / InstallLocation.
  - COM/ActiveX CLSIDs present under `Registry::HKEY_CLASSES_ROOT\CLSID`.
  - Known file paths under Program Files / System32 / SysWOW64.
- Output: a colour console table (`Rule`, `Found item`, `Version`, `Evidence`) and a `findings=N info=N` summary line.
- `-Markdown <path>` writes a bilingual report (繁體中文 + English headings); `-Json <path>` writes machine-readable JSON.
- `-IncludeComputerName` optionally adds the machine name to the report (off by default, for privacy).
- Exit codes: `0` no findings, `1` findings present, `2` script error.
- **Strictly read-only**: never writes the registry, never deletes, uninstalls or changes anything. The only files it writes are the reports you request.

## Install

Unzip the release, then run from PowerShell 5.1 or PowerShell 7:

```powershell
.\Invoke-LegacyRuntimeAudit.ps1
# with reports:
.\Invoke-LegacyRuntimeAudit.ps1 -Markdown .\report.md -Json .\report.json
```

## Build

```powershell
./build.ps1   # runs the assert-based tests, then packages dist/legacy-runtime-audit-v1.0.0.zip
```

No modules, no dotnet required.

## Privacy

The script reads the registry (uninstall entries, a small set of CLSIDs, one Edge policy value) and checks whether a few known files exist. It sends nothing over the network and writes no telemetry.

## Licence

MIT. See `LICENSE`.

---

## 功能（繁體中文）

一個嚴格唯讀的 Windows 掃描工具，用來找出過時且不安全的執行環境——Apple QuickTime、Microsoft Silverlight、Adobe Flash／Shockwave、TrueCrypt、Java SE 6/7、已停止支援的 Adobe Reader，以及 Python 2.7——另加一個 Internet Explorer ActiveX 相依性標記。它以自動化取代以往逐項手動檢查這些已退役元件的做法。

- 9 條資料驅動規則，每條包含 ID、名稱、一句「原因」（繁體中文 + English）及官方遷移網址。
- 以三種證據偵測：
  - 解除安裝項目（HKLM、HKLM WOW6432Node、HKCU 的 `...\CurrentVersion\Uninstall\*`），以 DisplayName 正則比對，並讀取 DisplayVersion／Publisher／InstallLocation。
  - 存在於 `Registry::HKEY_CLASSES_ROOT\CLSID` 的 COM/ActiveX CLSID。
  - Program Files／System32／SysWOW64 下的已知檔案路徑。
- 輸出：彩色主控台表格（`Rule`、`Found item`、`Version`、`Evidence`）及 `findings=N info=N` 摘要行。
- `-Markdown <path>` 輸出雙語報告（繁體中文 + English 標題）；`-Json <path>` 輸出機器可讀 JSON。
- `-IncludeComputerName` 可選擇在報告加入電腦名稱（預設關閉，保障私隱）。
- 結束代碼：`0` 無發現、`1` 有發現、`2` 指令碼錯誤。
- **嚴格唯讀**：絕不寫入登錄檔，絕不刪除、解除安裝或變更任何東西。唯一寫入的檔案是你要求的報告。

## 安裝

解壓縮後，於 PowerShell 5.1 或 PowerShell 7 執行：

```powershell
.\Invoke-LegacyRuntimeAudit.ps1
# 附帶報告：
.\Invoke-LegacyRuntimeAudit.ps1 -Markdown .\report.md -Json .\report.json
```

## 建置

```powershell
./build.ps1   # 執行斷言式測試，再打包 dist/legacy-runtime-audit-v1.0.0.zip
```

無需任何模組或 dotnet。

## 私隱

指令碼只讀取登錄檔（解除安裝項目、少量 CLSID、一個 Edge 政策值）並檢查少數已知檔案是否存在。它不會傳送任何資料到網路，也不產生任何遙測。

## 授權

MIT。詳見 `LICENSE`。

## Sponsor / 贊助

If this tool helps you, you can buy me a coffee. 如果這個工具對你有幫助，歡迎請我喝杯咖啡。

- Buy Me a Coffee: https://buymeacoffee.com/kinfxhk
- PayPal: https://paypal.me/sc2nohope
- PayMe (HSBC): https://payme.hsbc/kinfx

# SBOM 報表操作手冊

## 快速開始

在專案根目錄執行以下指令。工具會自動掃描 `resource-bom/` 下的各系統目錄。
如果終端提示符看似在專案目錄，錯誤卻指向垃圾桶，先用 `pwd -P` 確認實際路徑，再用 `cd -P /你的專案路徑/sbom-tools` 重新進入。

```sh
.venv/bin/python -B generate_license_excel.py  # Excel 元件清查
python3 -B analyze_bom.py                      # HTML 授權清查
```

目前 `new-gtdmcash` 的輸入已按以下結構擺放，可以直接執行。新增系統時，在 `resource-bom/` 建立另一個同樣結構的目錄。

```text
resource-bom/
└── new-gtdmcash/
    ├── bom.json
    └── bom.xml
```

| 跑完要看什麼 | 預設位置 |
| --- | --- |
| Excel 元件清單、授權查證及統計 | `reports/new-gtdmcash/new-gtdmcash-元件清查.xlsx` |
| HTML 授權清查 | `reports/index.html`，點系統名稱進入明細 |
| Excel 查證清冊 | `reports/license-list-evidence/manifest.json` |

**第一次執行 Excel**，請在支援檔案鎖定的 Unix 環境使用 Python 3.11 以上，先安裝依賴：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install openpyxl
```

Excel 需要 EOS 快照。若顯示「EOS 原廠快照不存在」，請從備份取回快照，或依下方範例用 `--allow-missing-eos` 試跑。HTML 和日期更新工具使用 Python 標準函式庫。

## 指令參數

### Excel 和 HTML 共用

| 參數 | 用途 | 省略時 |
| --- | --- | --- |
| `--input DIR` | 批次掃描 DIR 下的系統目錄 | `resource-bom/` |
| `--bom-dir DIR` | 只讀取 DIR 內的 SBOM，與 `--input` 擇一使用 | 使用批次掃描 |
| `--project NAME` | 搭配 `--bom-dir` 指定系統名稱和輸出子目錄 | 使用輸入目錄名稱 |
| `--output DIR` | 指定報表輸出根目錄 | `reports/` |
| `--evidence-dir DIR` | 指定原廠授權及 EOS 快照目錄 | `reports/license-list-evidence/` |
| `--evidence FILE` | 指定人工授權補查紀錄 | `config/license-evidence.json` |

Excel 掃描批次根目錄下一層的子目錄，每個系統要有同一批產出的 JSON 和 XML。HTML 會遞迴掃描，可讀單一格式，同一目錄有兩份時優先讀 JSON。

### Excel 專用

| 參數 | 用途 | 省略時 |
| --- | --- | --- |
| `--allow-missing-eos` | 缺少 EOS 快照時仍產檔，受影響欄位留白並記錄缺件 | 列出所有缺件並停止 |
| `--release-dates FILE` | 指定發布日期快取 | `config/release-dates.json` |

### 發布日期工具

`fetch_release_dates.py` 會連線查詢 Maven Central。它會重建指定的快取檔，範圍取決於本次輸入。

| 參數 | 用途 | 省略時 |
| --- | --- | --- |
| `--input DIR` | 批次搜尋各系統的 `bom.json` | `resource-bom/` |
| `--bom-dir DIR` | 只查詢 DIR 內的 `bom.json`，與 `--input` 擇一使用 | 使用批次掃描 |
| `--output FILE` | 指定要重建的快取檔 | `config/release-dates.json` |

三支指令都可加 `--help` 查看參數。

## 常見操作範例

### 只重產一個系統

```sh
.venv/bin/python -B generate_license_excel.py --bom-dir resource-bom/new-gtdmcash
python3 -B analyze_bom.py --bom-dir resource-bom/new-gtdmcash
```

若收到的檔案直接放在專案根目錄，把輸入改為 `--bom-dir . --project new-gtdmcash`。單獨產出 HTML 時，該輸出目錄的總覽會只列出這個系統。加 `--output /tmp/sbom-preview` 可把試跑結果寫到獨立目錄。

### 缺 EOS 快照時先試跑 Excel

```sh
.venv/bin/python -B generate_license_excel.py --allow-missing-eos --output /tmp/sbom-preview
```

受影響的 EOS 會留白，原因記在「授權查證」及清冊的 `missingEosSnapshots`。授權補查仍依原有規則核對。

### 只更新一個系統的發布日期

```sh
python3 -B fetch_release_dates.py --bom-dir resource-bom/new-gtdmcash --output /tmp/gtdmcash-release-dates.json
.venv/bin/python -B generate_license_excel.py --bom-dir resource-bom/new-gtdmcash --release-dates /tmp/gtdmcash-release-dates.json
```

Excel 只採用和當前 SBOM 的 SHA-1 相符的快取日期。舊快取缺少 SHA-1、雜湊不同或查無版本時，日期留白，原因見「授權查證」。

## 查證資料與報表判讀

### 查證快照放在哪裡

把專案備份中的快照放在 `reports/license-list-evidence/`，也可用 `--evidence-dir` 指定資料包位置。

```text
license-list-evidence/
├── eos/                            # config/eos-lifecycle.json 的 snapshot 檔案
├── serializer-2.7.3/
│   └── official-xalan-2.7.3-official.html
└── cas-client-core-4.0.4/
    └── official-cas-client-4.0.4-LICENSE
```

補查授權以 SBOM 缺漏為前提，並核對 PURL、SBOM 與 `~/.m2/repository/` 套件的實際 SHA-256，以及套件內的授權文件或原廠快照。缺少套件或授權文件時，該筆留白並記錄原因。HTML 不需要 EOS 快照。

### 常見欄位怎麼看

- 淺藍色表示該欄缺少可填資料。GPL／LGPL／AGPL 的授權欄標黃底紅字，HTML 另列人工確認順序。
- 中國來源以名單中的完整 Maven `groupId` 比對。命中填「是」並標示元件名稱及產地欄。填「否」表示未命中名單。
- 查證清冊保留輸入與報表雜湊，以及各系統的補查狀態。

2026-11-19 的 `new-gtdmcash` 試跑結果為 177 個元件，6 個補查授權，0 個授權缺漏，27 個命中 GPL／LGPL／AGPL。歷史交付詳見 [報表說明](reports.md)。

## 專案架構

工具讀取 SBOM、套用共用判定，再交由 Excel 與 HTML 各自產出報表。Excel 驗證整批輸出後才發布報表與清冊。

| 目錄或模組 | 職責 |
| --- | --- |
| `resource-bom/` | 每個系統一組 SBOM |
| `config/` | [授權證據](../config/license-evidence.json)、[EOS](../config/eos-lifecycle.json)、[產地名單](../config/china-origin-groups.json)、[報表設定](../config/report-settings.json)、[發布日期快取](../config/release-dates.json) |
| `sbom_tools/bom.py` | 讀取 CycloneDX，核對 JSON／XML 的應用識別、元件、授權、雜湊及依賴關係 |
| `sbom_tools/assessment.py`、`evidence.py` | 共用元件判定與查證 |
| `sbom_tools/excel_report.py`、`html_report.py` | 產生 Excel 與 HTML |
| `sbom_tools/release_dates.py`、`publication.py`、`paths.py` | 更新日期快取、發布報表及管理共用路徑 |
| `reports/`、`docs/` | 報表與本機快照、操作文件 |

`resource-bom/`、`reports/` 和快照目錄以 `.gitkeep` 保留。報表與本機快照可另行備份。

### 開發測試

安裝 `openpyxl` 後可離線測試 SBOM 比對、雜湊核對、產地規則、報表發布及 CLI 產檔。

```sh
.venv/bin/python -B -m unittest discover -s tests -v
```

# SBOM 第三方元件授權清單

從 CycloneDX SBOM 產生第三方元件授權清查報告。請從專案根目錄執行以下命令。

## 產生 Excel

將同一系統的 `bom.json` 與 `bom.xml` 放在 `resource-bom/<系統>/`。程式先比對兩份 SBOM，再將各系統的 Excel 寫入 `reports/<系統>/`。

```sh
.venv/bin/python -B generate_license_excel.py
```

先讀 SBOM 授權，缺漏時使用 `license-evidence.json` 並核對本機同版本 Maven JAR 雜湊與內部授權檔。JAR 未附授權時使用已保存的原廠文件。缺漏欄位留白標淺藍。GPL／LGPL／AGPL 的授權欄，以及命中中國來源名單的元件名稱和產地欄，使用黃底紅字。

產檔需要 Python 3.11 以上、openpyxl，以及支援檔案鎖定的 Unix 環境。程式直接建立九欄表頭，先暫存並驗證整批 Excel，再發布報表及查證清冊。查證方式及歷史報告見 [reports/README.md](reports/README.md)。

在 [china-origin-groups.json](china-origin-groups.json) 增刪 Maven `groupId` 來維護中國來源名單。程式逐字比對，命中填「是」，未命中依清查規則填「否」。填「否」僅表示未命中名單。

## 產生 HTML

HTML 使用 Python 標準函式庫。同一目錄若有兩種格式，優先讀取 JSON。Excel 與 HTML 採用同一套授權補查規則，補查須符合 SBOM 與本機套件的 SHA-256，並核對授權文件。

```sh
python3 -B analyze_bom.py --input resource-bom --output reports --evidence license-evidence.json
```

## 更新發布日期

當輸入 SBOM 有變動時，可連線查詢 Maven Central，重建 Excel 使用的 `release-dates.json`。重產 Excel 時會重新比對快取所記錄的 SHA-1。舊快取缺少已核對的 SHA-1 時，日期留白並在「授權查證」說明原因。

```sh
python3 -B fetch_release_dates.py
```

## 程式分工

| 檔案 | 職責 |
| --- | --- |
| `sbom_tools/bom.py` | 讀取 CycloneDX 與比對 JSON/XML |
| `sbom_tools/assessment.py`、`evidence.py` | 建立共用元件結果，核對授權、發布日期、EOS 與產地名單 |
| `sbom_tools/excel_report.py`、`html_report.py` | 產生 Excel 與 HTML 報表 |
| `sbom_tools/release_dates.py`、`publication.py` | 更新發布日期快取、發布已驗證的報表 |

用標準函式庫執行離線測試，涵蓋 SBOM 比對、授權與發布日期雜湊核對、產地比對及發布失敗時回復。

```sh
python3 -B -m unittest discover -s tests -v
```

# sbom-tools

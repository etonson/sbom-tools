# SBOM 第三方元件授權清單

從 CycloneDX SBOM 產生第三方元件授權清查報告。請從專案根目錄執行以下命令。

## 產生 Excel

將同一系統的 `bom.json` 與 `bom.xml` 放在 `resource-bom/<系統>/`。程式先比對兩份 SBOM，再將各系統的 Excel 寫入 `reports/<系統>/`。

```sh
.venv/bin/python -B generate_license_excel.py
```

先讀 SBOM 授權，缺漏時使用 `license-evidence.json` 並核對本機同版本 Maven JAR 雜湊與內部授權檔。JAR 未附授權時使用已保存的原廠文件。缺漏欄位留白標淺藍，GPL／LGPL／AGPL 與已確認中國來源元件標黃底紅字。

產檔需要 Python 3 與 openpyxl，並使用本機的補充資料、範本與查證快照。查證方式及歷史報告見 [reports/README.md](reports/README.md)。

## 產生 HTML

HTML 只需要 Python 3。同一目錄若有兩種格式，優先讀取 JSON。

```sh
python3 -B analyze_bom.py --input resource-bom --output reports --evidence license-evidence.json
```

## 更新發布日期

當輸入 SBOM 有變動時，可連線查詢 Maven Central，重建 Excel 使用的 `release-dates.json`。產生 Excel 與 HTML 時可離線執行。

```sh
python3 -B fetch_release_dates.py
```

## 程式分工

| 檔案 | 職責 |
| --- | --- |
| `sbom_common.py` | 讀取 CycloneDX JSON/XML、比對兩種格式、讀取授權證據和辨識授權類型 |
| `analyze_bom.py` | 判讀授權並產生 HTML 總覽與明細，樣式取自 `report.css` |
| `generate_license_excel.py` | 核對本機授權證據、建立及驗證 Excel、寫出查證清冊 |
| `fetch_release_dates.py` | 查詢 Maven Central 的發布時間並核對套件 SHA-1 |

# sbom-tools

# 各系統元件授權清單

要產生新報表，請先看 [快速開始與參數說明](README.md)。

以下是 2026-11-09 的歷史交付紀錄。當時採用原始範本的九欄格式，每個系統一份 Excel。

| 系統 | Excel | 元件數 | SBOM 已記載授權 | 補查授權 | 授權仍缺漏 | GPL／LGPL／AGPL 標記 |
|---|---|---:|---:|---:|---:|---:|
| 鄉鎮市出納 | [new-gtdmcash-元件清查.xlsx](../reports/new-gtdmcash/new-gtdmcash-元件清查.xlsx) | 177 | 171 | 6 | 0 | 27 |
| 市縣出納支付 | [new-gten-元件清查.xlsx](../reports/new-gten/new-gten-元件清查.xlsx) | 204 | 203 | 1 | 0 | 24 |

GPL／LGPL／AGPL 標記包括多重授權與例外條款。同一元件僅計一次，供人工覆核。最新操作方式見 [操作說明](README.md)。

## 重產方式

在專案根目錄執行：

```sh
.venv/bin/python -B generate_license_excel.py
```

輸入為 `resource-bom/*/bom.json`、對應 `bom.xml`、`config/` 內的設定及 `reports/license-list-evidence/` 的原廠文件。需要 Python 3.11 以上與 openpyxl。程式離線執行，為各組 SBOM 直接建立九欄報告並寫出查證 manifest。

## 查證順序及標示

1. 優先使用 SBOM 授權；JSON/XML 的應用識別、元件、版本、授權、雜湊及依賴關係須一致。
2. 授權缺漏時比對補充資料的 PURL 與 SHA-256，再核對 `~/.m2/repository/` 對應套件的實際 SHA-256。Excel 將核對過的內部授權文件保存於 `license-list-evidence/artifacts/`，按 Maven 套件路徑與 SHA-256 存放。
3. jaxen、oro、xalan、OpenPDF 以內部授權檔佐證。serializer、CAS Client 未附 LICENSE，另核對原廠文件，保存快照及來源網址。補查的 7 筆涉及 6 個不同套件（OpenPDF 出現於兩個系統）。
4. 查無結果欄位留白並填淺藍色。GPL／LGPL／AGPL 的授權欄標黃底紅字。Maven `groupId` 與 `china-origin-groups.json` 逐字比對，命中填「是」，元件名稱及產地欄標黃底紅字。
5. 來源欄使用 mvnrepository 連結，由 group／artifact／version 組成，未逐筆開啟；SBOM 記載的專案網址保留在「授權查證」。
6. 套件用途使用 SBOM description 原文。發布日期取 Maven Central 的 JAR Last-Modified（UTC），僅 SHA-1 與 SBOM 相符者填入，存於 `config/release-dates.json`，早期版本可能晚於實際發布；需更新時先執行 `.venv/bin/python -B fetch_release_dates.py`（需連網）。EOS 僅填原廠公告的日期或維護狀態，規則在 `config/eos-lifecycle.json`，原廠快照在 `license-list-evidence/eos/`，狀態以查證日為準；其餘留白，沒有沿用範本推定值。「是否為大陸產品」未發現中國來源者依專案負責人指示填「否」，非逐一查證。

本批 SBOM 沒有 fastjson。`com.hynnet:jacob-jdk15` 本機 POM 記載發布者 hynnet, Inc.，但未能核實國別，依指示填「否」並加註說明；授權欄依 LGPL 標黃底紅字。未僅因使用中文或 namespace 就認定產地。

每份檔案含「系統元件清單」、「授權查證」、「清查說明」、「授權組合統計」四張工作表，第一張使用系統名稱。查證頁保留完整座標、PURL、SHA-256、原始授權、補查來源及檔案位置。新產出的 `license-list-evidence/manifest.json` 以 `componentsByProject` 記錄各系統的補查狀態，並保存輸入設定、SBOM、證據及報告雜湊。

多筆授權保留原文及適用範圍，不擅自推定 AND／OR。OpenPDF 的 Apache-2.0 僅適用部分檔案，另列 LGPL 2.1、MPL 2.0；CAS Client 保留 Apache-2.0 及 BSD-3-Clause 記載。

產檔後會讀回 Excel，檢查元件筆數、所有空白儲存格的淺藍底、指定授權的黃底紅字及 XLSX 內 XML 可解析性。這不等於 CycloneDX schema 或法律合規審查。證據目錄及補充資料請一併備份。

## 原廠文件來源

- serializer：[Apache Xalan-Java 2.7.3](https://xalan.apache.org/xalan-j/)，保存於 `license-list-evidence/serializer-2.7.3/official-xalan-2.7.3-official.html`。
- CAS Client：[原廠 cas-client-4.0.4 LICENSE](https://github.com/apereo/java-cas-client/blob/cas-client-4.0.4/LICENSE)，保存於 `license-list-evidence/cas-client-core-4.0.4/official-cas-client-4.0.4-LICENSE`。

## 既有 HTML 報告

如需更新另有的 HTML 清查報告，從根目錄執行：

```sh
python3 -B analyze_bom.py --input resource-bom --output reports --evidence config/license-evidence.json
```

Excel 與 HTML 使用 `config/license-evidence.json`。

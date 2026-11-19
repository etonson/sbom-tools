#!/usr/bin/env python3
"""Generate offline Traditional Chinese license inventories from CycloneDX BOMs."""

import argparse
import html
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote

from sbom_common import (
    FAMILIES,
    classify,
    digest,
    flatten,
    gpl_without_multiple_licenses,
    has_exception,
    has_license,
    load_bom,
    load_evidence,
    sha256_of,
)


def effective_licenses(component):
    """BOM licenses win; a supplement is only consulted when the BOM has none."""
    if any(has_license(entry) for entry in component["licenses"]):
        return component["licenses"]
    return component.get("supplement", {}).get("licenses", [])


ASSESSMENT_LABELS = {
    "priority": "優先人工確認",
    "review": "授權條件確認",
    "outside": "未命中本次關注授權",
    "unknown": "授權資訊不足",
}


def assess_component(component):
    """Assign a review queue, never a legal compliance decision."""
    licenses = effective_licenses(component)
    families = classify(licenses)
    if not any(has_license(entry) for entry in licenses):
        category = "unknown"
        reason = "BOM 未提供授權資訊，尚不能判定是否屬於本次清查範圍。"
        action = "補查該版本的原廠 LICENSE、POM 或官方授權文件，更新 BOM 後重新清查。"
        status = "待補充授權資料"
    elif "AGPL" in families:
        category = "priority"
        reason = "授權資訊含 AGPL，需優先確認實際採用條款及網路服務情境；此分類不代表違規。"
        action = "確認實際授權路徑、是否修改元件、網路互動及交付方式，交由授權負責人覆核。"
        status = "尚待人工確認"
    elif gpl_without_multiple_licenses(licenses):
        category = "priority"
        reason = ("BOM 未記載其他授權，且包含例外條款；例外具有適用條件，需確認實際使用與交付方式。"
                  if has_exception(licenses) else
                  "BOM 僅記載 GPL，未記載多重授權或例外條款；需優先確認實際使用與交付方式。")
        action = "確認使用／修改方式、是否對外交付及例外適用條件，並核對該版本的原廠授權或既有商業授權。"
        status = "尚待人工確認"
    elif families:
        category = "review"
        reason = ("授權資訊含 LGPL，需確認適用授權條件；若並列其他授權，BOM 欄位本身不表示可任選。"
                  if "LGPL" in families else
                  "BOM 記載 GPL 與其他授權或例外條款；需確認授權關係及實際可採用的條款。")
        action = ("確認實際採用的授權、是否修改函式庫、連結與交付方式，再依適用條款確認相應義務。"
                  if "LGPL" in families else
                  "核對該版本的原廠授權文件及 AND／OR 關係，確認所採授權與例外條件，不以 GPL 字樣直接判定。")
        status = "尚待人工確認"
    else:
        category = "outside"
        reason = "授權欄位未命中 GPL／AGPL／LGPL；其他授權義務不在本次自動篩選範圍。"
        action = "保留授權及著作權聲明，依實際條款另行確認義務；自訂或不明名稱仍需核實。"
        status = "未評估其他授權義務"
    if "supplement" in component:
        reason = "BOM 未記載授權，依人工補充的原廠授權證據判讀。" + reason
        status = "人工補充授權（附證據）；" + status
    return {"component": component, "category": category, "reason": reason,
            "action": action, "status": status}


def analyze(data, evidence=None):
    # Identity includes version and purl; repeated records contribute all license entries.
    unique = {}

    for component in flatten(data.get("components", []) or []):
        key = tuple(component.get(k, "") for k in ("group", "name", "version", "purl"))
        if key not in unique:
            unique[key] = {**component, "licenses": []}
        licenses = unique[key]["licenses"]
        for entry in component.get("licenses", []) or []:
            if entry not in licenses:
                licenses.append(entry)
    components = sorted(unique.values(), key=lambda c: (c.get("group", ""), c.get("name", ""), c.get("version", "")))
    groups = {family: [] for family in FAMILIES}
    missing = []
    mismatched = []
    matched = 0
    for component in components:
        if not any(has_license(entry) for entry in component["licenses"]):
            missing.append(component)
            record = (evidence or {}).get(component.get("purl", ""))
            if record and record["sha256"].lower() in sha256_of(component):
                component["supplement"] = record
            elif record:
                # Evidence describes a different binary; never apply it.
                mismatched.append(component)
        families = classify(effective_licenses(component))
        matched += bool(families)
        for family in families:
            groups[family].append(component)
    gpl_single = [c for c in groups["GPL"] if gpl_without_multiple_licenses(effective_licenses(c))]
    assessments = [assess_component(component) for component in components]
    queues = {category: [a for a in assessments if a["category"] == category]
              for category in ASSESSMENT_LABELS}
    return {"total": len(components), "matched": matched, "groups": groups, "missing": missing,
            "supplemented": [c for c in missing if "supplement" in c], "mismatched": mismatched,
            "assessments": assessments, "queues": queues,
            "gpl_single": gpl_single,
            "gpl_single_no_exception": [c for c in gpl_single if not has_exception(effective_licenses(c))],
            "gpl_single_with_exception": [c for c in gpl_single if has_exception(effective_licenses(c))]}


def escape(value):
    return html.escape(str(value), quote=True)


def license_html(entries):
    parts = []
    for entry in entries:
        if entry.get("expression"):
            parts.append("<li>授權運算式：" + escape(entry["expression"]) + "</li>")
        license = entry.get("license", {})
        labels = [license[k] for k in ("id", "name") if license.get(k)]
        url = license.get("url", "")
        if url:
            # Only web URLs become links. All source strings remain visible and escaped.
            link = (f'<a href="{escape(url)}" rel="noreferrer">{escape(url)}</a>'
                    if re.match(r"^https?://", url, re.I) else escape(url))
            labels_html = " / ".join(escape(label) for label in labels)
            parts.append(f"<li>{labels_html}<small>{link}</small></li>")
        elif labels:
            parts.append("<li>" + " / ".join(escape(label) for label in labels) + "</li>")
    return '<ul class="licenses">' + "".join(parts) + "</ul>"


def supplement_html(component):
    record = component.get("supplement")
    if not record:
        return ""
    items = "".join(f"<li>{escape(item)}</li>" for item in record["evidence"])
    return ('<div class="supplement"><span class="badge badge-supplement">人工補充（BOM 未記載）</span>'
            + license_html(record["licenses"])
            + f'<ul class="evidence-list">{items}</ul>'
            + f'<small>綁定 SHA-256：{escape(record["sha256"])}；查證：{escape(record.get("reviewedBy", "未提供"))}'
              f' {escape(record.get("reviewedAt", ""))}</small></div>')


def detection_html(component):
    if any(has_license(e) for e in component["licenses"]):
        return license_html(component["licenses"])
    return "BOM 未提供授權資訊" + supplement_html(component)


def component_table(components, include_licenses=True):
    if not components:
        return '<p class="empty">無符合元件。</p>'
    rows = []
    for component in components:
        name = ":".join(filter(None, [component.get("group"), component.get("name")]))
        cells = f'<td class="component">{escape(name)}</td><td>{escape(component.get("version") or "未提供")}</td>'
        if include_licenses:
            cells += "<td>" + detection_html(component) + "</td>"
        elif "supplement" in component:
            cells += "<td>" + supplement_html(component) + "</td>"
        else:
            cells += "<td>—</td>"
        rows.append("<tr>" + cells + "</tr>")
    return ('<div class="table-wrap"><table><thead><tr><th scope="col">元件（groupId:artifactId）</th>'
            '<th scope="col">版本</th>' + ('<th scope="col">BOM 記載授權</th>' if include_licenses
                                         else '<th scope="col">人工補充授權</th>')
            + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>")


CSS = Path(__file__).with_name("report.css").read_text(encoding="utf-8")

SCRIPT = """
function revealTarget() {
  const target = document.getElementById(location.hash.slice(1));
  if (target && target.tagName === 'DETAILS') {
    target.open = true;
    requestAnimationFrame(() => target.scrollIntoView({block: 'start'}));
  }
}
window.addEventListener('hashchange', revealTarget);
document.addEventListener('click', event => {
  const link = event.target.closest('a[href^="#"]');
  if (link && link.hash === location.hash) revealTarget();
});
revealTarget();
let printState = [];
window.addEventListener('beforeprint', () => {
  printState = [...document.querySelectorAll('details:not(.evidence)')].map(el => [el, el.open]);
  printState.forEach(([el]) => { el.open = true; });
});
window.addEventListener('afterprint', () => {
  printState.forEach(([el, open]) => { el.open = open; });
});
"""


def page(title, content):
    return (f'<!doctype html>\n<html lang="zh-Hant"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{escape(title)}</title><style>{CSS}</style></head><body><main>{content}</main>'
            f'<script>{SCRIPT}</script></body></html>\n')


def disclosure(title, body, hint="", element_id=""):
    identity = f' id="{escape(element_id)}"' if element_id else ""
    return (f'<details{identity}><summary>{title}'
            + (f'<small>{escape(hint)}</small>' if hint else "")
            + f'</summary><div>{body}</div></details>')


def evidence_html(component):
    fragment = {k: component[k] for k in ("group", "name", "version", "purl", "licenses") if k in component}
    if "supplement" in component:
        fragment["人工補充（非 BOM 原文）"] = component["supplement"]
    return ('<details class="evidence"><summary>查看 BOM 授權資料</summary><pre>'
            + escape(json.dumps(fragment, ensure_ascii=False, indent=2)) + '</pre></details>')


def assessment_table(assessments):
    if not assessments:
        return '<p class="empty">無符合元件。</p>'
    rows = []
    for assessment in assessments:
        c = assessment["component"]
        category = assessment["category"]
        name = ":".join(filter(None, [c.get("group"), c.get("name")]))
        detection = detection_html(c)
        rows.append(f'<tr><td class="component">{escape(name)}<small>{escape(c.get("version") or "未提供版本")}</small>{evidence_html(c)}</td>'
                    f'<td>{detection}</td><td><span class="badge badge-{category}">{ASSESSMENT_LABELS[category]}</span>'
                    f'<p>{escape(assessment["reason"])}</p><div class="status">狀態：{escape(assessment["status"])}</div></td>'
                    f'<td>{escape(assessment["action"])}</td></tr>')
    return ('<div class="table-wrap"><table><thead><tr><th scope="col">元件／版本</th>'
            '<th scope="col">授權偵測（BOM 原文）</th><th scope="col">初步評估／判定狀態</th>'
            '<th scope="col">建議處理</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>')


def risk_cards(result, links=True):
    descriptions = {
        "priority": "先確認使用、交付方式及適用授權條款",
        "review": "確認多筆授權、例外條款或 LGPL 相應義務",
        "outside": "本次篩選未命中，不代表已通過合規審查",
        "unknown": "補充原廠授權資訊後再確認",
    }
    cards = []
    for category, label in ASSESSMENT_LABELS.items():
        tag = 'a' if links else 'div'
        href = f' href="#queue-{category}"' if links else ''
        cards.append(f'<{tag} class="risk-card {category}"{href}><span class="label">{label}</span>'
                     f'<strong>{len(result["queues"][category])}</strong><span class="desc">{descriptions[category]}</span></{tag}>')
    return '<div class="risk-grid">' + ''.join(cards) + '</div>'


def priority_card(assessment):
    c = assessment["component"]
    name = ":".join(filter(None, [c.get("group"), c.get("name")]))
    return f'''<article class="task priority"><div class="task-head"><div>
<span class="badge badge-priority">優先人工確認</span><h3>{escape(name)}</h3>
<span class="version">版本 {escape(c.get('version') or '未提供')}</span></div>
<span class="status">狀態：{escape(assessment['status'])}</span></div>
<div class="task-grid"><div><div class="field-label">授權偵測 · BOM 原始記載</div>
{detection_html(c)}{evidence_html(c)}</div>
<div><div class="field-label">初步評估 · 為何列入</div><p>{escape(assessment['reason'])}</p>
<div class="field-label">建議處理</div><p>{escape(assessment['action'])}</p>
<a class="action-link" href="#usage-checklist">確認使用與交付方式</a>
<a class="action-link" href="#official-sources">核對官方授權條款</a></div></div></article>'''


def supplement_note(result):
    note = ""
    if result["supplemented"]:
        note += (f'<p class="note">其中 {len(result["supplemented"])} 個元件 BOM 未記載授權，'
                 '已依原廠授權證據人工補充後分類，逐項標示「人工補充（BOM 未記載）」；'
                 '<a href="#bom-missing">查看清單</a>。</p>')
    if result["mismatched"]:
        names = "、".join(c.get("name", "") for c in result["mismatched"])
        note += (f'<p class="note">警告：{escape(names)} 有補充紀錄但 SHA-256 與 BOM 不符，未套用，'
                 '請重新查證該版本。</p>')
    return note


def render_report(project, source, data, result):
    metadata = data.get("metadata", {})
    application = metadata.get("component", {})
    source_digest = digest(source)
    content = f'''<header><div class="topline"><span class="eyebrow">第三方元件開源授權風險清查</span><span class="project">{escape(project)}</span></div>
<h1>開源授權風險清查報告</h1>
<p class="subtitle">依據 SBOM 授權資訊進行自動化篩選，區分「授權偵測」與「初步風險評估」；不以授權字樣直接判定違規或原始碼公開義務。</p></header>
<section class="risk-hero"><h2>本次需要採取的處理</h2>
<p class="scan-count">掃描系統 <b>{escape(application.get('name', project))}</b>，共 <strong>{result['total']}</strong> 個第三方元件。</p>
{risk_cards(result)}
<div class="disclaimer"><strong>判讀原則：</strong>授權名稱是偵測事實，處理分類是人工覆核的起點。本報告為自動化授權清查，不代表法律意見或違規判定。</div>
<p class="queue-total">四類互斥，每個元件只計一次；合計 {result['total']} 個。點選卡片查看對應項目。</p>
{supplement_note(result)}</section>
<div class="toolbar"><h2>需要處理的項目</h2><button type="button" onclick="window.print()">列印／另存 PDF</button></div>
<p class="section-intro">左側保留 BOM 授權事實，右側說明確認原因與建議；尚未完成人工覆核的項目不標記為已合規。</p>
<section id="queue-priority"><h3>優先人工確認 <span class="count">{len(result['queues']['priority'])} 個</span></h3>'''
    content += ''.join(priority_card(a) for a in result['queues']['priority']) or '<p class="empty">無需優先確認的元件。</p>'
    content += '</section>'
    hints = {
        "review": "核對授權關係、例外適用條件、使用／修改與交付方式。",
        "unknown": "授權資訊缺漏，需補充原廠授權證據；不歸入一般授權。",
        "outside": "仍保留逐項授權原文；未命中本次關注範圍不代表無其他義務。",
    }
    for category in ("review", "unknown", "outside"):
        content += disclosure(f'{ASSESSMENT_LABELS[category]} <span class="count">{len(result["queues"][category])} 個</span>',
                              assessment_table(result["queues"][category]), hints[category], f'queue-{category}')
    checklist = '''<ol class="method-list"><li>確認元件用途、連結方式、是否修改第三方程式碼。</li>
<li>確認是否僅組織內部使用、對外提供網路服務，或交付 WAR／JAR 等副本；記錄交付對象與方式。</li>
<li>核對實際版本的 LICENSE、例外條款、授權運算式及既有商業授權文件，記錄採用依據。</li>
<li>由授權負責人覆核後記錄結論；目前報告不保存人工審查結果，重新產生時仍呈現自動分類。</li></ol>'''
    content += disclosure('人工確認清單', checklist, element_id='usage-checklist')
    content += '<h2>授權偵測明細</h2><p class="section-intro">以下為關鍵字命中與 BOM 記載分類，並非違規數量。跨授權類別可能重複，關注授權命中元件總數只計一次。</p>'
    content += '<div class="hit-counts">' + ''.join(f'<span>{f} 關鍵字命中：{len(result["groups"][f])}</span>' for f in FAMILIES) + f'<span>命中元件共 {result["matched"]} 個</span></div>'
    gpl_other = len(result['groups']['GPL']) - len(result['gpl_single'])
    content += f'''<p class="note">GPL 偵測分組：多筆授權記錄或組合運算式 {gpl_other} 個；
未記載多重授權且附例外條款 {len(result['gpl_single_with_exception'])} 個；
未記載多重授權及例外條款 {len(result['gpl_single_no_exception'])} 個。
多筆授權若未明示 AND／OR，本報告不自行推定可任選，也不將例外條款視為另一項授權。</p>'''
    for family in ("LGPL", "GPL", "AGPL"):
        content += disclosure(f'{family}：{len(result["groups"][family])} 個', component_table(result['groups'][family]),
                              "依 BOM 原文保留其他授權、運算式及例外條款。")
    content += disclosure(f'GPL 未記載多重授權：{len(result["gpl_single"])} 個',
                          f'<h3>未記載例外條款：{len(result["gpl_single_no_exception"])} 個</h3>'
                          + component_table(result['gpl_single_no_exception'])
                          + f'<h3>附例外條款：{len(result["gpl_single_with_exception"])} 個</h3>'
                          + component_table(result['gpl_single_with_exception']),
                          '單筆非空授權且未辨識到多授權組合；不能排除 BOM 未記載的商業授權等方案。', 'gpl-single')
    content += disclosure(f'BOM 未提供授權資訊：{len(result["missing"])} 個（已人工補充 {len(result["supplemented"])} 個）',
                          component_table(result['missing'], False),
                          "BOM 原文缺漏的事實保留於此；人工補充僅在 purl 與 SHA-256 皆相符時套用。", 'bom-missing')
    official = '''<p>授權偵測不等於開源義務判定。實際義務須依授權版本、使用、修改、交付方式與適用例外確認。</p>
<ul class="source-links"><li><a href="https://www.gnu.org/licenses/gpl-faq.html#GPLRequireSourcePostedPublic">GNU FAQ：原始碼提供</a></li>
<li><a href="https://www.gnu.org/licenses/gpl-faq.html#InternalDistribution">GNU FAQ：組織內部使用</a></li>
<li><a href="https://www.mysql.com/about/legal/licensing/oem/">MySQL 官方授權說明</a>：Universal FOSS Exception 有適用條件，不能直接視為允許所有閉源系統使用。</li></ul>'''
    content += disclosure('授權判讀與官方參考', official, element_id='official-sources')
    method = f'''<div class="meta">系統：{escape(application.get('name', project))}　版本：{escape(application.get('version', '未提供'))}<br>
來源：{escape(source.as_posix())}<br>BOM 時間：{escape(metadata.get('timestamp', '未提供'))}<br>來源 SHA-256：{source_digest}</div>
<ul class="method-list"><li>以 BOM 授權 ID、名稱、運算式、URL 辨識 GPL／AGPL／LGPL 縮寫及 GNU 英文全名，支援 LGPL 常見 GNU 連結。</li>
<li>優先確認：AGPL 命中，或 GPL 未記載多重授權（包含附例外條款）；條件確認：其餘關注授權命中元件。此順序僅為人工確認優先序。</li>
<li>未提供任何非空授權欄位歸為資訊不足；其餘未命中項目不表示一般／安全授權，也未評估其他義務。</li>
<li>BOM 未記載授權的元件，若在 license-evidence.json 有人工查證紀錄，且 purl 與元件 SHA-256 皆相符，改以該紀錄分類並標示「人工補充（BOM 未記載）」，附證據、查證人與日期；BOM 有授權時一律以 BOM 為準。</li>
<li>只計 components 與巢狀元件，不計系統本身與產生工具；依 group、name、version、purl 合併重複元件及授權。每項「BOM 授權資料」呈現合併後的授權欄位摘錄。</li>
<li>自訂名稱、連結或不完整資料可能影響關鍵字判讀；完整法律適用需人工核對，報告不推定多欄位間的 AND／OR。</li></ul>'''
    content += disclosure('資料來源與分析方法', method)
    content += '<footer>本報告保留 BOM 授權記載，將自動偵測與人工覆核事項分開呈現。授權篩選結果不構成法律意見或合規結論。</footer>'
    return page(project + ' 開源授權風險清查報告', content)


def render_index(prepared):
    total = sum(item[3]['total'] for item in prepared)
    combined = {'queues': {category: [a for item in prepared for a in item[3]['queues'][category]] for category in ASSESSMENT_LABELS}}
    content = ('<header><div class="eyebrow">第三方元件開源授權風險清查</div><h1>各系統處理摘要</h1>'
               '<p class="subtitle">依需要採取的處理安排人工覆核；授權名稱命中不等於違規或原始碼公開義務。</p></header>'
               f'<section class="risk-hero"><h2>{len(prepared)} 個系統 · {total} 筆專案元件</h2>'
               + risk_cards(combined, links=False)
               + '<div class="disclaimer">本報告為自動化授權清查，不代表法律意見或違規判定。跨系統共用元件按各系統分別計數，四類合計等於專案元件總數。</div></section>')
    rows = []
    for project, relative, _, result in prepared:
        rows.append(f'<tr><td><a href="{quote(relative.as_posix())}">{escape(project)}</a></td><td>{result["total"]}</td>'
                    + ''.join(f'<td>{len(result["queues"][category])}</td>' for category in ASSESSMENT_LABELS) + '</tr>')
    content += ('<div class="table-wrap"><table><thead><tr><th>系統報告</th><th>元件總數</th>'
                + ''.join(f'<th>{label}</th>' for label in ASSESSMENT_LABELS.values())
                + '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>')
    content += '<footer>點選系統名稱查看確認原因、處理建議、授權偵測明細及原始授權資料。</footer>'
    return page('各系統開源授權風險清查', content)


def main():
    parser = argparse.ArgumentParser(description="逐專案產生開源授權風險清查 HTML，區分偵測與人工確認事項（無外部套件）")
    parser.add_argument("--input", type=Path, default=Path("resource-bom"), help="BOM 根目錄")
    parser.add_argument("--output", type=Path, default=Path("reports"), help="HTML 輸出目錄")
    parser.add_argument("--evidence", type=Path, default=Path("license-evidence.json"),
                        help="人工查證的補充授權（檔案不存在則不套用）")
    args = parser.parse_args()
    try:
        evidence = load_evidence(args.evidence)
    except (ValueError, OSError, KeyError, AttributeError) as error:
        print(f"補充授權讀取失敗：{args.evidence}：{error}", file=sys.stderr)
        return 1
    # Prefer JSON over XML in each directory, so paired formats never count twice.
    sources = {}
    for path in sorted(args.input.rglob("bom.xml")):
        sources[path.parent] = path
    for path in sorted(args.input.rglob("bom.json")):
        sources[path.parent] = path
    if not sources:
        parser.error(f"{args.input} 找不到 bom.json 或 bom.xml")
    prepared = []
    for directory, source in sorted(sources.items()):
        relative = directory.relative_to(args.input)
        project = relative.as_posix() if relative.parts else directory.name
        target = relative / "license-report.html"
        try:
            data = load_bom(source)
            result = analyze(data, evidence)
        except (ValueError, OSError, ET.ParseError, TypeError, AttributeError) as error:
            print(f"分析失敗：{source}：{error}", file=sys.stderr)
            return 1
        prepared.append((project, target, render_report(project, source, data, result), result))
    for project, relative, report, result in prepared:
        target = args.output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(report, encoding="utf-8")
        summary = ', '.join(f'{label}={len(result["queues"][category])}'
                            for category, label in ASSESSMENT_LABELS.items())
        print(f'{project}: {summary} → {target}')
    (args.output / "index.html").write_text(render_index(prepared), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

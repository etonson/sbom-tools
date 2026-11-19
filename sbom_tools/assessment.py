"""Apply inventory rules independently of report presentation."""

from .bom import classify, flatten, gpl_without_multiple_licenses, has_exception, has_license, sha256_of
from .evidence import eos_for, release_for, resolve_license, sha1_of


def evaluate_components(data, evidence, china_origin_groups=(), releases=None, lifecycle=None):
    """Use one component identity and the same rules in both reports."""
    components = {}
    for component in flatten(data.get('components') or []):
        coordinate = tuple(component.get(key, '') for key in ('group', 'name', 'version', 'purl'))
        sha256 = sha256_of(component)
        key = (*coordinate, frozenset(sha256), frozenset() if sha256 else frozenset(sha1_of(component)))
        original = component.get('licenses') or []
        if key not in components:
            components[key] = {**component, 'licenses': list(original)}
            continue
        current = components[key]
        for entry in original:
            if entry not in current['licenses']:
                current['licenses'].append(entry)

    releases = releases or {}
    lifecycle = lifecycle or {}
    ordered = sorted(components.values(), key=lambda c: (
        c.get('group', ''), c.get('name', ''), c.get('version', '')
    ))
    for component in ordered:
        result = resolve_license(component, evidence)
        component['license_result'] = result
        component['license_families'] = classify(result['licenses'])
        if result['status'] == 'verified':
            component['supplement'] = result['record']
        component['origin_match'] = component.get('group') in china_origin_groups
        component['release'] = release_for(component, releases)
        component['eos'] = eos_for(component, lifecycle)
    return ordered


def effective_licenses(component):
    return component['license_result']['licenses']


ASSESSMENT_LABELS = {
    "priority": "優先人工確認",
    "review": "授權條件確認",
    "outside": "未命中本次關注授權",
    "unknown": "授權資訊不足",
}


def assess_component(component):
    """Assign a review queue, never a legal compliance decision."""
    licenses = effective_licenses(component)
    families = component['license_families']
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

#!/usr/bin/env python3
"""Rebuild per-system Excel inventories, using SBOM first and verified evidence second."""
import json
import math
import re
import unicodedata
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from pathlib import Path

from openpyxl import Workbook, load_workbook
from openpyxl.comments import Comment
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from sbom_common import (
    check_pair,
    classify,
    digest,
    flatten,
    has_license,
    load_evidence,
    require,
    sha256_of,
)

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'reports'
EVIDENCE = OUT / 'license-list-evidence'
CHINA_ORIGIN_GROUPS = ROOT / 'china-origin-groups.json'
BLUE = 'DDEBF7'
YELLOW = 'FFFF00'
RED = 'FF0000'
INVENTORY_WIDTHS = (7.5, 35.5, 23, 50, 18.66, 46.51, 65, 18, 35)
INVENTORY_HEADERS = ('序', '元件名稱', '版號', '套件用途', '發布日期', '來源', '授權方式', '是否為大陸產品', 'EOS')
SYSTEMS = {'new-gtdmcash': '鄉鎮市出納', 'new-gten': '市縣出納支付'}


def load_china_origin_groups(path):
    groups = json.loads(path.read_text(encoding='utf-8-sig'))
    require(isinstance(groups, list) and all(
        isinstance(group, str) and group and group == group.strip() for group in groups
    ), f'{path.name} 須為 Maven groupId 字串陣列，項目不可空白或含有前後空格')
    return set(groups)


def labels(entries):
    result = []
    for entry in entries:
        if entry.get('expression'):
            result.append(entry['expression'])
        else:
            lic = entry.get('license', {})
            value = lic.get('id') or lic.get('name') or lic.get('url')
            if value:
                if lic.get('id') and lic.get('name'):
                    value += '（' + lic['name'] + '）'
                result.append(value)
    return '; '.join(result)


def supplement(component, records):
    """Accept prior reviewed evidence only after checking the exact local artifact."""
    record = records.get(component.get('purl'))
    if not record:
        return [], [], '補充資料無相符 PURL；授權留白'
    require(record['sha256'].lower() in sha256_of(component), '補充資料與 SBOM SHA-256 不符')
    g, a, v = (component[k] for k in ('group', 'name', 'version'))
    jar = Path.home() / '.m2/repository' / g.replace('.', '/') / a / v / f'{a}-{v}.jar'
    if not jar.exists():
        return [], [], f'本機無同版本 JAR：{jar}；授權留白'
    require(digest(jar) == record['sha256'].lower(), f'JAR SHA-256 不符：{jar}')
    target = EVIDENCE / f'{a}-{v}'
    target.mkdir(parents=True, exist_ok=True)
    files = []
    with zipfile.ZipFile(jar) as archive:
        for name in archive.namelist():
            base = Path(name).name
            if not base or not re.search(r'license|licence|copying|notice|^MANIFEST\.MF$', base, re.I):
                continue
            # Preserve archive paths to avoid collisions between embedded licenses.
            relative = Path(name)
            if relative.is_absolute() or '..' in relative.parts:
                continue
            dest = target / 'jar' / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(archive.read(name))
            files.append({'path': str(dest.relative_to(ROOT)), 'sha256': digest(dest), 'jarEntry': name})
    official = {
        'serializer': ('official-xalan-2.7.3-official.html', 'https://xalan.apache.org/xalan-j/'),
        'cas-client-core': ('official-cas-client-4.0.4-LICENSE',
                            'https://raw.githubusercontent.com/apereo/java-cas-client/cas-client-4.0.4/LICENSE'),
    }
    if a in official:
        filename, url = official[a]
        source = target / filename
        if not source.exists():
            return [], files, 'JAR 未附 LICENSE，原廠快照不存在；授權留白'
        files.append({'path': str(source.relative_to(ROOT)), 'sha256': digest(source), 'url': url})
    elif not any(re.search(r'licen[cs]e', f.get('jarEntry', ''), re.I) for f in files):
        return [], files, 'JAR 未附 LICENSE；授權留白'
    return record['licenses'], files, f'同版本 JAR SHA-256 核對相符：{jar}'


def text_width(value):
    return sum(2 if unicodedata.east_asian_width(ch) in 'WF' else 1 for ch in str(value or ''))


def mvnrepository_url(component):
    # Same link form as the template's 來源 column; built from the coordinates, not fetched.
    return f"https://mvnrepository.com/artifact/{component['group']}/{component['name']}/{component['version']}"


def eos_rule(component, rules):
    version = component.get('version', '')
    return next((rule for rule in rules if component.get('group') in rule['groups'] and
                 (version == rule['versionLine'] or version.startswith(rule['versionLine'] + '.'))), None)


def style_table(sheet, widths, size=10):
    sheet.freeze_panes = 'A2'
    sheet.auto_filter.ref = sheet.dimensions
    for i, width in enumerate(widths, 1):
        sheet.column_dimensions[get_column_letter(i)].width = width
    for cell in sheet[1]:
        cell.fill = PatternFill('solid', fgColor='1F4E78')
        cell.font = Font(name='微軟正黑體', bold=True, color='FFFFFF', size=11)
        cell.alignment = Alignment(wrap_text=True, vertical='center')
    sheet.row_dimensions[1].height = 32
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.font = Font(name='微軟正黑體', size=size)
            cell.alignment = Alignment(vertical='top', wrap_text=True)
            cell.border = Border(bottom=Side(style='hair', color='D9E1F2'))
            if cell.value is None or cell.value == '':
                cell.fill = PatternFill('solid', fgColor=BLUE)


def format_inventory(sheet):
    style_table(sheet, INVENTORY_WIDTHS, size=14)
    flagged = 0
    for index in range(2, sheet.max_row + 1):
        families = classify([{'license': {'name': sheet.cell(index, 7).value or ''}}])
        if families:
            flagged += 1
            cell = sheet.cell(index, 7)
            cell.fill = PatternFill('solid', fgColor=YELLOW)
            cell.font = Font(name='微軟正黑體', size=14, color=RED, bold=True)
        if sheet.cell(index, 8).value == '是':
            for col in (2, 8):
                sheet.cell(index, col).fill = PatternFill('solid', fgColor=YELLOW)
                sheet.cell(index, col).font = Font(name='微軟正黑體', size=14, color=RED, bold=True)
        # 14pt text fits about 0.75 of the column's nominal character width.
        lines = max(math.ceil(text_width(sheet.cell(index, col).value) / (INVENTORY_WIDTHS[col - 1] * 0.75))
                    for col in (2, 3, 4, 6, 7, 9))
        sheet.row_dimensions[index].height = min(409, max(1, lines) * 21)
    sheet.sheet_properties.pageSetUpPr.fitToPage = True
    sheet.page_setup.orientation = 'landscape'
    sheet.page_setup.paperSize = sheet.PAPERSIZE_A3
    sheet.page_setup.fitToWidth = 1
    sheet.page_setup.fitToHeight = 0
    sheet.print_title_rows = '1:1'
    return flagged


def build_workbook(directory, data, china_origin_groups, records, releases, lifecycle, checked_at):
    components = sorted(flatten(data['components']), key=lambda c: (c.get('group', ''), c['name'], c.get('version', '')))
    title = SYSTEMS.get(directory.name, directory.name)[:31]
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = title
    sheet.append(INVENTORY_HEADERS)
    details = workbook.create_sheet('授權查證')
    details.append(['序', 'Group / Artifact', '版號', '授權來源', 'SBOM 原始授權', '採用授權',
                    'PURL', 'SBOM SHA-256', '查證說明', '證據檔案', '來源及國別說明', 'SBOM 專案網址', '發布日期查證', 'EOS 依據'])
    license_counts = Counter()
    component_evidence = {}
    from_bom = supplemented = unknown = 0
    for index, c in enumerate(components, 1):
        original = c.get('licenses', [])
        licenses, files, notes = original, [], ''
        source = 'SBOM'
        if any(has_license(e) for e in original):
            from_bom += 1
        else:
            licenses, files, notes = supplement(c, records)
            source = '同版本 JAR／原廠文件補查' if licenses else None
            supplemented += bool(licenses)
            unknown += not bool(licenses)
            record = records.get(c.get('purl'), {})
            notes += '\n' + '\n'.join(record.get('evidence', []))
            if licenses:
                notes += '\n既有查證日期：' + record.get('reviewedAt', '')
            component_evidence[c['purl']] = {
                'jarSHA256': next(iter(sha256_of(c)), ''), 'licenses': licenses,
                'files': files, 'notes': notes}
        license_text = labels(licenses)
        license_counts[license_text or '（空白／未查得）'] += 1
        refs = c.get('externalReferences', [])
        urls = [r['url'] for kind in ('website', 'vcs') for r in refs
                if r.get('type') == kind and r.get('url', '').startswith(('https://', 'http://'))]
        homepage = next(iter(urls), None)
        source_url = mvnrepository_url(c)
        group = c.get('group', '')
        # Positive identification only; lack of a match does not establish country.
        china = group in china_origin_groups
        country = '是' if china else '否'
        country_note = (f'groupId 命中 {CHINA_ORIGIN_GROUPS.name}：{group}' if china else
                        'groupId 未命中中國來源名單，依清查填表規則填「否」；未逐一查證發布者國別。')
        if group == 'com.hynnet':
            country_note += (' com.hynnet 為重新發布來源；本機 POM 記載 hynnet, Inc.／dev@hynnet.com，'
                             '原始專案為 JACOB，發布者國別未能核實。')
        eos = eos_rule(c, lifecycle['rules'])
        eos_note = (f"{eos['source']}（查證日 {lifecycle['checkedAt']}；快照 license-list-evidence/eos/{eos['snapshot']}）"
                    if eos else '原廠未公告此元件的生命週期，或未能核對；留白。')
        release = releases.get(c['purl'], {'status': 'not-queried'})
        release_note = {'ok': f"Maven Central JAR Last-Modified {release.get('lastModified')}，SHA-1 與 SBOM 相符",
                        'not-found': 'Maven Central 查無此版本；留白',
                        'sha1-mismatch': f"Maven Central JAR 與 SBOM 的 SHA-1 不同（Central {release.get('centralSha1')}）；留白",
                        }.get(release['status'], f"未取得（{release['status']}）；留白")
        sheet.append([index, c['name'], c.get('version') or None, c.get('description') or None,
                      release.get('date'), source_url or None, license_text or None, country,
                      eos['eos'] if eos else None])
        row = index + 1
        if eos:
            sheet.cell(row, 9).hyperlink = eos['source']
        # Only exceptions get a cell note; the 授權查證 sheet holds the full detail for every row.
        if source != 'SBOM':
            note = Comment('來源：' + (source or '查無結果') + '\n' + notes.strip(), '授權查證')
            note.width, note.height = 480, 260
            sheet.cell(row, 7).comment = note
        if china or group == 'com.hynnet':
            note = Comment(country_note, '來源查證')
            note.width, note.height = 420, 140
            sheet.cell(row, 8).comment = note
        details.append([index, group + ':' + c['name'], c.get('version'), source,
                        labels(original) or None, license_text or None, c.get('purl'),
                        '; '.join(sorted(sha256_of(c))) or None,
                        notes.strip() or '以 SBOM 原始授權記載為準。',
                        '\n'.join(f['path'] for f in files) or None, country_note, homepage, release_note, eos_note])
    flagged = format_inventory(sheet)
    style_table(details, [8, 48, 25, 30, 60, 65, 70, 70, 100, 80, 80, 60, 70, 90])
    counts = {
        'components': len(components),
        'sbomLicenses': from_bom,
        'supplemented': supplemented,
        'unknownLicenses': unknown,
        'copyleftMarked': flagged,
    }
    add_summary(workbook, directory, title, components, counts, checked_at)
    stats = workbook.create_sheet('授權組合統計')
    stats.append(['授權組合（保留來源記載）', '元件數'])
    for label, count in sorted(license_counts.items()):
        stats.append([label, count])
    style_table(stats, [110, 15])
    return workbook, counts, component_evidence


def add_summary(workbook, directory, title, components, counts, checked_at):
    summary = workbook.create_sheet('清查說明')
    summary.append(['項目', '內容'])
    summary.append(['系統', title + ' / ' + directory.name])
    summary.append(['元件數', counts['components']])
    summary.append(['SBOM 已記載授權', counts['sbomLicenses']])
    summary.append(['同版本 JAR／原廠文件補查', counts['supplemented']])
    summary.append(['授權查無結果', counts['unknownLicenses']])
    summary.append(['AGPL／LGPL／GPL 標記元件數（含多重授權及例外）', counts['copyleftMarked']])
    summary.append(['標示規則', '查無結果欄位留白並填淺藍色；AGPL／LGPL／GPL 授權欄、確認中國來源元件名稱及產地欄為黃底紅字。'])
    summary.append(['來源欄', 'mvnrepository 連結由 group／artifact／version 組成，未逐筆開啟；SBOM 記載的專案網址見授權查證。'])
    summary.append(['缺漏欄位', '套件用途採 SBOM description（保留原文）；發布日期採 Maven Central JAR 上架時間（UTC），僅 SHA-1 與 SBOM 相符者填入，早期版本可能晚於實際發布；EOS 僅填原廠公告的日期或維護狀態（連結及查證日見授權查證），其餘留白。'])
    has_fastjson = any('fastjson' in c['name'].lower() for c in components)
    has_hynnet = any(c.get('group') == 'com.hynnet' for c in components)
    country_summary = ('有 fastjson 元件。' if has_fastjson else '未發現 fastjson。')
    country_summary += f'groupId 與 {CHINA_ORIGIN_GROUPS.name} 逐字比對，命中填「是」，其餘填「否」。'
    if has_hynnet:
        country_summary += 'com.hynnet 重新發布來源之國別未能核實，同填「否」，詳見授權查證。'
    summary.append(['國別清查', country_summary])
    summary.append(['授權關係', '保留原始多重授權及例外，不自行推定 AND／OR。OpenPDF Apache-2.0 僅適用部分檔案，詳見查證資料。'])
    summary.append(['核對時間', checked_at])
    summary.append(['JSON/XML 核對', '應用識別、元件、版本、授權、雜湊及依賴關係一致；非 CycloneDX schema 驗證。'])
    summary.append(['中國來源名單', CHINA_ORIGIN_GROUPS.name])
    for filename in ('bom.json', 'bom.xml'):
        path = directory / filename
        summary.append([filename, str(path.relative_to(ROOT)) + '\nSHA-256: ' + digest(path)])
    summary.append(['補充資料', 'license-evidence.json\nSHA-256: ' + digest(ROOT / 'license-evidence.json')])
    style_table(summary, [60, 120])



def validate_workbook(dest, component_count):
    """Read back the inventory and check its row count, highlights, and XML."""
    check = load_workbook(dest).worksheets[0]
    require(check.max_row == component_count + 1, 'Excel 筆數不符')
    for row in check.iter_rows(min_row=2):
        for cell in row:
            if cell.value is None:
                require(cell.fill.fgColor.rgb == '00' + BLUE, f'空白未標淺藍：{cell.coordinate}')
        if classify([{'license': {'name': row[6].value or ''}}]):
            require(row[6].fill.fgColor.rgb == '00' + YELLOW and row[6].font.color.rgb == '00' + RED,
                    '授權警示格式錯誤')
    with zipfile.ZipFile(dest) as archive:
        for name in archive.namelist():
            if name.endswith('.xml'):
                ET.fromstring(archive.read(name))


def main():
    china_origin_groups = load_china_origin_groups(CHINA_ORIGIN_GROUPS)
    records = load_evidence(ROOT / 'license-evidence.json')
    releases = json.loads((ROOT / 'release-dates.json').read_text(encoding='utf-8'))['artifacts']
    lifecycle = json.loads((ROOT / 'eos-lifecycle.json').read_text(encoding='utf-8'))
    for rule in lifecycle['rules']:
        require((EVIDENCE / 'eos' / rule['snapshot']).exists(), f"EOS 原廠快照不存在：{rule['snapshot']}")
    manifest = {'checkedAt': datetime.now().astimezone().isoformat(), 'components': {}, 'reports': []}
    for directory in sorted((ROOT / 'resource-bom').iterdir()):
        if not directory.is_dir() or not (directory / 'bom.json').exists():
            continue
        data = check_pair(directory)
        workbook, counts, component_evidence = build_workbook(
            directory, data, china_origin_groups, records, releases, lifecycle, manifest['checkedAt'],
        )
        dest = OUT / directory.name / f'{directory.name}-元件清查.xlsx'
        dest.parent.mkdir(parents=True, exist_ok=True)
        workbook.save(dest)
        validate_workbook(dest, counts['components'])
        item = {'path': str(dest.relative_to(ROOT)), **counts, 'sha256': digest(dest)}
        manifest['components'].update(component_evidence)
        manifest['reports'].append(item)
        print(json.dumps(item, ensure_ascii=False))
    (EVIDENCE / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()

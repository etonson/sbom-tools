#!/usr/bin/env python3
"""Rebuild per-system Excel inventories, using SBOM first and verified evidence second."""
import argparse
import json
import math
import unicodedata
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from openpyxl import Workbook, load_workbook
from openpyxl.comments import Comment
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from .assessment import evaluate_components
from .bom import check_pair, digest, require, sha256_of
from .evidence import load_china_origin_groups, load_evidence
from .paths import (
    BOM_DIRECTORY,
    CHINA_ORIGIN_GROUPS,
    EOS_LIFECYCLE,
    EVIDENCE_SUBDIRECTORY,
    RELEASE_DATES,
    REPORT_DIRECTORY,
    REPORT_SETTINGS,
    add_report_arguments,
    display_path,
    evidence_config,
    single_project,
)
from .publication import publish


BLUE = 'DDEBF7'
YELLOW = 'FFFF00'
RED = 'FF0000'
INVENTORY_WIDTHS = (7.5, 35.5, 23, 50, 18.66, 46.51, 65, 18, 35)
INVENTORY_HEADERS = ('序', '元件名稱', '版號', '套件用途', '發布日期', '來源', '授權方式', '是否為大陸產品', 'EOS')


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


def text_width(value):
    return sum(2 if unicodedata.east_asian_width(ch) in 'WF' else 1 for ch in str(value or ''))


def mvnrepository_url(component):
    group, name, version = (component.get(key) for key in ('group', 'name', 'version'))
    if group and name and version:
        return f'https://mvnrepository.com/artifact/{group}/{name}/{version}'
    return None


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


def format_inventory(sheet, components):
    style_table(sheet, INVENTORY_WIDTHS, size=14)
    for index, component in enumerate(components, 2):
        if component['license_families']:
            cell = sheet.cell(index, 7)
            cell.fill = PatternFill('solid', fgColor=YELLOW)
            cell.font = Font(name='微軟正黑體', size=14, color=RED, bold=True)
        if component['origin_match']:
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


def build_workbook(project, components, *, settings, lifecycle, missing_eos, inputs, checked_at):
    title = settings['projectNames'].get(project, project)[:31]
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = title
    sheet.append(INVENTORY_HEADERS)
    details = workbook.create_sheet('授權查證')
    details.append(['序', 'Group / Artifact', '版號', '授權來源', 'SBOM 原始授權', '採用授權',
                    'PURL', 'SBOM SHA-256', '查證說明', '證據檔案', '來源及國別說明', 'SBOM 專案網址', '發布日期查證', 'EOS 依據'])
    license_counts = Counter()
    component_evidence = []
    from_bom = supplemented = unknown = 0
    for index, c in enumerate(components, 1):
        original = c['licenses']
        result = c['license_result']
        licenses = result['licenses']
        files = []
        notes = result['note']
        source = None
        if result['status'] == 'bom':
            source = 'SBOM'
            from_bom += 1
        else:
            if result['status'] == 'verified':
                source = '同版本 JAR／原廠文件補查'
                supplemented += 1
                record = result['record']
                notes += '\n' + '\n'.join(record['evidence'])
                notes += '\n既有查證日期：' + record.get('reviewedAt', '')
                files = result['report_files']
            else:
                unknown += 1
            component_evidence.append({
                'purl': c.get('purl'),
                'sbomSHA256': sorted(sha256_of(c)),
                'status': result['status'],
                'licenses': licenses,
                'files': files,
                'notes': notes,
            })
        license_text = labels(licenses)
        license_counts[license_text or '（空白／未查得）'] += 1
        refs = c.get('externalReferences', [])
        urls = [r['url'] for kind in ('website', 'vcs') for r in refs
                if r.get('type') == kind and r.get('url', '').startswith(('https://', 'http://'))]
        homepage = next(iter(urls), None)
        source_url = mvnrepository_url(c)
        group = c.get('group', '')
        china = c['origin_match']
        country = '是' if china else '否'
        country_note = (f'groupId 命中 {CHINA_ORIGIN_GROUPS.name}：{group}' if china else
                        'groupId 未命中中國來源名單，依清查填表規則填「否」；未逐一查證發布者國別。')
        origin_note = settings['originNotes'].get(group)
        if origin_note:
            country_note += ' ' + origin_note
        eos = c['eos']
        if eos and eos['snapshot'] in missing_eos:
            eos_note = f"缺少 EOS 快照：{eos['snapshot']}；留白。"
            eos = None
        elif eos:
            eos_note = f"{eos['source']}（查證日 {lifecycle['checkedAt']}；快照 {eos['snapshot']}）"
        else:
            eos_note = '原廠未公告此元件的生命週期，或未能核對；留白。'
        release = c['release']
        release_note = {'ok': f"Maven Central JAR Last-Modified {release.get('lastModified')}，SHA-1 與 SBOM 相符",
                        'unverified-cache': '既有發布日期缺少已核對的 SHA-1；留白，待更新快取',
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
        if china or origin_note:
            note = Comment(country_note, '來源查證')
            note.width, note.height = 420, 140
            sheet.cell(row, 8).comment = note
        details.append([index, group + ':' + c['name'], c.get('version'), source,
                        labels(original) or None, license_text or None, c.get('purl'),
                        '; '.join(sorted(sha256_of(c))) or None,
                        notes.strip() or '以 SBOM 原始授權記載為準。',
                        '\n'.join(f['path'] for f in files) or None, country_note, homepage, release_note, eos_note])
    format_inventory(sheet, components)
    style_table(details, [8, 48, 25, 30, 60, 65, 70, 70, 100, 80, 80, 60, 70, 90])
    counts = {
        'components': len(components),
        'sbomLicenses': from_bom,
        'supplemented': supplemented,
        'unknownLicenses': unknown,
        'copyleftMarked': sum(bool(c['license_families']) for c in components),
    }
    add_summary(workbook, project, title, counts, checked_at, inputs, missing_eos)
    summary = workbook['清查說明']
    for term in settings['artifactNameChecks']:
        matched = sum(term.casefold() in c['name'].casefold() for c in components)
        summary.append([f'元件名稱檢查 {term}', matched])
    style_table(summary, [60, 120])
    stats = workbook.create_sheet('授權組合統計')
    stats.append(['授權組合（保留來源記載）', '元件數'])
    for label, count in sorted(license_counts.items()):
        stats.append([label, count])
    style_table(stats, [110, 15])
    return workbook, counts, component_evidence


def add_summary(workbook, project, title, counts, checked_at, inputs, missing_eos):
    summary = workbook.create_sheet('清查說明')
    summary.append(['項目', '內容'])
    summary.append(['系統', title + ' / ' + project])
    summary.append(['元件數', counts['components']])
    summary.append(['SBOM 已記載授權', counts['sbomLicenses']])
    summary.append(['同版本 JAR／原廠文件補查', counts['supplemented']])
    summary.append(['授權查無結果', counts['unknownLicenses']])
    summary.append(['AGPL／LGPL／GPL 標記元件數（含多重授權及例外）', counts['copyleftMarked']])
    summary.append(['標示規則', '查無結果欄位留白並填淺藍色；AGPL／LGPL／GPL 授權欄、命中中國來源名單的元件名稱及產地欄為黃底紅字。'])
    summary.append(['來源欄', 'mvnrepository 連結由 group／artifact／version 組成，未逐筆開啟；SBOM 記載的專案網址見授權查證。'])
    summary.append(['缺漏欄位', '套件用途採 SBOM description（保留原文）；發布日期採 Maven Central JAR 上架時間（UTC），僅 SHA-1 與 SBOM 相符者填入，早期版本可能晚於實際發布；EOS 僅填原廠公告的日期或維護狀態（連結及查證日見授權查證），其餘留白。'])
    summary.append(['國別清查', f'groupId 與 {CHINA_ORIGIN_GROUPS.name} 逐字比對，命中填「是」，其餘填「否」。'])
    summary.append(['授權關係', '保留原始多重授權及例外。適用範圍詳見查證資料。'])
    summary.append(['核對時間', checked_at])
    summary.append(['JSON/XML 核對', '應用識別、元件、版本、授權、雜湊及依賴關係一致；非 CycloneDX schema 驗證。'])
    if missing_eos:
        summary.append(['缺少 EOS 快照', '\n'.join(missing_eos.values())])
    for path, checksum in inputs.items():
        summary.append([path.name, display_path(path) + '\nSHA-256: ' + checksum])


def validate_workbook(dest, components):
    """Read back the inventory and check its row count, highlights, and XML."""
    check = load_workbook(dest).worksheets[0]
    require(check.max_row == len(components) + 1, 'Excel 筆數不符')
    for row, component in zip(check.iter_rows(min_row=2), components):
        for cell in row:
            if cell.value is None:
                require(cell.fill.fgColor.rgb == '00' + BLUE, f'空白未標淺藍：{cell.coordinate}')
        if component['license_families']:
            require(row[6].fill.fgColor.rgb == '00' + YELLOW and row[6].font.color.rgb == '00' + RED,
                    '授權警示格式錯誤')
        if component['origin_match']:
            require(all(row[index].fill.fgColor.rgb == '00' + YELLOW and
                        row[index].font.color.rgb == '00' + RED for index in (1, 7)),
                    '產地警示格式錯誤')
    with zipfile.ZipFile(dest) as archive:
        for name in archive.namelist():
            if name.endswith('.xml'):
                ET.fromstring(archive.read(name))


def stage_evidence(files, staging, output, evidence_dir, input_hashes):
    published = []
    for entry in files:
        if 'artifactPath' in entry:
            relative = EVIDENCE_SUBDIRECTORY / 'artifacts' / entry['artifactPath']
            staged = staging / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(entry['content'])
            path = output / relative
            metadata = {'jarEntry': entry['jarEntry']}
        else:
            path = evidence_dir / entry['snapshot']
            expected = input_hashes.setdefault(path, entry['sha256'])
            require(expected == entry['sha256'], f'產檔期間快照有變動：{display_path(path)}')
            metadata = {'url': entry['url']}
        published.append({'path': display_path(path), 'sha256': entry['sha256'], **metadata})
    return published


def generate_reports(projects, output, evidence_dir, evidence_path, *, release_path, allow_missing_eos):
    settings = json.loads(REPORT_SETTINGS.read_text(encoding='utf-8'))
    input_paths = (CHINA_ORIGIN_GROUPS, evidence_path, release_path, EOS_LIFECYCLE, REPORT_SETTINGS)
    input_hashes = {path: digest(path) for path in input_paths}
    china_origin_groups = load_china_origin_groups()
    records = load_evidence(evidence_path)
    releases = json.loads(release_path.read_text(encoding='utf-8'))['artifacts']
    lifecycle = json.loads(EOS_LIFECYCLE.read_text(encoding='utf-8'))

    snapshots = {rule['snapshot']: evidence_dir / 'eos' / rule['snapshot']
                 for rule in lifecycle['rules']}
    missing_eos = {name: display_path(path) for name, path in sorted(snapshots.items())
                   if not path.is_file()}
    if missing_eos and not allow_missing_eos:
        listing = '\n'.join(missing_eos.values())
        raise ValueError(f'EOS 原廠快照不存在：\n{listing}\n可用 --evidence-dir 指定快照位置。')
    for name, snapshot in snapshots.items():
        if name not in missing_eos:
            input_hashes[snapshot] = digest(snapshot)

    manifest = {
        'checkedAt': datetime.now().astimezone().isoformat(),
        'missingEosSnapshots': list(missing_eos.values()),
        'componentsByProject': {},
        'reports': [],
    }
    manifest_relative = EVIDENCE_SUBDIRECTORY / 'manifest.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=output.parent, prefix='.sbom-excel-') as temporary:
        staging = Path(temporary)
        reports = []
        for project, directory in projects:
            bom_inputs = {directory / name: digest(directory / name) for name in ('bom.json', 'bom.xml')}
            input_hashes.update(bom_inputs)
            components = evaluate_components(
                check_pair(directory), records, china_origin_groups, releases, lifecycle,
                evidence_dir=evidence_dir,
            )
            for component in components:
                result = component['license_result']
                if result['status'] == 'verified':
                    result['report_files'] = stage_evidence(
                        result['files'], staging, output, evidence_dir, input_hashes,
                    )
            workbook_inputs = {**bom_inputs, CHINA_ORIGIN_GROUPS: input_hashes[CHINA_ORIGIN_GROUPS],
                               evidence_path: input_hashes[evidence_path]}
            workbook, counts, evidence = build_workbook(
                project, components, settings=settings, lifecycle=lifecycle, missing_eos=missing_eos,
                inputs=workbook_inputs, checked_at=manifest['checkedAt'],
            )
            relative = Path(project) / f'{project}-元件清查.xlsx'
            staged = staging / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            workbook.save(staged)
            validate_workbook(staged, components)
            manifest['componentsByProject'][project] = evidence
            manifest['reports'].append({
                'path': display_path(output / relative), **counts, 'sha256': digest(staged),
            })
            reports.append(relative)

        for path, expected in input_hashes.items():
            require(digest(path) == expected, f'產檔期間輸入有變動：{display_path(path)}')
        manifest['inputs'] = {display_path(path): expected for path, expected in input_hashes.items()}
        evidence_files = sorted(path.relative_to(staging) for path in
                                (staging / EVIDENCE_SUBDIRECTORY).rglob('*') if path.is_file())
        staged_manifest = staging / manifest_relative
        staged_manifest.parent.mkdir(parents=True, exist_ok=True)
        staged_manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        publish(staging, output, [*evidence_files, *reports, manifest_relative])
    return manifest['reports']


def main(argv=None):
    parser = argparse.ArgumentParser(description='核對 CycloneDX JSON/XML 並產生 Excel 元件清查')
    add_report_arguments(parser, input_directory=BOM_DIRECTORY, output_directory=REPORT_DIRECTORY)
    parser.add_argument('--release-dates', type=Path, default=RELEASE_DATES, help='發布日期快取檔案')
    parser.add_argument('--allow-missing-eos', action='store_true', help='缺少 EOS 快照時，受影響欄位留白')
    args = parser.parse_args(argv)
    selected = single_project(parser, args)
    projects = [selected] if selected else [
        (path.parent.name, path.parent) for path in sorted(args.input.glob('*/bom.json'))
    ]
    if not projects:
        parser.error(f'{args.input} 找不到 bom.json')
    try:
        reports = generate_reports(projects, args.output, args.evidence_dir, evidence_config(args.evidence),
                                   release_path=args.release_dates, allow_missing_eos=args.allow_missing_eos)
    except (OSError, ValueError, KeyError, ET.ParseError) as error:
        parser.exit(1, f'Excel 產檔失敗：{error}\n')
    for item in reports:
        print(json.dumps(item, ensure_ascii=False))

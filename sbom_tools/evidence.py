"""Load and verify supplemental evidence shared by Excel and HTML."""

import hashlib
import json
import re
import zipfile
from pathlib import Path
from urllib.parse import parse_qs

from .bom import has_license, sha256_of
from .paths import CHINA_ORIGIN_GROUPS, EVIDENCE_DIRECTORY


LICENSE_FILENAME = re.compile(r'license|licence|copying|notice|^MANIFEST\.MF$', re.I)
LICENSE_FILE = re.compile(r'licen[cs]e', re.I)


def load_evidence(path):
    """Manually verified licenses, keyed by purl and bound to the artifact's SHA-256."""
    if path is None or not path.exists():
        return {}
    records = json.loads(path.read_text(encoding="utf-8-sig")).get("components", [])
    evidence = {}
    for record in records:
        if not (record.get("purl") and record.get("sha256") and record.get("evidence")
                and any(has_license(entry) for entry in record.get("licenses", []))):
            raise ValueError(f"補充授權缺少 purl、sha256、licenses 或 evidence：{record.get('purl', '')}")
        evidence[record["purl"]] = record
    return evidence


def load_china_origin_groups(path=CHINA_ORIGIN_GROUPS):
    groups = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(groups, list) or not all(
        isinstance(group, str) and group and group == group.strip() for group in groups
    ):
        raise ValueError(f'{path.name} 須為 Maven groupId 字串陣列，項目不可空白或含有前後空格')
    return set(groups)


def maven_artifact(component):
    """Build the repository-relative path for the exact Maven variant."""
    purl = component.get('purl', '')
    if not purl.startswith('pkg:maven/'):
        return None
    qualifiers = parse_qs(purl.partition('?')[2].partition('#')[0])
    classifier = qualifiers.get('classifier', [''])[0]
    extension = qualifiers.get('type', ['jar'])[0]
    group, name, version = (component.get(key, '') for key in ('group', 'name', 'version'))
    parts = (*group.split('.'), name, version, extension)
    if any(not part or part in {'.', '..'} or '/' in part or '\\' in part for part in parts):
        return None
    if classifier and (classifier in {'.', '..'} or '/' in classifier or '\\' in classifier):
        return None
    suffix = f'-{classifier}' if classifier else ''
    return Path(*group.split('.'), name, version, f'{name}-{version}{suffix}.{extension}')


def resolve_license(component, records, evidence_dir=EVIDENCE_DIRECTORY, maven_repository=None):
    """Resolve the original licenses or verify a reviewed record against the actual artifact."""
    original = component.get('licenses') or []
    if any(has_license(entry) for entry in original):
        return {'status': 'bom', 'licenses': original, 'note': '', 'files': []}

    result = {'status': 'missing', 'licenses': [], 'note': '補充資料無相符 PURL；授權留白', 'files': []}
    record = records.get(component.get('purl'))
    if record is None:
        return result

    def finish(status, note, files=()):
        result.update(status=status, note=note, files=list(files))
        if status == 'verified':
            result.update(licenses=record['licenses'], record=record)
        return result

    expected = record['sha256'].lower()
    if not re.fullmatch(r'[0-9a-f]{64}', expected) or expected not in sha256_of(component):
        return finish('sha256-mismatch', '補充資料與 SBOM SHA-256 不符；授權留白')
    artifact = maven_artifact(component)
    if artifact is None:
        return finish('unsupported-artifact', '無法辨識本機 Maven 套件路徑；授權留白')
    jar = (maven_repository or Path.home() / '.m2/repository') / artifact
    if not jar.is_file():
        return finish('missing-artifact', f'本機無同版本套件：{jar}；授權留白')

    # Hash and inspect the same open file, even if the cache entry is replaced.
    with jar.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
            return finish('sha256-mismatch', f'本機套件 SHA-256 不符：{jar}；授權留白')
        stream.seek(0)
        files = []
        try:
            with zipfile.ZipFile(stream) as archive:
                for entry in archive.infolist():
                    relative = Path(entry.filename)
                    if (entry.is_dir() or relative.is_absolute() or '..' in relative.parts
                            or '\\' in entry.filename
                            or not LICENSE_FILENAME.search(relative.name)):
                        continue
                    payload = archive.read(entry)
                    files.append({
                        'artifactPath': str(artifact / expected / relative),
                        'sha256': hashlib.sha256(payload).hexdigest(),
                        'jarEntry': entry.filename,
                        'content': payload,
                    })
        except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
            return finish('invalid-artifact', '無法讀取套件內的授權文件；授權留白')

    official = record.get('officialSnapshot')
    if official:
        relative = Path(official['path'])
        snapshot = evidence_dir / relative
        if (relative.is_absolute() or '..' in relative.parts
                or not snapshot.resolve().is_relative_to(evidence_dir.resolve()) or not snapshot.is_file()):
            return finish('missing-snapshot', '原廠授權快照不存在；授權留白')
        files.append({
            'snapshot': str(relative),
            'sha256': hashlib.sha256(snapshot.read_bytes()).hexdigest(),
            'url': official['url'],
        })
    elif not any(LICENSE_FILE.search(Path(file['jarEntry']).name) for file in files):
        return finish('missing-license-file', '套件未附 LICENSE；授權留白')
    return finish('verified', f'同版本 JAR SHA-256 核對相符：{jar}', files)


def sha1_of(component):
    return {entry['content'].lower() for entry in component.get('hashes', []) or []
            if entry.get('alg', '').upper() == 'SHA-1' and entry.get('content')}


def release_for(component, releases):
    """Return a release date only when its cached verification matches this BOM."""
    entry = releases.get(component.get('purl'))
    if entry is None:
        return {'status': 'not-queried'}
    if entry['status'] != 'ok':
        return {**entry, 'date': None}
    verified = entry.get('sbomSha1', '')
    if not verified:
        return {'status': 'unverified-cache'}
    if verified.lower() not in sha1_of(component):
        return {**entry, 'status': 'sha1-mismatch', 'date': None}
    return entry


def eos_for(component, lifecycle):
    version = component.get('version') or ''
    return next((rule for rule in lifecycle.get('rules', [])
                 if component.get('group') in rule['groups']
                 and (version == rule['versionLine'] or version.startswith(rule['versionLine'] + '.'))), None)

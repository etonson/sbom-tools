#!/usr/bin/env python3
"""Record each SBOM artifact's Maven Central publish time in release-dates.json.

A date is kept only when Central's artifact matches the SBOM's SHA-1, so it describes the same JAR.
"""
import hashlib
import json
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote

from .bom import flatten, load_bom, require
from .evidence import ROOT, maven_artifact, sha1_of

CENTRAL = 'https://repo1.maven.org/maven2'
HEADERS = {'User-Agent': 'sbom-license-inventory'}


def fetch(url, method='GET'):
    request = urllib.request.Request(url, method=method, headers=HEADERS)
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read(), response.headers


def lookup(component):
    purl = component['purl']
    artifact = maven_artifact(component)
    if artifact is None:
        return purl, {'status': 'unsupported-artifact', 'date': None}
    url = f"{CENTRAL}/{quote(artifact.as_posix())}"
    expected = sha1_of(component)
    result = {'url': url, 'date': None}
    if not expected:
        return purl, {**result, 'status': 'missing-sha1'}
    try:
        try:
            tokens = fetch(url + '.sha1')[0].decode('utf-8', 'replace').lower().split()
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            tokens = []
        sha1 = tokens[0] if tokens else ''
        if sha1 not in expected:
            # Some older checksums are missing or incorrect. Verify the artifact itself.
            sha1 = hashlib.sha1(fetch(url)[0]).hexdigest()
        if sha1 not in expected:
            result.update(status='sha1-mismatch', centralSha1=sha1, sbomSha1=sorted(expected)[0])
            return purl, result
        modified = fetch(url, 'HEAD')[1].get('Last-Modified')
    except urllib.error.HTTPError as error:
        result['status'] = 'not-found' if error.code == 404 else f'http-{error.code}'
        return purl, result
    try:
        moment = parsedate_to_datetime(modified)
    except (TypeError, ValueError):
        return purl, {**result, 'status': 'missing-last-modified'}
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)
    result.update(status='ok', date=moment.strftime('%Y-%m-%d'), lastModified=moment.isoformat(),
                  sbomSha1=sha1)
    return purl, result


def main():
    components = {}
    for path in sorted((ROOT / 'resource-bom').glob('*/bom.json')):
        for component in flatten(load_bom(path).get('components') or []):
            if component.get('purl'):
                components[(component['purl'], frozenset(sha1_of(component)))] = component
    require(components, 'resource-bom 沒有可查詢的元件')
    artifacts = {}
    with ThreadPoolExecutor(6) as pool:
        for purl, result in pool.map(lookup, components.values()):
            if purl not in artifacts or result['status'] == 'ok':
                artifacts[purl] = result
    output = {'source': CENTRAL, 'field': 'JAR Last-Modified (UTC)',
              'checkedAt': datetime.now(timezone.utc).isoformat(), 'artifacts': dict(sorted(artifacts.items()))}
    with TemporaryDirectory(dir=ROOT, prefix='.sbom-release-') as temporary:
        staged = Path(temporary) / 'release-dates.json'
        staged.write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        staged.replace(ROOT / staged.name)
    print(dict(Counter(item['status'] for item in artifacts.values())))

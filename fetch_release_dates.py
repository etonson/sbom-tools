#!/usr/bin/env python3
"""Record each SBOM artifact's Maven Central publish time in release-dates.json.

A date is kept only when Central's artifact matches the SBOM's SHA-1, so it describes the same JAR.
"""
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CENTRAL = 'https://repo1.maven.org/maven2'
HEADERS = {'User-Agent': 'sbom-license-inventory'}


def fetch(url, method='GET'):
    request = urllib.request.Request(url, method=method, headers=HEADERS)
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read(), response.headers


def lookup(component):
    purl = component['purl']
    qualifiers = urllib.parse.parse_qs(purl.partition('?')[2])
    classifier = qualifiers.get('classifier', [''])[0]
    extension = qualifiers.get('type', ['jar'])[0]
    g, a, v = component['group'], component['name'], component['version']
    suffix = f'-{classifier}' if classifier else ''
    url = f"{CENTRAL}/{g.replace('.', '/')}/{a}/{v}/{a}-{v}{suffix}.{extension}"
    expected = next((h['content'].lower() for h in component.get('hashes', [])
                     if h.get('alg', '').upper() == 'SHA-1'), None)
    result = {'url': url, 'date': None}
    try:
        sha1 = fetch(url + '.sha1')[0].decode('utf-8', 'replace').split()[0].lower()
        if sha1 != expected:
            # Some old .sha1 files on Central are wrong, so the JAR itself decides.
            sha1 = hashlib.sha1(fetch(url)[0]).hexdigest()
        modified = fetch(url, 'HEAD')[1]['Last-Modified']
    except urllib.error.HTTPError as error:
        result['status'] = 'not-found' if error.code == 404 else f'http-{error.code}'
        return purl, result
    if expected != sha1:
        result.update(status='sha1-mismatch', centralSha1=sha1, sbomSha1=expected)
        return purl, result
    moment = parsedate_to_datetime(modified).astimezone(timezone.utc)
    result.update(status='ok', date=moment.strftime('%Y-%m-%d'), lastModified=moment.isoformat())
    return purl, result


def main():
    components = {}
    for path in sorted((ROOT / 'resource-bom').glob('*/bom.json')):
        for component in json.loads(path.read_text(encoding='utf-8'))['components']:
            components[component['purl']] = component
    with ThreadPoolExecutor(6) as pool:
        artifacts = dict(sorted(pool.map(lookup, components.values())))
    output = {'source': CENTRAL, 'field': 'JAR Last-Modified (UTC)',
              'checkedAt': datetime.now(timezone.utc).isoformat(), 'artifacts': artifacts}
    (ROOT / 'release-dates.json').write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    counts = {}
    for item in artifacts.values():
        counts[item['status']] = counts.get(item['status'], 0) + 1
    print(counts)


if __name__ == '__main__':
    main()

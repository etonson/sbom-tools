import hashlib
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from zipfile import ZipFile

from sbom_tools.assessment import evaluate_components
from sbom_tools.bom import check_pair
from sbom_tools.evidence import maven_artifact, release_for, resolve_license
from sbom_tools.html_report import analyze
from sbom_tools.publication import publish
from sbom_tools.release_dates import lookup, main as refresh_release_dates


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.component = {
            'group': 'example.org', 'name': 'demo', 'version': '1',
            'purl': 'pkg:maven/example.org/demo@1?classifier=custom&type=jar',
        }

    def test_nested_components_and_exact_origin_match(self):
        child = {**self.component, 'group': 'example.org.sub', 'name': 'child'}
        data = {'components': [{**self.component, 'components': [child]}, self.component]}
        assessed = evaluate_components(data, {}, {'example.org'})
        self.assertEqual([(item['name'], item['origin_match']) for item in assessed],
                         [('demo', True), ('child', False)])

    def test_license_requires_the_exact_local_artifact(self):
        with TemporaryDirectory() as temporary:
            repository = Path(temporary)
            relative = maven_artifact(self.component)
            self.assertEqual(relative, Path('example/org/demo/1/demo-1-custom.jar'))
            jar = repository / relative
            jar.parent.mkdir(parents=True)
            with ZipFile(jar, 'w') as archive:
                archive.writestr('META-INF/LICENSE.txt', 'Verified fixture')
            sha256 = hashlib.sha256(jar.read_bytes()).hexdigest()
            self.component['hashes'] = [{'alg': 'SHA-256', 'content': sha256}]
            records = {self.component['purl']: {
                'sha256': sha256, 'evidence': ['Fixture'],
                'licenses': [{'expression': 'GPL-2.0-only'}],
            }}
            with patch('sbom_tools.assessment.resolve_license', wraps=lambda c, r:
                       resolve_license(c, r, maven_repository=repository)):
                assessed = evaluate_components({'components': [self.component]}, records)[0]
                html_result = analyze({'components': [self.component]}, records)
                self.assertEqual(assessed['license_result']['status'], 'verified')
                self.assertEqual(html_result['supplemented'][0]['license_families'], {'GPL'})
                jar.write_bytes(b'different artifact')
                self.assertEqual(analyze({'components': [self.component]}, records)['matched'], 0)
            result = resolve_license(self.component, records, maven_repository=repository)
            self.assertEqual(result['status'], 'sha256-mismatch')

    def test_release_cache_is_bound_to_the_bom_hash(self):
        checksum = 'a' * 40
        self.component['hashes'] = [{'alg': 'SHA-1', 'content': checksum.upper()}]
        date = '2025-02-10'
        with patch('sbom_tools.release_dates.fetch', side_effect=[
            (checksum.encode(), {}), (b'', {'Last-Modified': 'Mon, 10 Feb 2025 12:00:00 GMT'}),
        ]):
            purl, result = lookup(self.component)
        self.assertEqual(result['sbomSha1'], checksum)
        self.assertEqual(release_for(self.component, {purl: result})['date'], date)
        legacy = {key: value for key, value in result.items() if key != 'sbomSha1'}
        self.assertEqual(release_for(self.component, {purl: legacy})['status'], 'unverified-cache')
        different = {**result, 'sbomSha1': 'b' * 40}
        rejected = release_for(self.component, {purl: different})
        self.assertEqual(rejected['status'], 'sha1-mismatch')
        self.assertIsNone(rejected['date'])

    def test_refresh_keeps_verified_date_for_purl_with_two_hashes(self):
        checksum = 'a' * 40
        cached = {**self.component, 'hashes': [{'alg': 'SHA-1', 'content': checksum}]}
        different = {**self.component, 'hashes': [{'alg': 'SHA-1', 'content': 'b' * 40}]}
        data = {'bomFormat': 'CycloneDX', 'components': [
            {'name': 'container', 'components': [cached]}, different,
        ]}
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            bom = root / 'resource-bom/project/bom.json'
            bom.parent.mkdir(parents=True)
            bom.write_text(json.dumps(data))
            with (patch('sbom_tools.release_dates.ROOT', root),
                  patch('sbom_tools.release_dates.fetch', side_effect=lambda url, method='GET': (
                      checksum.encode() if url.endswith('.sha1') else b'different artifact',
                      {'Last-Modified': 'Mon, 10 Feb 2025 12:00:00 GMT'},
                  )),
                  patch('builtins.print')):
                refresh_release_dates()
            entry = json.loads((root / 'release-dates.json').read_text())['artifacts'][self.component['purl']]
            self.assertEqual(entry['sbomSha1'], checksum)
            self.assertEqual(entry['date'], '2025-02-10')


class InputAndPublicationTests(unittest.TestCase):
    def test_bom_pair_rejects_different_dependency_graphs(self):
        component = {'name': 'system', 'version': '1'}
        data = {'bomFormat': 'CycloneDX', 'metadata': {'component': component}, 'components': [],
                'dependencies': [{'ref': 'system', 'dependsOn': ['other']}]}
        xml = ('<bom xmlns="http://cyclonedx.org/schema/bom/1.6">'
               '<metadata><component><name>system</name><version>1</version></component></metadata>'
               '<dependencies><dependency ref="system"><dependency ref="other"/></dependency>'
               '</dependencies></bom>')
        with TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / 'bom.json').write_text(json.dumps(data))
            (path / 'bom.xml').write_text(xml)
            self.assertEqual(check_pair(path), data)
            (path / 'bom.xml').write_text(xml.replace('ref="other"', 'ref="different"'))
            with self.assertRaisesRegex(ValueError, '依賴關係不同'):
                check_pair(path)

    def test_publish_rolls_back_if_manifest_replacement_fails(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged, destination = root / 'stage', root / 'reports'
            staged.mkdir()
            destination.mkdir()
            existing = Path('existing.xlsx')
            new = Path('new.xlsx')
            manifest = Path('manifest.json')
            (destination / existing).write_text('old report')
            (destination / manifest).write_text('old manifest')
            for relative in (existing, new, manifest):
                (staged / relative).write_text('new')

            replace = os.replace

            def fail_manifest(source, target):
                if source == staged / manifest:
                    raise OSError('cannot replace manifest')
                replace(source, target)

            with patch('sbom_tools.publication.os.replace', side_effect=fail_manifest):
                with self.assertRaisesRegex(OSError, 'cannot replace manifest'):
                    publish(staged, destination, [existing, new, manifest])

            self.assertEqual((destination / existing).read_text(), 'old report')
            self.assertFalse((destination / new).exists())
            self.assertEqual((destination / manifest).read_text(), 'old manifest')

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

try:
    from openpyxl import load_workbook
except ImportError:
    load_workbook = None


ROOT = Path(__file__).resolve().parents[1]


class ReportCommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = self.root / 'incoming files'
        self.inputs.mkdir()
        self.evidence = self.root / 'snapshot bundle'
        self.output = self.root / 'output'
        self.bom = self.inputs / 'bom.json'
        self.xml = self.inputs / 'bom.xml'
        component = {
            'group': 'org.springframework', 'name': 'example', 'version': '7.0.1',
            'licenses': [{'license': {'id': 'LGPL-2.1-only'}}],
        }
        republished = {
            'group': 'com.hynnet', 'name': 'jacob-jdk15', 'version': '1',
            'licenses': [{'license': {'id': 'Apache-2.0'}}],
        }
        self.bom.write_text(json.dumps({
            'bomFormat': 'CycloneDX', 'metadata': {'component': {'name': 'demo'}},
            'components': [component, republished],
        }))
        self.xml.write_text(
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.6">'
            '<metadata><component><name>demo</name></component></metadata>'
            '<components><component><group>org.springframework</group><name>example</name>'
            '<version>7.0.1</version><licenses><license><id>LGPL-2.1-only</id></license>'
            '</licenses></component>'
            '<component><group>com.hynnet</group><name>jacob-jdk15</name>'
            '<version>1</version><licenses><license><id>Apache-2.0</id></license>'
            '</licenses></component></components></bom>'
        )

    def run_report(self, script, *options, check=True):
        return subprocess.run(
            [sys.executable, '-B', str(ROOT / script), '--bom-dir', str(self.inputs),
             '--project', 'fixture-report', '--evidence-dir', str(self.evidence),
             '--output', str(self.output), *options],
            cwd=self.root, check=check, text=True, capture_output=True,
        )

    def test_html_accepts_a_direct_xml_input(self):
        self.bom.unlink()
        self.run_report('analyze_bom.py')
        report = self.output / 'fixture-report/license-report.html'
        self.assertIn('LGPL-2.1-only', report.read_text(encoding='utf-8'))
        self.assertIn('fixture-report/license-report.html', (self.output / 'index.html').read_text(encoding='utf-8'))

    @unittest.skipIf(load_workbook is None, 'Excel CLI 測試需要 openpyxl')
    def test_excel_and_html_use_the_supplied_pair_and_output(self):
        strict = self.run_report('generate_license_excel.py', check=False)
        self.assertNotEqual(strict.returncode, 0)
        self.assertIn('spring-framework.json', strict.stderr)
        self.assertIn('spring-boot.json', strict.stderr)
        self.assertFalse(self.output.exists())

        self.run_report('generate_license_excel.py', '--allow-missing-eos')
        html = self.run_report('analyze_bom.py')
        self.assertIn('授權條件確認=1', html.stdout)
        workbook_path = self.output / 'fixture-report/fixture-report-元件清查.xlsx'
        workbook = load_workbook(workbook_path)
        try:
            self.assertEqual(workbook.worksheets[0].max_row, 3)
            self.assertEqual(workbook.worksheets[0]['G3'].value, 'LGPL-2.1-only')
            self.assertIsNone(workbook.worksheets[0]['I3'].value)
            self.assertIn('缺少 EOS 快照', workbook['授權查證']['N3'].value)
            self.assertIn('JACOB', workbook['授權查證']['K2'].value)
        finally:
            workbook.close()
        manifest_path = self.output / 'license-list-evidence/manifest.json'
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        for source in (self.bom, self.xml):
            self.assertEqual(manifest['inputs'][str(source)], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(manifest['reports'][0]['sha256'], hashlib.sha256(workbook_path.read_bytes()).hexdigest())
        self.assertIn(str(self.evidence / 'eos/spring-framework.json'), manifest['missingEosSnapshots'])

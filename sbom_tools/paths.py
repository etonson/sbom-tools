"""Repository paths and shared report command arguments."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIRECTORY = ROOT / 'config'
BOM_DIRECTORY = ROOT / 'resource-bom'
REPORT_DIRECTORY = ROOT / 'reports'
EVIDENCE_SUBDIRECTORY = Path('license-list-evidence')
EVIDENCE_DIRECTORY = REPORT_DIRECTORY / EVIDENCE_SUBDIRECTORY
LICENSE_EVIDENCE = CONFIG_DIRECTORY / 'license-evidence.json'
CHINA_ORIGIN_GROUPS = CONFIG_DIRECTORY / 'china-origin-groups.json'
RELEASE_DATES = CONFIG_DIRECTORY / 'release-dates.json'
EOS_LIFECYCLE = CONFIG_DIRECTORY / 'eos-lifecycle.json'
REPORT_SETTINGS = CONFIG_DIRECTORY / 'report-settings.json'


def display_path(path):
    absolute = path.resolve()
    return str(absolute.relative_to(ROOT)) if absolute.is_relative_to(ROOT) else str(absolute)


def add_report_arguments(parser, *, input_directory, output_directory):
    sources = parser.add_mutually_exclusive_group()
    sources.add_argument('--input', type=Path, default=input_directory, help='批次搜尋 SBOM 的根目錄')
    sources.add_argument('--bom-dir', type=Path, help='直接指定含 SBOM 檔案的單一目錄')
    parser.add_argument('--project', help='搭配 --bom-dir 指定系統名稱及輸出子目錄')
    parser.add_argument('--output', type=Path, default=output_directory, help='報表輸出目錄')
    parser.add_argument('--evidence-dir', type=Path, default=EVIDENCE_DIRECTORY,
                        help='原廠授權與 EOS 快照目錄')
    parser.add_argument('--evidence', type=Path, default=LICENSE_EVIDENCE,
                        help='人工查證的授權補充資料')


def single_project(parser, arguments):
    if arguments.bom_dir is None:
        if arguments.project is not None:
            parser.error('--project 須搭配 --bom-dir')
        return None
    directory = arguments.bom_dir.absolute().resolve()
    project = arguments.project if arguments.project is not None else directory.name
    if (not project.strip() or project in {'.', '..'}
            or any(character in project for character in '/\\[]:*?')):
        parser.error('--project 必須是單一目錄名稱')
    return project, directory


def evidence_config(path):
    # Previous HTML examples explicitly passed the file before it moved to config/.
    if path == Path('license-evidence.json') and not path.exists():
        return LICENSE_EVIDENCE
    return path

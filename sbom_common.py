"""Read and compare CycloneDX inventories and classify their license entries."""

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter


FAMILIES = ("GPL", "AGPL", "LGPL")
PATTERNS = {
    "GPL": r"(?<![\w])GPL(?![A-Za-z])|\bGNU\s+General\s+Public\s+Licen[cs]e\b",
    "AGPL": r"(?<![\w])AGPL(?![A-Za-z])|\b(?:GNU\s+)?Affero\s+General\s+Public\s+Licen[cs]e\b",
    "LGPL": r"(?<![\w])LGPL(?![A-Za-z])|\bGNU\s+(?:Lesser|Library)(?:\s+or\s+Lesser)?\s+General\s+Public\s+Licen[cs]e\b|gnu\.org/(?:licenses/(?:old-licenses/)?(?:lgpl|lesser)|copyleft/lesser)",
}


def classify(licenses):
    """Match each license field independently, preserving overlapping families."""
    fields = [str(value) for entry in licenses for value in
              [entry.get("expression", ""), *entry.get("license", {}).values()]
              if isinstance(value, str)]
    return {family for family, pattern in PATTERNS.items()
            if any(re.search(pattern, value, re.I) for value in fields)}


def has_license(entry):
    return bool(entry.get("expression", "").strip() or any(
        entry.get("license", {}).get(k, "").strip() for k in ("id", "name", "url")))


def gpl_without_multiple_licenses(licenses):
    """Conservative BOM-field filter, not a determination of available legal licenses."""
    entries = [entry for entry in licenses if has_license(entry)]
    if len(entries) != 1 or "GPL" not in classify(entries):
        return False
    entry = entries[0]
    # WITH attaches an exception; AND/OR combines licenses. Do not split on WITH.
    if re.search(r"(?<![\w.+-])(?:AND|OR)(?![\w.+-])", entry.get("expression", ""), re.I):
        return False
    for key in ("id", "name"):
        label = entry.get("license", {}).get(key, "")
        # A choice of later GPL versions is not a separately named license.
        label = re.sub(r"\bor (?:any )?later(?: version)?\b", "", label, flags=re.I)
        if re.search(r"(?<![\w.+-])(?:AND|OR)(?![\w.+-])|\b(?:dual|multi[- ]?licens\w*)\b|[/;]|、", label, re.I):
            return False
    return True


def has_exception(licenses):
    fields = [entry.get("expression", "") for entry in licenses]
    fields += [entry.get("license", {}).get(key, "")
               for entry in licenses for key in ("id", "name", "url")]
    return any(re.search(r"exception|例外|\bWITH\b", field, re.I) for field in fields)


def _xml_component(element):
    component = {key: element.findtext(key, "") for key in
                 ("group", "name", "version", "purl")}
    component["hashes"] = [{"alg": h.get("alg", ""), "content": h.text or ""}
                           for h in element.findall("hashes/hash")]
    component["licenses"] = []
    for entry in element.findall("licenses/*"):
        if entry.tag == "expression":
            component["licenses"].append({"expression": entry.text or ""})
        elif entry.tag == "license":
            component["licenses"].append({"license": {
                key: entry.findtext(key, "") for key in ("id", "name", "url")
                if entry.findtext(key)}})
    component["components"] = [_xml_component(c) for c in element.findall("components/component")]
    return component


def load_bom(path):
    if path.suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if data.get("bomFormat") != "CycloneDX":
            raise ValueError("不是 CycloneDX JSON")
        return data
    return _xml_bom(_parse_xml_root(path))


def _parse_xml_root(path):
    root = ET.parse(path).getroot()
    if root.tag != "bom" and not root.tag.startswith("{http://cyclonedx.org/schema/bom/"):
        raise ValueError("不是 CycloneDX XML")
    for element in root.iter():
        element.tag = element.tag.split("}")[-1]
    return root


def _xml_bom(root):
    application = root.find("metadata/component")
    return {
        "specVersion": "XML",
        "serialNumber": root.get("serialNumber", ""),
        "metadata": {"timestamp": root.findtext("metadata/timestamp", ""),
                     "component": _xml_component(application) if application is not None else {}},
        "components": [_xml_component(c) for c in root.findall("components/component")],
    }


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


def sha256_of(component):
    return {h.get("content", "").lower() for h in component.get("hashes", []) or []
            if h.get("alg", "").upper() == "SHA-256"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def flatten(components):
    for component in components:
        yield component
        yield from flatten(component.get('components', []) or [])


def _component_signature(component):
    return (tuple(component.get(k, '') for k in ('group', 'name', 'version', 'purl')),
            tuple(sorted((h['alg'], h['content']) for h in component.get('hashes', []))),
            json.dumps(component.get('licenses', []), sort_keys=True))


def check_pair(directory):
    """Verify that the BOM pair describes the same inventory and return the JSON data."""
    data = load_bom(directory / 'bom.json')
    root = _parse_xml_root(directory / 'bom.xml')
    other = _xml_bom(root)
    require(_component_signature(data['metadata']['component']) == _component_signature(other['metadata']['component']),
            f'{directory.name}: JSON/XML 應用識別不同')
    json_components = Counter(map(_component_signature, flatten(data['components'])))
    xml_components = Counter(map(_component_signature, flatten(other['components'])))
    require(json_components == xml_components,
            f'{directory.name}: JSON/XML 元件、授權或雜湊不同')
    xml_deps = {d.get('ref'): sorted(c.get('ref') for c in d.findall('dependency'))
                for d in root.findall('dependencies/dependency')}
    json_deps = {d['ref']: sorted(d.get('dependsOn', [])) for d in data.get('dependencies', [])}
    require(xml_deps == json_deps, f'{directory.name}: JSON/XML 依賴關係不同')
    return data

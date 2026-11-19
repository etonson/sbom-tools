"""Compatibility imports for the shared functions used by existing callers."""

from sbom_tools.bom import (
    FAMILIES,
    check_pair,
    classify,
    digest,
    flatten,
    gpl_without_multiple_licenses,
    has_exception,
    has_license,
    load_bom,
    require,
    sha256_of,
)
from sbom_tools.evidence import load_evidence

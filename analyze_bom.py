#!/usr/bin/env python3
"""Generate offline Traditional Chinese HTML inventories."""

from sbom_tools.html_report import analyze, main

__all__ = ['analyze', 'main']


if __name__ == "__main__":
    raise SystemExit(main())

# Repository Guidelines

## Project Structure & Module Organization

This repository stores generated software bills of materials (SBOMs):

- `resource-bom/new-gtdmcash/`: inventory for the `gtdmcash` application.
- `resource-bom/new-gten/`: inventory for the `GTEN` application.

Each directory contains `bom.json` and `bom.xml` in CycloneDX 1.6 format. No application source, tests, or build configuration is currently present. Add inventories under `resource-bom/<project-name>/` using the same filenames.

## Build, Test, and Development Commands

Run these syntax checks from the repository root:

```sh
python3 -m json.tool resource-bom/new-gten/bom.json > /dev/null
python3 -c 'import xml.etree.ElementTree as E; E.parse("resource-bom/new-gten/bom.xml")'
```

Repeat for `new-gtdmcash` and any new project directories. These checks require Python 3. There is no local application to build or run. Existing inventories identify `org.cyclonedx:cyclonedx-maven-plugin:2.9.1` as their generator; regenerate them from the corresponding application checkout using its build configuration.

## Formatting & Naming Conventions

Preserve generator-produced formatting, UTF-8 encoding, and existing directory names. XML currently uses two-space indentation. Keep JSON and XML outputs together when updating an inventory. Avoid manually changing dependency versions, hashes, package URLs, or dependency relationships; regenerate from the source build.

## Validation Guidelines

No testing framework or coverage threshold is configured. Before submitting an update, parse both formats and compare application identity, component inventories, and dependency relationships. Syntax checks do not establish CycloneDX schema validity; validate against the declared schema when a compatible validator is available. Review unexpected dependency additions and removals.

## Commit & Pull Request Guidelines

Git history is unavailable in this checkout, so no established commit convention can be confirmed. Use concise, imperative subjects such as `Update GTEN dependency inventory`. In pull requests, identify the affected application, source revision, generation command, notable dependency changes, and validation performed.

## Agent Instructions

Prefer codebase-memory-mcp graph tools for code discovery. Fall back to file searches when the project is unindexed or results are insufficient; direct searches are appropriate for configuration and other non-code files.

# sbom-spdx-cyclonedx-license-cli-lite

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib%20only)-brightgreen.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Offline **CycloneDX 1.4/1.5 JSON** & **SPDX 2.2/2.3 JSON** Software Bill of Materials (SBOM) compliance auditor.  
100% pure Python 3.9+ standard library — zero external dependencies, air-gapped CI/CD ready.

Офлайн-аудитор соответствия SBOM (**CycloneDX 1.4/1.5 JSON** и **SPDX 2.2/2.3 JSON**).  
100% чистый Python 3.9+ stdlib — ноль внешних зависимостей, готов к работе в изолированных CI/CD-контурах.

---

## Policy Checks / Проверки политик

| Rule ID | Severity | Description / Описание |
|---|---|---|
| `LIC-COPYLEFT` | `CRITICAL` | Prohibited copyleft/restricted licenses (`AGPL-3.0`, `GPL-3.0`, `SSPL-1.0`) |
| `LIC-MISSING` | `HIGH` | Component has no declared or concluded license |
| `LIC-UNKNOWN` | `HIGH` | License is `UNKNOWN`, `NOASSERTION`, `NONE`, or `UNLICENSED` |
| `VER-UNPINNED` | `HIGH` | Floating/unpinned version (`*`, `latest`, `^1.0`, `~2.0`, `>=1.0`, empty) |
| `HASH-MISSING-SHA256` | `MEDIUM` | Missing `SHA-256` cryptographic digest |
| `PURL-MISSING` | `MEDIUM` | Missing Package URL (`purl`) |
| `DUP-CONFLICT-VER` | `MEDIUM` | Duplicate package with conflicting versions |
| `META-NO-SUPPLIER` | `LOW` | Missing supplier / author provenance metadata |

---

## CLI Examples / Примеры использования

```bash
# Audit a CycloneDX SBOM (text output, fail on high/critical)
py sbom_audit.py audit samples/cyclonedx_risky.json --fail-on high

# Audit an SPDX SBOM and output JSON
py sbom_audit.py audit samples/spdx_sample.json --format json --fail-on critical

# Audit with Markdown report and custom denied license
py sbom_audit.py audit samples/cyclonedx_clean.json --format markdown --deny-license EPL-2.0

# Diff two SBOM releases (added, removed, version/license changes)
py sbom_audit.py diff samples/cyclonedx_clean.json samples/cyclonedx_risky.json --format markdown
```

---

## Need the full Pro Studio?

Need the full Pro Studio (Web UI, custom policy matrix, SARIF 2.1.0, dependency graph & license attribution report)?  
Order / contact via FunPay: **https://funpay.com/users/20096179/**

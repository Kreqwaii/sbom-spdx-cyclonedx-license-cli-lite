#!/usr/bin/env python3
"""sbom-spdx-cyclonedx-license-cli-lite: Offline CycloneDX & SPDX SBOM compliance auditor."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

__version__ = "0.1.0"

SEVERITY_ORDER: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
}

DEFAULT_DENIED_LICENSES = {
    "AGPL-3.0",
    "AGPL-3.0-ONLY",
    "AGPL-3.0-OR-LATER",
    "GPL-3.0",
    "GPL-3.0-ONLY",
    "GPL-3.0-OR-LATER",
    "SSPL-1.0",
}

UNKNOWN_LICENSE_MARKERS = {"", "UNKNOWN", "NOASSERTION", "NONE", "UNLICENSED"}

FLOATING_VERSION_RE = re.compile(
    r"^(?:\*|x|X|latest|main|master|head|dev|nightly|[\^~><=].*|.*\.\*|.*\.x)$",
    re.IGNORECASE,
)


@dataclass
class Component:
    name: str
    version: str = ""
    purl: str = ""
    licenses: List[str] = field(default_factory=list)
    hashes: Dict[str, str] = field(default_factory=dict)
    supplier: str = ""
    bom_ref: str = ""


@dataclass
class Finding:
    rule_id: str
    severity: str  # critical, high, medium, low
    component: str
    version: str
    message: str
    remediation: str = ""


@dataclass
class AuditReport:
    sbom_format: str
    spec_version: str
    total_components: int
    findings: List[Finding]
    summary: Dict[str, int]


def _normalize_license(lic: str) -> str:
    return lic.strip().upper()


def _extract_cdx_licenses(raw_licenses: Any) -> List[str]:
    result: List[str] = []
    if not isinstance(raw_licenses, list):
        return result
    for item in raw_licenses:
        if not isinstance(item, dict):
            continue
        if "license" in item and isinstance(item["license"], dict):
            lic_obj = item["license"]
            lic_id = lic_obj.get("id") or lic_obj.get("name") or ""
            if lic_id:
                result.append(str(lic_id).strip())
        elif "expression" in item and item["expression"]:
            result.append(str(item["expression"]).strip())
    return result


def _extract_cdx_hashes(raw_hashes: Any) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    if not isinstance(raw_hashes, list):
        return hashes
    for h in raw_hashes:
        if isinstance(h, dict) and h.get("alg") and h.get("content"):
            hashes[str(h["alg"]).upper()] = str(h["content"]).strip()
    return hashes


def _extract_cdx_supplier(comp: Dict[str, Any]) -> str:
    supplier = comp.get("supplier")
    if isinstance(supplier, dict):
        name = supplier.get("name") or ""
        if name:
            return str(name).strip()
    elif isinstance(supplier, str) and supplier.strip():
        return supplier.strip()
    author = comp.get("author")
    if isinstance(author, str) and author.strip():
        return author.strip()
    publisher = comp.get("publisher")
    if isinstance(publisher, str) and publisher.strip():
        return publisher.strip()
    return ""


def parse_sbom(data: Dict[str, Any]) -> Tuple[str, str, List[Component]]:
    """Parse CycloneDX 1.4/1.5 JSON or SPDX 2.2/2.3 JSON into normalized components."""
    if not isinstance(data, dict):
        raise ValueError("SBOM root must be a JSON object.")

    if data.get("bomFormat") == "CycloneDX":
        spec_ver = str(data.get("specVersion") or "unknown")
        raw_comps = data.get("components") or []
        components: List[Component] = []
        for c in raw_comps:
            if not isinstance(c, dict):
                continue
            components.append(
                Component(
                    name=str(c.get("name") or "").strip(),
                    version=str(c.get("version") or "").strip(),
                    purl=str(c.get("purl") or "").strip(),
                    licenses=_extract_cdx_licenses(c.get("licenses")),
                    hashes=_extract_cdx_hashes(c.get("hashes")),
                    supplier=_extract_cdx_supplier(c),
                    bom_ref=str(c.get("bom-ref") or "").strip(),
                )
            )
        return "CycloneDX", spec_ver, components

    if "spdxVersion" in data or "packages" in data:
        spec_ver = str(data.get("spdxVersion") or "SPDX-2.3")
        raw_pkgs = data.get("packages") or []
        components = []
        for p in raw_pkgs:
            if not isinstance(p, dict):
                continue
            licenses: List[str] = []
            for key in ("licenseConcluded", "licenseDeclared"):
                val = p.get(key)
                if isinstance(val, str) and val.strip():
                    licenses.append(val.strip())
            # Deduplicate while preserving order
            seen = set()
            dedup_licenses = []
            for l in licenses:
                if l not in seen:
                    seen.add(l)
                    dedup_licenses.append(l)

            hashes: Dict[str, str] = {}
            for cs in p.get("checksums") or []:
                if isinstance(cs, dict) and cs.get("algorithm") and cs.get("checksumValue"):
                    hashes[str(cs["algorithm"]).upper()] = str(cs["checksumValue"]).strip()

            purl = ""
            for ref in p.get("externalRefs") or []:
                if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                    purl = str(ref.get("referenceLocator") or "").strip()
                    break

            supplier = str(p.get("supplier") or p.get("originator") or "").strip()
            if supplier.upper() == "NOASSERTION":
                supplier = ""

            components.append(
                Component(
                    name=str(p.get("name") or "").strip(),
                    version=str(p.get("versionInfo") or "").strip(),
                    purl=purl,
                    licenses=dedup_licenses,
                    hashes=hashes,
                    supplier=supplier,
                    bom_ref=str(p.get("SPDXID") or "").strip(),
                )
            )
        return "SPDX", spec_ver, components

    raise ValueError("Unsupported SBOM format: expected CycloneDX 1.4/1.5 or SPDX 2.2/2.3 JSON.")


def _is_floating_version(version: str) -> bool:
    v = version.strip()
    if not v:
        return True
    return bool(FLOATING_VERSION_RE.match(v))


def audit_components(
    sbom_format: str,
    spec_version: str,
    components: Sequence[Component],
    denied_licenses: Optional[Sequence[str]] = None,
) -> AuditReport:
    denied = {_normalize_license(x) for x in (denied_licenses or DEFAULT_DENIED_LICENSES)}
    findings: List[Finding] = []
    versions_by_name: Dict[str, set] = defaultdict(set)

    for comp in components:
        comp_name = comp.name or "<unnamed>"
        comp_ver = comp.version or "<unpinned>"

        if comp.name:
            versions_by_name[comp.name.lower()].add(comp.version or "<empty>")

        # 1. License policy & missing/unknown license
        if not comp.licenses:
            findings.append(
                Finding(
                    rule_id="LIC-MISSING",
                    severity="high",
                    component=comp_name,
                    version=comp_ver,
                    message="Component has no declared or concluded license.",
                    remediation="Declare a valid SPDX license identifier.",
                )
            )
        else:
            for lic in comp.licenses:
                norm = _normalize_license(lic)
                if norm in UNKNOWN_LICENSE_MARKERS:
                    findings.append(
                        Finding(
                            rule_id="LIC-UNKNOWN",
                            severity="high",
                            component=comp_name,
                            version=comp_ver,
                            message=f"Component has unknown/unasserted license '{lic}'.",
                            remediation="Resolve license metadata to a known SPDX identifier.",
                        )
                    )
                elif any(d in norm for d in denied):
                    findings.append(
                        Finding(
                            rule_id="LIC-COPYLEFT",
                            severity="critical",
                            component=comp_name,
                            version=comp_ver,
                            message=f"Prohibited copyleft/restricted license detected: '{lic}'.",
                            remediation="Replace component or obtain commercial exception.",
                        )
                    )

        # 2. Unpinned / floating version
        if _is_floating_version(comp.version):
            findings.append(
                Finding(
                    rule_id="VER-UNPINNED",
                    severity="high",
                    component=comp_name,
                    version=comp_ver,
                    message=f"Component version '{comp.version or 'empty'}' is unpinned or floating.",
                    remediation="Pin an exact immutable version.",
                )
            )

        # 3. Missing SHA-256 hash
        if "SHA-256" not in comp.hashes and "SHA256" not in comp.hashes:
            findings.append(
                Finding(
                    rule_id="HASH-MISSING-SHA256",
                    severity="medium",
                    component=comp_name,
                    version=comp_ver,
                    message="Component is missing a SHA-256 cryptographic hash.",
                    remediation="Include SHA-256 digest for artifact integrity verification.",
                )
            )

        # 4. Missing PURL
        if not comp.purl:
            findings.append(
                Finding(
                    rule_id="PURL-MISSING",
                    severity="medium",
                    component=comp_name,
                    version=comp_ver,
                    message="Component is missing a Package URL (purl).",
                    remediation="Add a valid pkg: purl identifier.",
                )
            )

        # 5. Missing supplier/author metadata
        if not comp.supplier:
            findings.append(
                Finding(
                    rule_id="META-NO-SUPPLIER",
                    severity="low",
                    component=comp_name,
                    version=comp_ver,
                    message="Component is missing supplier/author metadata.",
                    remediation="Populate supplier or author field for provenance tracking.",
                )
            )

    # 6. Duplicate packages with conflicting versions
    for name_lower, vers in sorted(versions_by_name.items()):
        if len(vers) > 1:
            findings.append(
                Finding(
                    rule_id="DUP-CONFLICT-VER",
                    severity="medium",
                    component=name_lower,
                    version=", ".join(sorted(vers)),
                    message=f"Duplicate package '{name_lower}' found with conflicting versions: {', '.join(sorted(vers))}.",
                    remediation="Deduplicate dependency tree to a single consistent version.",
                )
            )

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    return AuditReport(
        sbom_format=sbom_format,
        spec_version=spec_version,
        total_components=len(components),
        findings=findings,
        summary=summary,
    )


def diff_sboms(old_comps: Sequence[Component], new_comps: Sequence[Component]) -> Dict[str, Any]:
    old_map = {c.name.lower(): c for c in old_comps if c.name}
    new_map = {c.name.lower(): c for c in new_comps if c.name}

    added = [
        {"name": new_map[k].name, "version": new_map[k].version, "licenses": new_map[k].licenses}
        for k in sorted(new_map.keys() - old_map.keys())
    ]
    removed = [
        {"name": old_map[k].name, "version": old_map[k].version, "licenses": old_map[k].licenses}
        for k in sorted(old_map.keys() - new_map.keys())
    ]
    changed = []
    for k in sorted(old_map.keys() & new_map.keys()):
        o, n = old_map[k], new_map[k]
        if o.version != n.version or o.licenses != n.licenses:
            changed.append(
                {
                    "name": n.name,
                    "old_version": o.version,
                    "new_version": n.version,
                    "old_licenses": o.licenses,
                    "new_licenses": n.licenses,
                }
            )

    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_count": len(changed),
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def format_report_json(report: AuditReport) -> str:
    return json.dumps(asdict(report), indent=2)


def format_report_markdown(report: AuditReport) -> str:
    lines = [
        f"# SBOM Compliance Audit ({report.sbom_format} {report.spec_version})",
        "",
        f"- **Total Components:** {report.total_components}",
        f"- **Critical:** {report.summary['critical']} | **High:** {report.summary['high']} | **Medium:** {report.summary['medium']} | **Low:** {report.summary['low']}",
        "",
    ]
    if not report.findings:
        lines.append("All checks passed with 0 findings.")
        return "\n".join(lines)

    lines.extend([
        "| Severity | Rule | Component | Version | Message |",
        "|---|---|---|---|---|",
    ])
    for f in report.findings:
        lines.append(f"| {f.severity.upper()} | `{f.rule_id}` | `{f.component}` | `{f.version}` | {f.message} |")
    return "\n".join(lines)


def format_report_text(report: AuditReport) -> str:
    lines = [
        f"SBOM Audit: {report.sbom_format} {report.spec_version} ({report.total_components} components)",
        f"Summary: critical={report.summary['critical']} high={report.summary['high']} medium={report.summary['medium']} low={report.summary['low']}",
    ]
    for f in report.findings:
        lines.append(f"[{f.severity.upper()}] {f.rule_id} {f.component}@{f.version}: {f.message}")
    return "\n".join(lines)


def should_fail(findings: Sequence[Finding], fail_on: str) -> bool:
    threshold = SEVERITY_ORDER.get(fail_on.lower(), 0)
    if threshold == 0:
        return False
    return any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in findings)


def _load_json(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    return json.loads(p.read_text(encoding="utf-8"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom-spdx-cyclonedx-license-cli-lite",
        description="Offline CycloneDX 1.4/1.5 & SPDX 2.2/2.3 SBOM compliance auditor.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    audit_p = sub.add_parser("audit", help="Audit an SBOM JSON file for license & supply-chain risks.")
    audit_p.add_argument("file", help="Path to CycloneDX or SPDX JSON file.")
    audit_p.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    audit_p.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help="Exit with code 1 if any finding meets or exceeds this severity (default: high).",
    )
    audit_p.add_argument(
        "--deny-license",
        action="append",
        default=[],
        help="Additional license ID to deny (can be repeated).",
    )

    diff_p = sub.add_parser("diff", help="Compare two SBOM JSON files.")
    diff_p.add_argument("old_file", help="Path to baseline SBOM JSON.")
    diff_p.add_argument("new_file", help="Path to target SBOM JSON.")
    diff_p.add_argument("--format", choices=["json", "markdown"], default="markdown")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "audit":
            data = _load_json(args.file)
            fmt, spec, comps = parse_sbom(data)
            denied = set(DEFAULT_DENIED_LICENSES) | {_normalize_license(x) for x in args.deny_license}
            report = audit_components(fmt, spec, comps, denied_licenses=sorted(denied))
            if args.format == "json":
                print(format_report_json(report))
            elif args.format == "markdown":
                print(format_report_markdown(report))
            else:
                print(format_report_text(report))
            return 1 if should_fail(report.findings, args.fail_on) else 0

        if args.command == "diff":
            old_data = _load_json(args.old_file)
            new_data = _load_json(args.new_file)
            _, _, old_comps = parse_sbom(old_data)
            _, _, new_comps = parse_sbom(new_data)
            diff_res = diff_sboms(old_comps, new_comps)
            if args.format == "json":
                print(json.dumps(diff_res, indent=2))
            else:
                lines = [
                    "# SBOM Diff Report",
                    f"- **Added:** {diff_res['added_count']} | **Removed:** {diff_res['removed_count']} | **Changed:** {diff_res['changed_count']}",
                ]
                for item in diff_res["added"]:
                    lines.append(f"- `+ {item['name']}@{item['version']}` ({', '.join(item['licenses']) or 'no license'})")
                for item in diff_res["removed"]:
                    lines.append(f"- `- {item['name']}@{item['version']}`")
                for item in diff_res["changed"]:
                    lines.append(
                        f"- `~ {item['name']}`: `{item['old_version']}` -> `{item['new_version']}`"
                    )
                print("\n".join(lines))
            return 0
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Generate TypeScript rules by adapting JavaScript generator output."""

from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generate_javascript_pqc_runtime import RULES  # noqa: E402

LANG = "typescript"
EXT = "ts"
RULES_DIR_PQC = ROOT / f"rules/languages/{LANG}/pqc"
RULES_DIR_RT = ROOT / f"rules/languages/{LANG}/runtime-security"
TESTS = ROOT / f"tests/languages/{LANG}"


def convert_rule_id(rule_id: str) -> str:
    return rule_id.replace("javascript-", f"{LANG}-")


def convert_yaml(yaml: str, rule_id: str) -> str:
    out = yaml.replace("javascript-", f"{LANG}-")
    out = out.replace("languages:\n      - javascript", f"languages:\n      - {LANG}")
    out = out.replace(f"id: javascript-", f"id: {LANG}-")
    return out


def convert_test(code: str) -> str:
    code = code.replace("const ", "const ")
    if "require(" in code and "import " not in code:
        code = re.sub(
            r"const (\w+) = require\('([^']+)'\);",
            r"import \1 from '\2';",
            code,
        )
        code = re.sub(
            r"const \{ ([^}]+) \} = require\('([^']+)'\);",
            r"import { \1 } from '\2';",
            code,
        )
    return code


def write_expected(rule_id: str, cat: str):
    import json

    test_dir = TESTS / cat / rule_id
    test_file = test_dir / f"test_code.{EXT}"
    rules_dir = RULES_DIR_PQC if cat == "pqc" else RULES_DIR_RT
    rule_file = rules_dir / f"{rule_id}.yml"
    result = subprocess.run(
        ["semgrep", "--config", str(rule_file), "--json", str(test_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    data = json.loads(result.stdout or "{}")
    findings = []
    for item in data.get("results", []):
        rid = item["check_id"].split(".")[-1]
        if rid != rule_id:
            continue
        findings.append(
            {
                "file": f"test_code.{EXT}",
                "line": item["start"]["line"],
                "rule_id": rule_id,
                "message": item["extra"]["message"],
            }
        )
    findings.sort(key=lambda x: x["line"])
    lines = ["findings:"]
    for f in findings:
        lines.append(f"  - file: {f['file']}")
        lines.append(f"    line: {f['line']}")
        lines.append(f"    rule_id: {f['rule_id']}")
        lines.append(f'    message: "{f["message"]}"')
    lines.append("")
    lines.append("no_findings:")
    lines.append(f"  - negative_cases.{EXT}")
    (test_dir / "expected.yml").write_text("\n".join(lines) + "\n")


def main():
    for js_id, spec in RULES.items():
        rule_id = convert_rule_id(js_id)
        cat = spec["category"]
        rules_dir = RULES_DIR_PQC if cat == "pqc" else RULES_DIR_RT
        rules_dir.mkdir(parents=True, exist_ok=True)
        (rules_dir / f"{rule_id}.yml").write_text(convert_yaml(spec["yaml"], rule_id))
        test_dir = TESTS / cat / rule_id
        test_dir.mkdir(parents=True, exist_ok=True)
        (test_dir / f"test_code.{EXT}").write_text(convert_test(spec["test"]))
        (test_dir / f"negative_cases.{EXT}").write_text(convert_test(spec["negative"]))
        write_expected(rule_id, cat)
    print(f"Generated {len(RULES)} TypeScript rules with tests")


if __name__ == "__main__":
    main()

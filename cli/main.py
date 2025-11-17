#!/usr/bin/env python3
"""
Argus Observe Rules CLI - For rule management and testing
"""

import json
import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

import typer
import yaml

app = typer.Typer(help="Argus Observe Rules - Security rule management and testing")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.command()
def run(
    target_dir: str = typer.Argument(..., help="Directory to scan with rules"),
    patterns: List[str] = typer.Argument(
        None, help="Rule patterns to match (e.g., 'crypto', 'md5', 'go-weak-*')"
    ),
    all_rules: bool = typer.Option(False, "--all", help="Run all available rules"),
):
    """Run security rules against a target directory"""
    target_dir = Path(target_dir).resolve().absolute()

    if not target_dir.exists():
        typer.echo(f"Error: Target directory {target_dir} does not exist")
        return typer.Exit(1)

    if all_rules:
        patterns = None

    rules = load_semgrep_rules(patterns=patterns)

    ## write to temporary file to execute for semgrep cli
    with tempfile.NamedTemporaryFile(
        mode="w", prefix="semgrep-", suffix=".yaml", delete=True
    ) as temp_file:
        rule_content = {"rules": rules}
        temp_file.write(yaml.dump(rule_content))
        temp_file.flush()
        temp_file_path = temp_file.name

        semgrep_cli = ["semgrep", "--config", temp_file_path, target_dir]
        subprocess.run(semgrep_cli, check=True)


@app.command()
def validate(
    rules_path: Optional[str] = typer.Option(
        None, "--rules", "-r", help="Specific rule file or directory to validate"
    ),
):
    """Validate rule files with semgrep"""
    if rules_path:
        typer.echo(f"Validating rules: {rules_path}")
        semgrep_cli = ["semgrep", "--validate", "--config", rules_path]
        subprocess.run(semgrep_cli, check=True)
    else:
        typer.echo("Validating all rules")
        rules = load_semgrep_rules()
        ## write to temporary file to execute for semgrep cli
        with tempfile.NamedTemporaryFile(
            mode="w",
            prefix="semgrep-",
            suffix=".yaml",
            delete=True,
        ) as temp_file:
            rule_content = {"rules": rules}
            temp_file.write(yaml.dump(rule_content))
            temp_file.flush()
            temp_file_path = temp_file.name
            semgrep_cli = ["semgrep", "--validate", "--config", temp_file_path]
            subprocess.run(semgrep_cli, check=True)


@app.command()
def test(
    rule: Optional[str] = typer.Option(
        None, "--rule", "-r", help="Specific rule to test"
    ),
    patterns: List[str] = typer.Argument(
        None, help="Rule patterns to match (e.g., 'crypto', 'md5', 'go-weak-*')"
    ),
    all_rules: bool = typer.Option(False, "--all", help="Test all rules"),
):
    """Run the full test suite against test cases"""
    if all_rules:
        rule = None
        patterns = []

    if rule:
        patterns = [rule]

    rules = load_semgrep_rules(patterns=patterns)
    if len(rules) == 0:
        typer.echo(
            "No rules discovered, verify that your patterns match to rule files."
        )
        return

    typer.echo(f"Testing {len(rules)} rules")

    with tempfile.NamedTemporaryFile(
        mode="w",
        prefix="semgrep-",
        suffix=".yaml",
        delete=True,
    ) as temp_file:
        rule_content = {"rules": rules}
        temp_file.write(yaml.dump(rule_content))
        temp_file.flush()
        temp_file_path = temp_file.name

        semgrep_cli = [
            "semgrep",
            "--config",
            temp_file_path,
            "--json",
            "--no-git-ignore",
            "tests",
        ]
        result = subprocess.run(semgrep_cli, capture_output=True, text=True)

        if result.returncode != 0:
            typer.echo(f"Semgrep failed: {result.stderr}")
            return typer.Exit(1)

        semgrep_output = json.loads(result.stdout)
        findings = semgrep_output.get("results", [])

        results_by_rule = group_semgrep_results_by_rule_id(findings)

        test_expectations = load_test_expectations(rules)

        execute_tests(results_by_rule, test_expectations, len(rules))


# Helper to load up rules from the files to a single list to pass to semgrep
def load_semgrep_rules(patterns: List[str] = []) -> list[dict]:
    rules_dir = Path("./rules").resolve().absolute()
    rule_files = list(rules_dir.rglob("*.yml"))

    if not patterns:
        matches = rule_files
    else:
        matches = [
            f
            for f in rule_files
            if any(re.search(p, f.name, re.IGNORECASE) for p in patterns)
        ]

    # need to group the semgrep rules as one to run the cli just once
    rules = []
    for rule_file in matches:
        try:
            with open(rule_file, "r") as f:
                rule_content = yaml.safe_load(f)

                if "rules" not in rule_content:
                    raise ValueError(f"Missing 'rules' in file {rule_file}")

                rules.extend(rule_content.get("rules", []))
        except Exception as e:
            logger.error(f"Failed to extract rules from {rule_file.name}: {e}")

    return rules


def group_semgrep_results_by_rule_id(findings):
    results_by_rule = {}
    for finding in findings:
        rule_id = finding["check_id"].split(".")[-1]
        file_path = Path(finding["path"]).name  # Just filename
        line = finding["start"]["line"]

        if rule_id not in results_by_rule:
            results_by_rule[rule_id] = []

        results_by_rule[rule_id].append(
            {
                "file": file_path,
                "full_path": finding["path"],  # Keep full path for debugging
                "line": line,
                "message": finding["extra"]["message"],
            }
        )
    return results_by_rule


def load_test_expectations(rules):
    # Only look for test expectations that match the loaded rules
    tests_dir = Path("tests")
    rule_expectations = {}

    for rule in rules:
        rule_id = rule["id"]
        # Find test directory that matches this rule ID
        expected_files = list(tests_dir.rglob(f"*/{rule_id}/expected.yml"))

        if not expected_files:
            typer.echo(f"WARNING: {rule_id}: no test cases found")
        else:
            for expected_file in expected_files:
                try:
                    with open(expected_file, "r") as f:
                        expected_data = yaml.safe_load(f)
                        # Store both the expectations and the test directory path
                        test_dir = expected_file.parent
                        rule_expectations[rule_id] = {
                            "expectations": expected_data,
                            "test_dir": str(test_dir),
                        }
                        break  # Only take the first match
                except Exception as e:
                    typer.echo(f"Failed to load {expected_file}: {e}")
                    continue
    return rule_expectations


def execute_tests(results_by_rule, rule_expectations, total_rules_loaded):
    # Validate results
    passed_tests = 0
    failed_tests = 0

    typer.echo("Running test validation...\n")

    # Check each rule that has expectations
    for rule_id, rule_data in rule_expectations.items():
        # Filter actual findings to only include those in the rule's test directory
        rule_test_dir = rule_data["test_dir"]
        all_actual_findings = results_by_rule.get(rule_id, [])
        # Use precise path matching to avoid matching subdirectories with similar names
        # e.g., go-crypto-aes should not match go-crypto-aes-ecb-mode
        actual_findings = [
            f
            for f in all_actual_findings
            if f.get("full_path", "").startswith(rule_test_dir + "/")
            and not f.get("full_path", "")
            .replace(rule_test_dir + "/", "")
            .startswith("../")
        ]

        expected = rule_data["expectations"]
        expected_findings = expected.get("findings") or []
        no_findings_files = expected.get("no_findings") or []

        # Validate expected findings
        passed = True

        # Check if we found all expected findings
        for exp_finding in expected_findings:
            exp_file = Path(exp_finding["file"]).name  # Normalize to just filename
            exp_line = exp_finding["line"]

            found_match = False
            for actual in actual_findings:
                actual_file = Path(actual["file"]).name  # Normalize to just filename
                if actual_file == exp_file and actual["line"] == exp_line:
                    found_match = True
                    break

            if not found_match:
                typer.echo(
                    f"FAIL: {rule_id}: Missing expected finding at {exp_file}:{exp_line}"
                )
                passed = False

        # Check if we have any unexpected findings
        for actual in actual_findings:
            actual_file = Path(actual["file"]).name  # Normalize to just filename
            actual_line = actual["line"]

            found_expected = False
            for exp_finding in expected_findings:
                exp_file = Path(exp_finding["file"]).name  # Normalize to just filename
                if exp_file == actual_file and exp_finding["line"] == actual_line:
                    found_expected = True
                    break

            if not found_expected:
                full_path = actual.get("full_path", "unknown")
                typer.echo(
                    f"FAIL: {rule_id}: Unexpected finding at {actual_file}:{actual_line} (full path: {full_path})"
                )
                typer.echo(f"      Message: {actual['message']}")
                passed = False

        # Check that no findings files have no actual findings
        for no_finding_file in no_findings_files:
            no_finding_filename = Path(
                no_finding_file
            ).name  # Normalize to just filename
            has_findings = any(
                Path(f["file"]).name == no_finding_filename for f in actual_findings
            )
            if has_findings:
                typer.echo(
                    f"FAIL: {rule_id}: Found unexpected findings in {no_finding_file}"
                )
                passed = False

        if passed:
            typer.echo(f"PASS: {rule_id}")
            passed_tests += 1
        else:
            failed_tests += 1

    # Report summary
    total_rules_tested = len(rule_expectations)
    rules_without_tests = total_rules_loaded - total_rules_tested

    summary_parts = [
        f"{passed_tests} passed",
        f"{failed_tests} failed",
        f"{total_rules_tested} total rules tested",
    ]
    if rules_without_tests > 0:
        summary_parts.append(f"{rules_without_tests} rules without tests")

    typer.echo(f"\nTest Summary: {', '.join(summary_parts)}")

    if failed_tests > 0:
        typer.echo(f"{failed_tests} test(s) failed!")
        raise typer.Exit(1)
    else:
        typer.echo("All tests passed!")
        raise typer.Exit(0)


if __name__ == "__main__":
    app()

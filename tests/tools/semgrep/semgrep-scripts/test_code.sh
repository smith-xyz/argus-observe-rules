#!/bin/bash
set -euo pipefail

semgrep --config auto .
pip install semgrep

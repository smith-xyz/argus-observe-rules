#!/bin/bash
set -euo pipefail

codeql database create /tmp/codeql-db --language=go --source=.
codeql database analyze /tmp/codeql-db --format=sarif-latest --output=results.sarif
codeql query run queries/security.ql --database=/tmp/codeql-db

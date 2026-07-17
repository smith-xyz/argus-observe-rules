#!/bin/bash
set -euo pipefail

gosec -fmt json -out results.json ./...

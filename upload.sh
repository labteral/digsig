#!/bin/bash
# Build and upload digsig to PyPI.
# Usage: run ./upload.sh from a virtualenv with build and twine installed.
set -euo pipefail
cd "$(dirname "$0")"

# Clean previous artifacts so nothing stale gets uploaded.
rm -rf dist build digsig.egg-info

# Build sdist + wheel from the pyproject (PEP 517).
python3 -m build

# Validate metadata and description rendering before uploading.
python3 -m twine check dist/*

python3 -m twine upload dist/*

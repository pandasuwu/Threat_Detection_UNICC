#!/usr/bin/env bash
# Run the eval suite. API must already be running on port 8000.
set -euo pipefail
cd "$(dirname "$0")/phase4"
python3 eval.py --out eval_results.json "$@"

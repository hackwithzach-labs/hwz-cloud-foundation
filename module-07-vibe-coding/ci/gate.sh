#!/usr/bin/env bash
# ci/gate.sh — the pre-deploy gate, as one script a pipeline can call.
#
# The point of this file is that it is boring. A gate people can argue with is
# a gate that gets skipped "just this once", so it takes no arguments, makes no
# decisions, and either exits 0 or fails the build.
set -euo pipefail

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN_JSON="${1:-plan.json}"

echo "== hwz pre-deploy gate =="

if [ ! -f "$PLAN_JSON" ]; then
  # Fail closed. A missing plan is not "nothing to check" -- it usually means
  # the plan step failed and the pipeline carried on regardless.
  echo "!! no plan at $PLAN_JSON. Refusing to pass a gate with nothing to gate."
  echo "   Generate one first:  terraform plan -out plan.out && terraform show -json plan.out > $PLAN_JSON"
  exit 1
fi

python3 "$MODULE_DIR/scan/scan.py" --plan "$PLAN_JSON"

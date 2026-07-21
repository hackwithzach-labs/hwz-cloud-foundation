"""
config.py :: the four API-security controls, each a single flag, plus an
always-on cost safety breaker.

This is the module-2 equivalent of baseline.tfvars / hardened.tfvars. The API
app is WEAK BY POLICY, never broken by omission: every endpoint runs, every
request is served, and every hole is one flag below set to False.

Run weak:      HWZ_PROFILE=baseline  uvicorn app.main:app
Run hardened:  HWZ_PROFILE=hardened  uvicorn app.main:app

Nothing here reads AWS. The app fronts a mock model call so the whole
build/scan/harden loop runs locally at zero cost.

(C) 2026 Vigilantia Technologies INC. All rights reserved.
"""
import os
from dataclasses import dataclass


EXPECTED_AUDIENCE = "hwz-inference-api"
JWT_SECRET = "lab-demo-secret-not-for-production"


@dataclass(frozen=True)
class Controls:
    verify_audience: bool      # Control 1: audience-bound token verification
    validate_schema: bool      # Control 2: JSON Schema on every request body
    enforce_caps: bool         # Control 3: per-token rate AND cost cap
    structured_audit: bool     # Control 4: structured audit logging


BASELINE = Controls(
    verify_audience=False,
    validate_schema=False,
    enforce_caps=False,
    structured_audit=False,
)

HARDENED = Controls(
    verify_audience=True,
    validate_schema=True,
    enforce_caps=True,
    structured_audit=True,
)

# TEACHING cap (Control 3). Baseline turns it OFF so you can attack its
# absence. Per-token and generous; the lesson is the control, not your wallet.
MAX_REQUESTS_PER_TOKEN = 5
MAX_TOKENS_PER_REQUEST = 400
MAX_COST_PER_TOKEN_USD = 0.10


# ---------------------------------------------------------------------------
# ABSOLUTE SAFETY CIRCUIT BREAKER  (always on, no profile can disable it)
# ---------------------------------------------------------------------------
# The teaching cap above is the thing you attack, so baseline switches it off.
# THIS breaker is different: it protects your real AWS bill and can NEVER be
# turned off, in any profile, by any request. It exists because you never trust
# the cloud's billing to stop a runaway: AWS Budgets ALERT, they do not
# HARD-STOP. So the app stops itself.
#
# Course rule: the cost-bomb attack is demonstrated against the MOCK model
# (USE_REAL_MODEL=False, the default) where it costs nothing. If you ever set
# USE_REAL_MODEL=True, this breaker plus a tiny token ceiling plus the cheapest
# model keeps a mistake to pennies. You do NOT flood a real paid model. Ever.
USE_REAL_MODEL = os.environ.get("HWZ_USE_REAL_MODEL", "false").lower() == "true"

ABS_MAX_MODEL_CALLS_PER_PROCESS = 25
ABS_MAX_TOKENS_PER_CALL = 128
ABS_CHEAPEST_MODEL_ONLY = True


def load() -> Controls:
    profile = os.environ.get("HWZ_PROFILE", "baseline").lower()
    if profile == "hardened":
        return HARDENED
    return BASELINE

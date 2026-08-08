# BASELINE / NAKED profile — the model ships with no guardrail and no WAF.
# Deploy this, run scan/scan.py (5 gaps), run attack/inject.py (6/6 succeed),
# review the app log, and see an authenticated, schema-clean API that will
# obey a stranger's buried instruction and echo a secret back out.
guardrails_enabled = false
waf_enabled        = false

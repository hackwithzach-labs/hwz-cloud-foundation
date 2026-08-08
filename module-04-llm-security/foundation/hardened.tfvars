# HARDENED profile — both firewalls on. The guardrail reads meaning (input +
# output + data/instruction boundary); the WAF reads structure (managed rules
# + rate cap) at the edge. Re-run scan/scan.py (PASS), re-run attack/inject.py
# (0/6 succeed), review the logs and confirm the blocks landed in the Module 3
# detection pipeline.
guardrails_enabled = true
waf_enabled        = true
rate_limit         = 2000

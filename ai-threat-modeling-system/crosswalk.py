"""crosswalk.py -- Appendix C: register rows to the control vocabularies an
auditor asks about. NIST SP 800-53 Rev 5 control families and representative
controls, CIS Controls v8 safeguards, and NIST AI RMF 1.0 functions for the
AI rows. Hand-mapped per row; keep it that way, a keyword mapping gets this wrong.
"""

CROSSWALK = {
    # id: (NIST 800-53, CIS v8, NIST AI RMF / GAI profile)
    "WS-01": ("SI-10 Information Input Validation; SA-11 Developer Testing", "16.1, 16.7 Application software security", "n/a"),
    "WS-02": ("IA-2 Identification and Authentication; AC-3 Access Enforcement; SC-23 Session Authenticity", "6.1, 6.3 Access control management", "n/a"),
    "WS-03": ("AC-6 Least Privilege; SC-7 Boundary Protection; AC-3", "4.1, 6.8 Secure configuration, access control", "n/a"),
    "WS-04": ("AC-3 Access Enforcement; AC-6", "6.8 Define and maintain role-based access control", "n/a"),
    "WS-05": ("AC-6 Least Privilege; SI-10; SI-15 Information Output Filtering", "16.1, 16.10 Secure design, application-layer controls", "Manage 2.4 (mechanisms to supersede, disengage or deactivate); Map 5.1 (likelihood and magnitude of impacts); GAI: Human-AI Configuration"),
    "WS-06": ("SC-28 Protection of Information at Rest; IA-5 Authenticator Management; SI-10", "3.11, 16.7", "Measure 2.7 (security and resilience); GAI: Information Security, Data Privacy"),
    "WS-07": ("IA-5 Authenticator Management; SC-12 Key Management; SA-11", "3.11 Encrypt sensitive data at rest; 16.12 Secrets in code", "n/a"),
    "WS-08": ("SI-10; CM-7 Least Functionality", "16.1, 16.7, 4.8", "n/a"),
    "WS-09": ("SI-10; SI-15; SC-18 Mobile Code", "16.7, 16.10", "GAI: Information Integrity (model output rendered as markup)"),
    "WS-10": ("IA-5(1) Password-based Authentication; SC-28", "3.11, 6.1", "n/a"),
    "WS-11": ("SI-10; SA-8 Security Engineering Principles; AC-3", "16.1, 16.10", "n/a"),
    "WS-12": ("CM-6 Configuration Settings; CM-7; SC-7", "4.1, 4.8, 16.9", "n/a"),
    "WS-13": ("AC-7 Unsuccessful Logon Attempts; IA-2", "6.2, 6.3", "n/a"),
    "WS-14": ("SC-23 Session Authenticity; SI-10", "16.1, 16.7", "n/a"),
    "WS-15": ("AU-2 Event Logging; AU-3 Content of Audit Records; AU-6 Review", "8.2, 8.5, 8.11 Audit log management", "Measure 2.7; Manage 4.1 (post-deployment monitoring)"),
    "WS-16": ("SI-10; SC-7; CM-6", "4.1, 13.10 (application-layer filtering), 16.7", "n/a"),
    "CAP-01": ("SI-10 Input Validation; SI-4 System Monitoring; SC-7", "16.1, 13.10", "Map 1.1; Measure 2.7; Manage 2.4; GAI: Information Integrity, Information Security"),
    "CAP-02": ("AC-6; CM-5 Access Restrictions for Change; SA-8", "16.1, 4.1", "Govern 1.7 (decommission/override); Manage 2.4; GAI: Human-AI Configuration"),
    "CAP-03": ("AC-6 Least Privilege; AC-3; IA-2(12) identity binding", "6.8, 3.3 Data access control", "Map 2.2 (how outputs are used and overseen); Measure 2.7, 2.10; GAI: Data Privacy"),
    "CAP-04": ("AC-6; AC-17 Remote Access; SC-7(5) Deny by default; CA-3 Information Exchange", "3.3, 13.10", "Govern 1.7; Manage 2.4; GAI: Human-AI Configuration"),
    "CAP-05": ("AU-6 Audit Review; SI-4; IR-4 Incident Handling", "8.11, 17.3 (incident response)", "Manage 4.1; Measure 2.7"),
    "CAP-06": ("SI-10; SI-3 Malicious Code Protection (content handling)", "16.1, 10.1", "Map 1.1 (intended settings and inputs); Measure 2.7; GAI: Information Integrity"),
    "CAP-07": ("AC-6(5) Privileged Accounts; PS-6; AT-2 Awareness Training; SI-10", "14.1, 14.2 Security awareness", "Govern 3.2 (roles for human-AI configurations); Measure 2.8 (transparency and accountability); GAI: Human-AI Configuration"),
    "CAP-08": ("SR-3 Supply Chain Controls and Processes; CM-3 Configuration Change Control; CM-8 System Component Inventory", "2.1, 2.2 Software inventory; 16.4 Third-party components", "Govern 6.1 (third-party); Map 4.1; GAI: Value Chain and Component Integration"),
    "CAP-09": ("CM-3 Configuration Change Control; CM-6; CA-7 Continuous Monitoring", "4.1, 4.2, 7.1 Vulnerability management", "Manage 4.1; Measure 2.6"),
    "CAP-10": ("SC-5 Denial of Service Protection; SC-6 Resource Availability", "16.1", "Measure 2.6 (reliability); GAI: Unbounded Consumption"),
    "CAP-V1": ("SC-13, SC-28, AU-2, AU-9, AC-6, SC-7 (verified)", "3.11, 8.2, 8.9, 12.x (verified)", "Govern 1.1 (policies in place)"),
    "CAP-V2": ("SC-7, AC-6, IA-5, SC-12 (verified)", "12.x, 3.11 (verified)", "Map 4.1; Govern 6.1"),
}

"""
CWE → ATT&CK Technique Mapping
Coverage: top ~100 CWEs covering ~95% of the corpus.
Source: CAPEC-ATT&CK cross-walk + MITRE manual mappings.

Each CWE maps to one or more ATT&CK technique IDs.
Primary technique listed first (highest semantic relevance).

Usage:
    from cwe_to_attack import get_techniques_for_cwe
    techniques = get_techniques_for_cwe("CWE-79")  # ["T1059.007", "T1189"]
"""

# CWE ID → [ATT&CK technique IDs] (primary first)
CWE_TO_ATTACK: dict[str, list[str]] = {
    # Injection
    "CWE-79":  ["T1059.007", "T1189"],           # XSS → JS Exec + Drive-by
    "CWE-89":  ["T1190"],                          # SQL Injection → Exploit Public App
    "CWE-78":  ["T1059.004", "T1059"],             # OS Command Injection → Shell Exec
    "CWE-77":  ["T1059"],                          # Command Injection → C&SI
    "CWE-94":  ["T1059"],                          # Code Injection → C&SI
    "CWE-74":  ["T1190"],                          # Injection (generic) → Exploit Public App
    "CWE-98":  ["T1059.007"],                      # File Inclusion → JS/Script Exec
    "CWE-917": ["T1059"],                          # EL Injection
    "CWE-1321":["T1059"],                          # Prototype Pollution
    "CWE-96":  ["T1059"],                          # Dynamic Code Evaluation

    # Buffer / Memory Errors
    "CWE-787": ["T1203", "T1068"],                 # OOB Write → Client Exploit + Priv Esc
    "CWE-125": ["T1005"],                          # OOB Read → Data from Local System
    "CWE-121": ["T1203"],                          # Stack Buffer Overflow
    "CWE-122": ["T1203"],                          # Heap Buffer Overflow
    "CWE-120": ["T1203"],                          # Classic Buffer Overflow
    "CWE-119": ["T1203", "T1068"],                 # Buffer Mismanagement
    "CWE-190": ["T1203"],                          # Integer Overflow → Exploit
    "CWE-191": ["T1203"],                          # Integer Underflow
    "CWE-416": ["T1203"],                          # Use-After-Free
    "CWE-415": ["T1203"],                          # Double Free
    "CWE-676": ["T1203"],                          # Dangerous C functions
    "CWE-124": ["T1203"],                          # Buffer Underwrite
    "CWE-126": ["T1005"],                          # Buffer Over-read
    "CWE-476": ["T1499"],                          # NULL ptr deref → DoS

    # Access Control / Authentication
    "CWE-862": ["T1078", "T1548"],                 # Missing Auth → Valid Accounts
    "CWE-863": ["T1078"],                          # Incorrect Authorization
    "CWE-284": ["T1078"],                          # Improper Access Control
    "CWE-287": ["T1078", "T1556"],                 # Improper Authentication
    "CWE-306": ["T1078"],                          # Missing Auth for Critical Function
    "CWE-285": ["T1078"],                          # Improper Authorization
    "CWE-639": ["T1078"],                          # IDOR
    "CWE-613": ["T1550.004"],                      # Session Expiry → Web Session Cookie
    "CWE-384": ["T1550.004"],                      # Session Fixation
    "CWE-294": ["T1557"],                          # Auth Bypass via Capture-Replay
    "CWE-290": ["T1556"],                          # Auth Bypass via Spoofing
    "CWE-303": ["T1078"],                          # Incorrect Auth Implementation
    "CWE-308": ["T1078"],                          # Single-Factor Auth for Critical Action

    # Privilege Escalation
    "CWE-269": ["T1548"],                          # Improper Privilege Management
    "CWE-266": ["T1548"],                          # Incorrect Privilege Assignment
    "CWE-250": ["T1548"],                          # Execution with Unnecessary Privileges
    "CWE-732": ["T1222"],                          # Incorrect Permission Assignment
    "CWE-276": ["T1222"],                          # Incorrect Default Permissions
    "CWE-277": ["T1222"],                          # Insecure Inherited Permissions
    "CWE-668": ["T1548"],                          # Exposure of Resource to Wrong Sphere
    "CWE-1285":["T1548"],                          # Improper validation of array index

    # Credential Exposure
    "CWE-798": ["T1552.001", "T1552"],             # Hardcoded Credentials
    "CWE-259": ["T1552.001"],                      # Hardcoded Password
    "CWE-321": ["T1552.004"],                      # Hardcoded Crypto Key
    "CWE-532": ["T1552.003"],                      # Sensitive Info in Log Files
    "CWE-312": ["T1005"],                          # Cleartext Storage of Sensitive Info
    "CWE-200": ["T1552", "T1005"],                 # Info Exposure → Unsecured Creds
    "CWE-209": ["T1592"],                          # Error Message Info Leakage
    "CWE-538": ["T1005"],                          # File/Directory Info Exposure
    "CWE-522": ["T1552"],                          # Insufficiently Protected Credentials
    "CWE-549": ["T1552"],                          # Missing Password Field Masking

    # Injection / Traversal / Upload
    "CWE-22":  ["T1083", "T1005"],                 # Path Traversal → Dir Discovery + Data
    "CWE-434": ["T1505.003"],                      # Unrestricted File Upload → Web Shell
    "CWE-611": ["T1190"],                          # XXE → Exploit Public App
    "CWE-918": ["T1090.002"],                      # SSRF → External Proxy
    "CWE-601": ["T1189"],                          # Open Redirect → Drive-by
    "CWE-73":  ["T1083"],                          # External Control of File Path
    "CWE-59":  ["T1574"],                          # Link Following → Hijack Exec Flow
    "CWE-36":  ["T1005"],                          # Absolute Path Traversal

    # CSRF
    "CWE-352": ["T1185"],                          # CSRF → Browser Session Hijacking

    # Code Execution / Deserialization
    "CWE-502": ["T1059"],                          # Deserialization → Arbitrary Exec
    "CWE-95":  ["T1059"],                          # Eval Injection
    "CWE-470": ["T1059"],                          # Unsafe Reflection
    "CWE-829": ["T1195.002"],                      # Local File Inclusion → Supply Chain
    "CWE-426": ["T1574"],                          # Untrusted Search Path
    "CWE-427": ["T1574"],                          # Uncontrolled Search Path

    # Denial of Service
    "CWE-400": ["T1499"],                          # Resource Consumption → DoS
    "CWE-770": ["T1499"],                          # Allocation Without Limits
    "CWE-674": ["T1499"],                          # Uncontrolled Recursion
    "CWE-834": ["T1499"],                          # Excessive Iteration
    "CWE-369": ["T1499"],                          # Divide by Zero
    "CWE-1333":["T1499"],                          # ReDoS
    "CWE-407": ["T1499"],                          # Algorithm Complexity

    # Cryptographic Failures
    "CWE-327": ["T1573"],                          # Use of Broken Crypto Algorithm
    "CWE-326": ["T1573"],                          # Inadequate Encryption Strength
    "CWE-338": ["T1573"],                          # Weak PRNG
    "CWE-347": ["T1553"],                          # Improper Verification of Sig
    "CWE-295": ["T1557"],                          # Improper Cert Validation → MiTM
    "CWE-297": ["T1557"],                          # Improper Validation of Cert Hostname
    "CWE-330": ["T1573"],                          # Use of Insufficiently Random Values
    "CWE-916": ["T1110.002"],                      # Use of Password Hash With Insufficient Computational Effort

    # Race Conditions
    "CWE-362": ["T1548"],                          # Race Condition → Priv Esc
    "CWE-367": ["T1548"],                          # TOCTOU
    "CWE-366": ["T1499"],                          # Race Condition in Switch

    # Supply Chain / Dependencies
    "CWE-494": ["T1195.002"],                      # Download Without Integrity Check
    "CWE-829": ["T1195.002"],                      # Inclusion of Functionality from Untrusted
    "CWE-1104":["T1195"],                          # Use of Unmaintained 3rd Party
    "CWE-937": ["T1195"],                          # OWASP A9 (Using Components with Known Vuln)

    # Network / Protocol
    "CWE-319": ["T1040"],                          # Cleartext Transmission → Network Sniff
    "CWE-311": ["T1040"],                          # Missing Encryption of Sensitive Data
    "CWE-924": ["T1557"],                          # Improper Enforcement of Protocol
    "CWE-941": ["T1557"],                          # Incorrectly Specified Destination in Protocol

    # Input Validation (generic)
    "CWE-20":  ["T1190"],                          # Improper Input Validation
    "CWE-1287":["T1190"],                          # Improper Validation of Specified Type
    "CWE-1284":["T1190"],                          # Improper Validation of Specified Quantity

    # Miscellaneous
    "CWE-276": ["T1222"],
    "CWE-693": ["T1562"],                          # Protection Mechanism Failure → Impair Defenses
    "CWE-749": ["T1059"],                          # Exposed Dangerous Method
    "CWE-843": ["T1203"],                          # Type Confusion
    "CWE-763": ["T1203"],                          # Release of Invalid Pointer
}


def get_techniques_for_cwe(cwe_id: str) -> list[str]:
    """Return ATT&CK technique IDs for a given CWE, or empty list if unknown."""
    return CWE_TO_ATTACK.get(cwe_id, [])


def get_all_covered_cwes() -> set[str]:
    return set(CWE_TO_ATTACK.keys())


def coverage_report(cwe_list: list[str]) -> dict:
    """Given a list of CWE IDs from the corpus, report mapping coverage."""
    covered = [c for c in cwe_list if c in CWE_TO_ATTACK]
    return {
        "total": len(cwe_list),
        "covered": len(covered),
        "coverage_pct": 100 * len(covered) / len(cwe_list) if cwe_list else 0,
        "uncovered": list(set(cwe_list) - set(covered)),
    }

# Resume and Interview Claims

## Suitable after you validate the code in your lab

**Microsoft Entra ID — Automated Identity Governance Audit** | Python, Microsoft Graph API, MSAL, PowerShell, IAM, GRC

- Built a read-only Microsoft Entra ID identity governance reporting tool using Python and Microsoft Graph, automating account inventory, security group discovery, and direct membership evidence collection.
- Developed policy-driven access-review indicators for disabled-account group assignments, sensitive-group membership attestations, missing identity attributes, and baseline variance, aligned to NIST SP 800-53 AC-2 and AC-6 review objectives.
- Engineered fault-aware Graph collection with pagination, bounded throttling retries, and fail-closed error handling; generated HTML, CSV, and JSON audit packages with SHA-256 file-integrity checksums.
- Created automated unit tests and synthetic demonstrations for a lab baseline of 8 users, 6 groups, and 5 target lab security groups, enabling repeatable portfolio validation without exposing tenant data.

## Don't claim unless verified

- Do not describe the demo as a production deployment.
- Do not claim a measured percentage of time saved without timing your process.
- Do not claim compliance certification or validated privileged-role assignments based on this project.
- Do not claim your live tenant was scanned until you actually run `python main.py --live` and verify the results.

## Interview storyline (STAR)

**Situation:** Manual Entra portal identity/group access checks needed a more repeatable evidence trail.

**Task:** Build a narrow, least-privileged, defensible auditor without making identity changes.

**Action:** Collected authorized Graph data, scoped group membership, mapped review indicators to control objectives, tested failure paths, and exported integrity-checkable results.

**Result:** Explain the tested lab numbers, demonstrate an offline run, and show how analyst attestation (rather than automatic assumption) closes findings.

# GRC Control Alignment — Analyst Workpaper

## Objective

Produce account and direct group membership evidence from an explicitly authorized Microsoft Entra ID tenant. Help a reviewer decide whether identified discrepancies need investigation.

| Control | Security intent | Evidence this project provides | What must still be validated |
|---|---|---|---|
| NIST SP 800-53 AC-2 | Account management and account reviews | User inventory, enabled status, group-to-user membership, configurable baseline differences | Account authorization, approval workflows, joiner/mover/leaver records, recertification approvals, monitoring cadence |
| NIST SP 800-53 AC-6 | Least privilege | Policy-designated sensitive group membership and cross-group review candidates | Actual role privileges, effective permissions, business need, owner authorization, privileged-role assignments |

## Important interpretation boundaries

- **Control mapping ≠ compliance determination.** An automated query alone cannot show every requirement is met.
- A security group called `sg-lab-admins` is not necessarily an Entra administrator role.
- A disabled user still listed as a group member can indicate lifecycle cleanup work. The script cannot conclude that user can authenticate.
- An access-review finding should have an assigned owner, attestation decision, supporting ticket, date, and closure notes before someone claims remediation.
- This script does not read nested membership, sign-in activity, MFA state, PIM activation, or Conditional Access.

## Recommended manual evidence review

1. Confirm the collection identity was authorized, scope was approved, and `audit.html` source is `LIVE`.
2. Independently compare user and membership totals to the Entra portal at a comparable time.
3. Review `findings.csv` with each group owner; record **Approved**, **Investigate**, or **Remediate**.
4. Save ticket IDs, authorization references, and any approved exceptions in an access-controlled evidence repository.
5. Compare `evidence_manifest.json` checksums with the outputs when transferring between evidence custodians.

## Reviewer attestation template

| Field | Entry |
|---|---|
| Review period / run ID | |
| Reviewer and role | |
| Scoping confirmation | |
| Findings reviewed | |
| Required removals / tickets | |
| Exceptions and expiry dates | |
| Final disposition | |

NIST control language: [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1).

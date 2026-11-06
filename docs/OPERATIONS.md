# Operating Guide, Security Model & Evidence Handling

## Roles and safeguards

- **Collector:** Authorized tenant user with delegated Graph read access.
- **Analyst:** Interprets findings and requests evidence/attestation from identity or application owners.
- **Change approver:** Controls any changes to memberships; **the collector never changes them**.

## Data flow

1. Device-code login obtains short-lived delegated token in memory.
2. GET users and groups with required selected fields; follow pagination.
3. GET each scoped group's **direct** members; abort on any Graph error after bounded retry.
4. Run locally maintained, version-controlled JSON policy.
5. Create local reports and a SHA-256 checksum manifest.
6. Human reviewer inspects output, documents decisions, and handles approved changes separately.

## Local and GitHub safety

- Add `.env`, report outputs, credentials, caches, and tenant snapshots to `.gitignore`.
- Only commit synthetic data and scrubbed screenshots. A copied screenshot may disclose usernames, domains, and tenant object IDs.
- Set restrictive folder permissions for real exports; do not upload live reports to public issue trackers.
- Review your organization's retention, incident response, and access management rules.
- This is **not** a secret management solution and hashes do not prove data authenticity or time of collection. Production evidence custody requires appropriate authentication, signatures or verified secure storage.

## Common problems

| Symptom | Likely cause / response |
|---|---|
| Missing `AZURE_TENANT_ID`/`AZURE_CLIENT_ID` | Set them in current PowerShell session; retry. |
| Device-code request fails | Verify single-tenant app registration and **Allow public client flows**. |
| HTTP 403 | Verify delegated permissions, tenant consent, signed-in user rights, and group visibility. |
| HTTP 429 | Graph is throttling; the collector honors Retry-After with bounded retries. Reduce scan frequency. |
| Unexpected counts | Directory changes may be eventual-consistent; compare at similar time and validate baseline. |
| Missing service principal membership | Graph v1.0 `/groups/{id}/members` has documented limitations; do not interpret the absence as proof the group has no such objects. |
| Group is named `admins` | Does not prove Entra directory role assignment; review privileges separately. |

## Expected lab reference

The submitted screenshots show 8 users, 6 groups (5 prefixed `sg-lab-`), one `sg-lab-admins` member, and three `sg-lab-it` direct members. This is a review baseline and must be updated after approved changes.

## Optional GitHub publication procedure

```powershell
git init
git add .
git status
# Ensure no live reports, tenant screenshots, or credentials appear
git commit -m "Build read-only Entra identity governance audit toolkit"
```

Then create a new **empty** GitHub repository and connect your local branch using the GitHub remote address you obtain from your own repository. Do not paste your actual tenant IDs into README examples.

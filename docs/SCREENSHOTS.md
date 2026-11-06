# Portfolio Screenshots — safe publication checklist

Add only screenshots you own and are permitted to share. Do **not** commit the original screenshots of the tenant until sensitive identifiers have been redacted and publication approved.

## Suggested GitHub visuals

1. **`00-demo-audit-report.png`** — sanitized screenshot of `docs/example-report/audit.html` (synthetic, safe to publish).
2. **`01-verified-domain-redacted.png`** — the verified Entra custom domain screen, with tenant resource references and personal info checked for exposure.
3. **`02-groups-redacted.png`** — scoped lab group inventory; blur object IDs and any account-specific details.
4. **`03-users-redacted.png`** — general user list; obscure UPNs, names, and object IDs if public publishing is not explicitly approved.
5. **`04-group-member-redacted.png`** — the `sg-lab-it` and `sg-lab-admins` direct membership screens with names/IDs redacted.

**Do not publish** login details, tenant IDs, App registration client IDs tied to sensitive configuration, tokens, screenshots with personal data, or raw live audit reports. The example report included here is generated entirely from synthetic identities.

## Suggested evidence comparison for private records

| Check | Portal screenshot | Script output | Result |
|---|---|---|---|
| Users | 8 | fill after live run | Pending |
| Groups | 6 | fill after live run | Pending |
| `sg-lab-*` groups | 5 | fill after live run | Pending |
| `sg-lab-it` direct members | 3 | fill after live run | Pending |
| `sg-lab-admins` direct members | 1 | fill after live run | Pending |

Do not mark this checklist as passed just because the **synthetic demo** matches the numbers. Only a separately authorized live run and comparison can validate it.

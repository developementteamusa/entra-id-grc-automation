"""Transparent, policy-driven review rules. Findings are indicators, not violations."""
import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timezone

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def evaluate(snapshot, policy):
    prefix = policy.get("group_prefix", "sg-lab-")
    groups = [g for g in snapshot["groups"] if (g.get("displayName") or "").casefold().startswith(prefix.casefold())]
    users = snapshot["users"]
    user_by_id = {u["id"]: u for u in users}
    memberships = snapshot["memberships"]
    sensitive = {name.casefold() for name in policy.get("sensitive_group_names", [])}
    findings = []
    group_to_users = {}
    user_to_groups = defaultdict(list)
    non_user_members = 0

    def add(rule, severity, subject, evidence, reason, action, controls):
        key = f"{rule}|{subject}"
        finding_id = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12].upper()
        findings.append({
            "id": f"GRC-{finding_id}",
            "rule": rule,
            "severity": severity,
            "subject": subject,
            "evidence": evidence,
            "why_review": reason,
            "recommended_action": action,
            "control_references": controls,
            "status": "Requires human review",
        })

    for group in groups:
        group_id = group["id"]
        name = group.get("displayName") or "<unnamed>"
        if group_id not in memberships:
            raise ValueError(f"Missing membership collection for group {group_id}; refusing partial report")
        direct_members = memberships[group_id]
        group_to_users[group_id] = []

        if not direct_members:
            add("EMPTY_GROUP", "INFO", name, f"Group {group_id} has no direct members", "Group might be intentionally empty or obsolete.", "Confirm group purpose and ownership before any cleanup.", ["AC-2"])

        for member in direct_members:
            obj_type = member.get("@odata.type")
            user_id = member.get("id")
            if obj_type != "#microsoft.graph.user":
                non_user_members += 1
                add("NON_USER_MEMBER", "INFO", name, f"Member {user_id or '(unknown ID)'}: {obj_type or 'unknown type'}", "This report evaluates only direct user memberships; other object types require separate review.", "Review nested groups, devices, service principals, or unknown member types separately.", ["AC-2", "AC-6"])
                continue
            user = user_by_id.get(user_id)
            if not user:
                add("UNRESOLVED_USER", "MEDIUM", name, f"User ID {user_id} was not present in the retrieved inventory", "Incomplete visibility can prevent reliable access reviews.", "Verify Graph permissions, object visibility, and recent directory changes.", ["AC-2"])
                continue
            group_to_users[group_id].append(user)
            user_to_groups[user_id].append(name)
            user_name = user.get("userPrincipalName") or user.get("displayName") or user_id
            if user.get("accountEnabled") is False:
                add("DISABLED_ACCOUNT_IN_GROUP", "MEDIUM", user_name, f"Disabled user remains a direct member of {name}", "Stale group membership can complicate account lifecycle governance; this does not imply the account can sign in.", "Confirm retention needs and remove unnecessary memberships through approved change management.", ["AC-2"])
            if name.casefold() in sensitive:
                add("SENSITIVE_GROUP_MEMBER_REVIEW", "MEDIUM", user_name, f"Direct member of policy-designated sensitive group {name}", "Access to this designated group requires documented owner approval; a group name alone does not establish an Entra directory role.", "Confirm business justification and capture group-owner attestation.", ["AC-6"])

    for user in users:
        for field in policy.get("required_user_attributes", []):
            if not user.get(field):
                user_name = user.get("userPrincipalName") or user.get("displayName") or user["id"]
                add("MISSING_USER_ATTRIBUTE", "LOW", user_name, f"Required field '{field}' is blank", "Missing identity metadata can reduce accuracy of access recertification.", "Confirm attribute ownership and update after validation.", ["AC-2"])

    for user_id, member_groups in user_to_groups.items():
        sensitive_matches = [n for n in member_groups if n.casefold() in sensitive]
        if sensitive_matches and len(member_groups) > 1:
            user = user_by_id[user_id]
            user_name = user.get("userPrincipalName") or user["id"]
            add("CROSS_GROUP_REVIEW", "LOW", user_name, "Direct memberships: " + ", ".join(sorted(member_groups)), "Overlapping access may be justified; review for least privilege rather than treating it as a violation.", "Ask the application/group owner to validate both memberships.", ["AC-6"])

    baseline = policy.get("baseline", {})
    totals = {"total_users": len(users), "total_groups": len(snapshot["groups"]), "scoped_groups": len(groups)}
    for key, observed in totals.items():
        expected = baseline.get(key)
        if expected is not None and observed != expected:
            add("BASELINE_COUNT_VARIANCE", "LOW", key, f"Expected {expected}; observed {observed}", "A snapshot difference requires investigation but is not necessarily unauthorized change.", "Verify approved adds/removes since baseline and update the baseline if authorized.", ["AC-2"])
    named_group_counts = {g["displayName"].casefold(): len(memberships[g["id"]]) for g in groups}
    for name, expected in baseline.get("direct_member_counts", {}).items():
        observed = named_group_counts.get(name.casefold())
        if observed is None or observed != expected:
            add("BASELINE_MEMBER_VARIANCE", "LOW", name, f"Expected {expected} direct member(s); observed {observed if observed is not None else 'group not found'}", "Group membership differs from the review baseline.", "Compare changes against approved requests and update baseline after sign-off.", ["AC-2", "AC-6"])

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["rule"], f["subject"]))
    counts = dict(Counter(f["severity"] for f in findings))
    return {
        "project": "Microsoft Entra ID Automated Identity Governance Audit",
        "source": snapshot["source"],
        "tenant_id": snapshot.get("tenant_id", ""),
        "collected_at_utc": snapshot["collected_at_utc"],
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "All tenant users; all groups counted; direct membership of prefix-matched groups only",
        "group_prefix": prefix,
        "metrics": {
            **totals,
            "scoped_direct_membership_edges": sum(len(memberships[g["id"]]) for g in groups),
            "non_user_members": non_user_members,
            "findings_total": len(findings),
            "findings_by_severity": {name: counts.get(name, 0) for name in SEVERITY_ORDER},
        },
        "users": users,
        "groups": groups,
        "memberships": memberships,
        "findings": findings,
        "disclaimer": "Review indicators only. Not a compliance certification, sign-in/MFA assessment, or proof of privileged directory roles. Microsoft Graph v1.0 group-members endpoint has known service-principal visibility limitations.",
    }

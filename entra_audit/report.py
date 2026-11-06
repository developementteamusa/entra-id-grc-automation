"""Export CSV, JSON, and self-contained HTML, with a SHA-256 evidence manifest."""
import csv
import hashlib
import json
from collections import Counter
from html import escape
from pathlib import Path


def csv_safe(value):
    """Neutralize spreadsheet formula injection in user-controlled text exports."""
    if value is None:
        return ""
    result = str(value)
    if result.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + result
    return result


def write_csv(path, headers, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        for row in rows:
            writer.writerow([csv_safe(v) for v in row])


def html_report(report):
    h = lambda x: escape(str(x if x is not None else ""), quote=True)
    counts = report["metrics"]["findings_by_severity"]
    cards = "".join(f'<div class="metric"><span>{h(label)}</span><strong>{value}</strong></div>' for label, value in [
        ("Users", report["metrics"]["total_users"]),
        ("Total groups", report["metrics"]["total_groups"]),
        ("Scoped groups", report["metrics"]["scoped_groups"]),
        ("Review findings", report["metrics"]["findings_total"]),
    ])
    severity_cards = "".join(
        f'<div class="severity {h(level.lower())}"><b>{h(level)}</b><strong>{counts.get(level, 0)}</strong></div>'
        for level in ("HIGH", "MEDIUM", "LOW", "INFO")
    )
    rows = []
    for f in report["findings"]:
        rows.append("<tr>" + "".join([
            f'<td><span class="pill {h(f["severity"].lower())}">{h(f["severity"])}</span></td>',
            f'<td><b>{h(f["rule"].replace("_", " "))}</b><small>{h(f["id"])}</small></td>',
            f'<td>{h(f["subject"])}</td>',
            f'<td>{h(f["evidence"])}</td>',
            f'<td>{h(f["recommended_action"])}</td>',
            f'<td>{h(", ".join(f["control_references"]))}</td>',
        ]) + "</tr>")
    table_rows = "\n".join(rows) if rows else '<tr><td colspan="6">No review findings from configured checks.</td></tr>'
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Identity Governance Audit — {h(report["source"])}</title>
<style>
:root{{--navy:#12243a;--teal:#0f807b;--muted:#637288;--line:#e5eaf0;--bg:#f4f7fb}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);font:14px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;color:var(--navy)}}
.wrap{{max-width:1250px;margin:auto;padding:28px 25px 70px}}header{{background:var(--navy);color:white;padding:40px 0}}
header .wrap{{padding-top:0;padding-bottom:0}}.eyebrow{{text-transform:uppercase;font-weight:750;letter-spacing:.14em;color:#82e1d2;font-size:12px}}
h1{{font-size:clamp(25px,3.4vw,39px);line-height:1.12;margin:11px 0}}h2{{font-size:20px;margin:28px 0 12px}}p{{margin:8px 0}}
.meta{{color:#bed0e0;font-size:13px}}.metrics{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:22px}}
.metric,.panel{{background:#fff;border:1px solid var(--line);border-radius:12px;padding:20px}}
.metric span{{display:block;color:var(--muted);font-size:13px}}.metric strong{{font-size:30px}}
.severities{{display:flex;gap:10px;flex-wrap:wrap}}.severity{{flex:1;min-width:120px;border-radius:10px;padding:14px 17px;background:white;border:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}}
.severity strong{{font-size:21px}}.pill{{display:inline-block;border-radius:100px;padding:4px 9px;font-weight:750;font-size:11px}}
.high{{color:#9e2631;background:#fce7e8}}.medium{{color:#865000;background:#fff2db}}.low{{color:#22599b;background:#e7f1ff}}.info{{color:#526274;background:#e8edf1}}
.table-wrap{{overflow-x:auto;background:white;border:1px solid var(--line);border-radius:12px}}
table{{width:100%;border-collapse:collapse;min-width:1020px;text-align:left}}th{{background:#edf3f8;color:#2a4158;font-size:12px;text-transform:uppercase;letter-spacing:.04em}}th,td{{border-bottom:1px solid var(--line);padding:12px 14px;vertical-align:top}}td{{max-width:370px;overflow-wrap:anywhere}}
tr:last-child td{{border-bottom:0}}small{{display:block;font-size:11px;color:var(--muted);margin-top:3px}}.note{{border-left:3px solid var(--teal);padding:6px 14px;color:#455b72;background:#f1fbfa}}
footer{{margin-top:30px;color:var(--muted);font-size:12px}}@media(max-width:700px){{.metrics{{grid-template-columns:repeat(2,1fr)}}.wrap{{padding-left:14px;padding-right:14px}}}}
@media print{{body{{background:#fff}}header{{print-color-adjust:exact;-webkit-print-color-adjust:exact}}.table-wrap{{overflow:visible}}table{{min-width:0;font-size:10px}}.wrap{{max-width:none}}}}
</style></head><body><header><div class="wrap"><div class="eyebrow">Identity Security • GRC Evidence</div>
<h1>Automated Identity Governance Audit</h1><p>Microsoft Entra ID · Read-only identity and group access review</p>
<p class="meta">Source: {h(report["source"].upper())} &nbsp; | &nbsp; Collected (UTC): {h(report["collected_at_utc"])} &nbsp; | &nbsp; Tenant: {h(report["tenant_id"])}</p></div></header>
<main class="wrap"><div class="metrics">{cards}</div><h2>Review severity breakdown</h2><div class="severities">{severity_cards}</div>
<h2>Audit findings and recommended actions</h2><div class="table-wrap"><table><thead><tr><th>Severity</th><th>Check / ID</th><th>Subject</th><th>Evidence</th><th>Review action</th><th>NIST mapping</th></tr></thead><tbody>{table_rows}</tbody></table></div>
<h2>Methodology and limitations</h2><section class="panel"><p><b>Coverage:</b> {h(report["scope"])}. Group prefix: <code>{h(report["group_prefix"])}</code>.</p>
<p><b>What this report can support:</b> Account lifecycle hygiene checks (AC-2) and owner review of selected group access (AC-6). Severity is a local prioritization heuristic, not a formal risk assessment.</p>
<p><b>What it does not establish:</b> Whether access was unauthorized, MFA state, interactive sign-in recency, effective permissions, transitive/nested group membership, or Entra administrative role assignments.</p>
<p class="note">{h(report["disclaimer"])}</p><p><b>Evidence handling:</b> Contains identity data in live mode. Store privately, restrict access, review retention requirements, and do not commit live reports to public GitHub.</p></section>
<footer>Generated (UTC): {h(report["generated_at_utc"])} · Evidence-only output · Analyst validation required before remediation</footer></main></body></html>'''


def export_report(report, output_dir):
    dest = Path(output_dir)
    dest.mkdir(parents=True, exist_ok=True)
    inventory = sorted(report["users"], key=lambda u: (u.get("displayName") or "").casefold())
    write_csv(dest / "users.csv", ["id", "display_name", "user_principal_name", "department", "job_title", "account_enabled"], [
        [u.get("id"), u.get("displayName"), u.get("userPrincipalName"), u.get("department"), u.get("jobTitle"), u.get("accountEnabled")]
        for u in inventory
    ])
    write_csv(dest / "groups.csv", ["group_id", "group_name", "security_enabled", "direct_members"], [
        [g["id"], g.get("displayName"), g.get("securityEnabled"), len(report["memberships"][g["id"]])]
        for g in report["groups"]
    ])
    user_by_id = {u["id"]: u for u in inventory}
    member_rows = []
    for group in report["groups"]:
        for member in report["memberships"][group["id"]]:
            user = user_by_id.get(member.get("id"), {})
            member_rows.append([group["displayName"], group["id"], member.get("id"), member.get("@odata.type"), user.get("displayName"), user.get("userPrincipalName")])
    write_csv(dest / "memberships.csv", ["group_name", "group_id", "member_id", "member_type", "display_name", "upn"], member_rows)
    write_csv(dest / "findings.csv", ["id", "severity", "rule", "subject", "evidence", "why_review", "recommended_action", "control_references", "status"], [
        [f["id"], f["severity"], f["rule"], f["subject"], f["evidence"], f["why_review"], f["recommended_action"], ", ".join(f["control_references"]), f["status"]]
        for f in report["findings"]
    ])
    (dest / "audit.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (dest / "audit.html").write_text(html_report(report), encoding="utf-8")
    files = ["users.csv", "groups.csv", "memberships.csv", "findings.csv", "audit.json", "audit.html"]
    manifest = {
        "generated_at_utc": report["generated_at_utc"],
        "source": report["source"],
        "sha256": {filename: hashlib.sha256((dest / filename).read_bytes()).hexdigest() for filename in files},
        "note": "SHA-256 detects later file alteration but does not prove collector identity or trusted capture time.",
    }
    (dest / "evidence_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return dest

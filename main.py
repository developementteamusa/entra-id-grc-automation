"""CLI: python main.py --demo | --live [--output OUTPUT_DIR]."""
import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

from entra_audit.audit import evaluate
from entra_audit.report import export_report

ROOT = Path(__file__).resolve().parent


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only Entra ID GRC audit reporting")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true", help="Run on fabricated data without credentials")
    mode.add_argument("--live", action="store_true", help="Authenticate to your own Entra tenant")
    parser.add_argument("--policy", type=Path, default=ROOT / "config" / "policy.json")
    parser.add_argument("--output", type=Path, help="Report folder (default reports/demo or reports/live)")
    args = parser.parse_args(argv)

    try:
        policy = json.loads(args.policy.read_text(encoding="utf-8"))
        if args.demo:
            snapshot = json.loads((ROOT / "samples" / "demo_snapshot.json").read_text(encoding="utf-8"))
        else:
            from entra_audit.auth import get_access_token
            from entra_audit.graph import GraphClient, collect_snapshot
            token, tenant_id = get_access_token()
            try:
                snapshot = collect_snapshot(GraphClient(token), tenant_id, policy.get("group_prefix", "sg-lab-"))
            finally:
                del token
        report = evaluate(snapshot, policy)
        target = args.output or (
            ROOT / "reports" / "demo" if args.demo else
            ROOT / "reports" / "live" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        )
        folder = export_report(report, target)
        metrics = report["metrics"]
        print(f"\nMode: {report['source'].upper()}")
        print(f"Users: {metrics['total_users']} | Groups: {metrics['total_groups']} | Scoped groups: {metrics['scoped_groups']}")
        print(f"Review findings: {metrics['findings_total']} | Breakdown: {metrics['findings_by_severity']}")
        print(f"Reports: {folder.resolve()}")
        print("Open audit.html in a browser. All live exports contain sensitive identity data.")
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print(f"Audit aborted; no complete report was generated: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        # Requests exceptions and MSAL/API errors must fail the run rather than report success.
        print(f"Audit collection failed (no complete report): {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

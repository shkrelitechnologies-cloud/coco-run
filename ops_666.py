#!/usr/bin/env python3
"""COCO 666 operational audit (read-only, local).

Reports from local aggregate ledgers in this repository when available. The
authoritative per-URL evidence is the private COCO repository/database
(silk.db/submissions.csv/daily_counts.csv); public/local aggregates do not
provide independently verifiable per-publication evidence in this checkout.
"""
from __future__ import annotations

import csv
import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
TZ = timezone(timedelta(hours=5, minutes=30))
TARGET = 666
REPO = "shkrelitechnologies-cloud/coco-run"
WORKFLOW = "run.yml"


def now_ist() -> datetime:
    return datetime.now(timezone.utc).astimezone(TZ)


def read_csv(path: Path) -> list[dict[str, str]] | None:
    if not path.exists():
        return None
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def run_cmd(args: list[str], timeout: int = 20) -> tuple[str | None, str | None]:
    try:
        out = subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.strip(), None
    except Exception as e:
        msg = getattr(e, "output", None) or str(e)
        if isinstance(msg, bytes):
            msg = msg.decode("utf-8", "replace")
        return None, str(msg).strip() or "command failed"


def gh_json(args: list[str]) -> tuple[Any, str | None]:
    if not shutil.which("gh"):
        return None, "gh unavailable"
    out, err = run_cmd(["gh", *args], timeout=25)
    if err or out is None:
        return None, err or "no output"
    try:
        return json.loads(out), None
    except Exception as e:
        return None, f"invalid json: {e}"


def safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(float(value))
    except Exception:
        return None


def main() -> int:
    now = now_ist()
    today = now.date().isoformat()
    midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    remaining_seconds = max(0.0, (midnight - now).total_seconds())

    daily = read_csv(ROOT / "daily_counts.csv")
    summary = read_csv(ROOT / "summary.csv")
    today_row = next((r for r in daily if r.get("ist_date") == today), None) if daily else None
    latest = summary[-1] if summary else None

    report: dict[str, Any] = {
        "project": "COCO",
        "repository": REPO,
        "authoritative_source": "private shkrelitechnologies-cloud/coco (silk.db/submissions.csv/daily_counts.csv)",
        "checked_at_ist": now.isoformat(timespec="seconds"),
        "today_ist": today,
        "target": TARGET,
        "local_aggregate_sources": ["daily_counts.csv", "summary.csv"],
        "notes": [
            "Read-only local audit; no writes performed.",
            "Per-URL public verification evidence is authoritative only in the private COCO ledger/database.",
            "Successful or active Actions runs are not publications.",
        ],
    }

    if today_row is None:
        report.update({
            "verified_unique_publications_aggregate": "unverifiable",
            "remaining_to_target": "unverifiable",
            "required_verified_per_hour": "unverifiable",
            "status_breakdown": "unverifiable",
            "note": "No local aggregate row for today in daily_counts.csv; do not infer zero without authoritative evidence.",
        })
    else:
        verified = safe_int(today_row.get("verified_publications"))
        if verified is None:
            report.update({
                "verified_unique_publications_aggregate": "unverifiable",
                "remaining_to_target": "unverifiable",
                "required_verified_per_hour": "unverifiable",
            })
        else:
            remaining = max(0, TARGET - verified)
            rate = (remaining / (remaining_seconds / 3600.0)) if remaining_seconds > 0 else None
            report.update({
                "verified_unique_publications_aggregate": verified,
                "target_progress": f"{verified}/{TARGET}",
                "remaining_to_target": remaining,
                "remaining_time_ist": str(midnight - now).split(".")[0],
                "required_verified_per_hour": round(rate, 3) if rate is not None else None,
                "status_breakdown_aggregate": {
                    "attempted": safe_int(today_row.get("attempted")) or 0,
                    "pending_moderation": safe_int(today_row.get("pending_moderation")) or 0,
                    "failed": safe_int(today_row.get("failed")) or 0,
                    "uncertain": safe_int(today_row.get("uncertain")) or 0,
                    "skipped": safe_int(today_row.get("skipped")) or 0,
                    "blocked": 0,
                    "duplicates": "not_explicit_in_aggregate",
                    "existing_listings_verified": "not_explicit_in_aggregate",
                },
                "evidence_note": "Aggregate counts from local daily_counts.csv; per-URL evidence is in private submissions.csv/database.",
            })

    if latest:
        report["latest_summary_snapshot"] = {k: latest.get(k) for k in [
            "ts", "sent_confirmed", "attempted", "failed", "uncertain", "skipped",
            "queue_pending", "awaiting_moderation", "daily_target", "remaining_to_target",
            "unique_verified_domains_today", "lifetime_verified_publications",
        ] if k in latest}

    runs, runs_err = gh_json([
        "run", "list", "-R", REPO, "--workflow", WORKFLOW, "--limit", "5",
        "--json", "databaseId,status,conclusion,event,createdAt,updatedAt,headBranch,url,displayTitle",
    ])
    if runs is not None:
        report["recent_runs"] = runs
        active = [r for r in runs if r.get("status") in {"queued", "in_progress", "requested", "waiting", "pending"}]
        latest_run = runs[0] if runs else None
        report["workflow_state"] = {
            "workflow": WORKFLOW,
            "active_runs": len(active),
            "latest_run": latest_run,
        }
        if active:
            report["next_safe_action_hint"] = "Worker run(s) active; avoid duplicate dispatch and monitor for stale/cancel conditions per watchdog policy."
        elif latest_run and latest_run.get("conclusion") not in (None, "success"):
            report["next_safe_action_hint"] = "Latest run not successful; inspect logs/blockers. Recovery should follow watchdog cooldown/policy (no rapid retry loop)."
        else:
            report["next_safe_action_hint"] = "No active run detected from recent list; if overdue per policy, a bounded recovery dispatch via workflow_dispatch/watchdog may be appropriate after checking blockers."
    else:
        text, text_err = (None, runs_err)
        if not shutil.which("gh"):
            report["recent_runs"] = runs_err
        else:
            # fallback to plain text listing
            out, err = run_cmd(["gh", "run", "list", "-R", REPO, "--limit", "5"])
            report["recent_runs"] = out.splitlines() if out is not None else (err or runs_err)
        report["workflow_state"] = "unavailable"
        report["next_safe_action_hint"] = "Could not query workflow state; verify GitHub Actions runs manually before dispatching recovery."

    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

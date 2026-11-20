# COCO Operations Record

COCO's unattended worker and watchdog are owned by this repository.

## Target and counting
- Daily target: 666 verified public publications.
- Clock: Asia/Kolkata (IST); daily counters reset at 00:00 IST and history is retained.
- Count only a unique public publication URL that can be independently opened/read back.
- Attempts, form clicks, HTTP 2xx responses, drafts, queues, moderation-pending items, duplicate URLs, and uncertain results do not count.

## Recovery
- `.github/workflows/coco-watchdog.yml` checks every 15 minutes.
- The watchdog re-enables the worker workflow if disabled, avoids duplicate active runs, cancels stale active/queued runs, and dispatches one recovery run when the worker is overdue.
- A recent failure is retried on the next eligible watchdog cycle; it must not create a rapid retry loop.
- A blocked website or individual candidate must be logged and skipped so later eligible candidates can be processed. Site rules, CAPTCHA, authentication, moderation, rate limits, and permission gates must never be bypassed.
- A systemic blocker (missing secret, GitHub permission failure, unavailable API, or invalid campaign source) is recorded as a blocker and must not be mislabeled healthy.

## Source of truth
The private COCO database and its `daily_counts.csv` / submission records remain the authoritative publication ledger. This repository's watchdog artifact `coco-watchdog-<run>` contains the latest health check. The public repository must not expose private campaign data, credentials, or donor details.

## Required health report
Every watchdog check records timestamp, worker state, active/stale run IDs, action taken, error/blocker details, and the next recovery condition. Daily reporting must show verified publications / 666, target gap, and separate pending/attempted/failed counts.

## Operator shorthand: `666`
When the operator requests `666`, perform a four-project operational audit (COCO, HUNTER, MAYA, SHIV): inspect each repository's latest workflow runs and schedule, reconcile that project's authoritative IST daily ledger, report verified unique publications / 666 and remaining target, separate attempts/pending/failed/blocked/skipped/duplicates, calculate required throughput to midnight IST, and identify the next safe action. A successful Actions run is not a publication. If the private database or ledger is unavailable, report the count as **unverifiable**, never as zero. COCO's authoritative source is the private database and its `daily_counts.csv`; do not infer a current count from a stale summary.

**Local audit command:** `python ops_666.py` (read-only). Reports from local aggregate `daily_counts.csv`/`summary.csv` when present, labels per-URL verification as private-authoritative, includes recent `run.yml` workflow state when `gh` is available, and emits a factual next-safe-action hint. It does not modify ledgers, databases, or workflows.

## Operational reference
- **Purpose:** Automated, permission/rules-respecting publication discovery and submission with independent verification counting.
- **Entry points/workflows:** `.github/workflows/run.yml` (main scheduled worker, `workflow_dispatch`), `.github/workflows/coco-watchdog.yml` and `.github/workflows/watchdog.yml` (health/recovery), `.github/workflows/fixer.yml`. See workflow files for schedules/timeouts/concurrency.
- **Daily target/reset:** 666 verified unique public publications/day; IST (`Asia/Kolkata`) 00:00 reset; historical records retained.
- **Configuration/credentials:** `config.yaml` in repo; secrets include `COCO_PRIVATE_SEED` (private DB access) and any publishing credentials as configured. Never expose secrets.
- **Ledgers/queues:** Public aggregates `daily_counts.csv`, `summary.csv`; authoritative private `submissions.csv`, `daily_counts.csv`, and SQLite DB in private COCO repo.
- **Verification:** Only unique public URLs with independent verifiable evidence count. Attempts, HTTP success, drafts/queues, moderation-pending, duplicates, uncertain results do not count.
- **Error handling/recovery:** Watchdogs re-enable/dispatch/cancel stale runs as configured; blocked sites/candidates skipped and logged; systemic blockers recorded, not hidden.
- **Resource limits:** Bounded job windows/timeouts, checkpointing/persistence before exit, concurrency lock, deduplication and rate-limit/backoff behavior in runtime.
- **Manual intervention:** Required for secret/permission failures, private DB corruption/restore issues, platform restrictions, or destinations requiring human/CAPTCHA/login/payment approval. Resume by fixing blocker and triggering `run.yml` via `workflow_dispatch` when safe.

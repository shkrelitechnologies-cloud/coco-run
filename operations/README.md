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

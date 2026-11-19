# COCO Publication and Operations Tracking

COCO keeps its operational records in the COCO project repositories; it does not depend on MIND for its source-of-truth counts.

## Repository-local files

- `daily_counts.csv` (this runner repository): public aggregate IST daily totals. It is refreshed by the workflow.
- `summary.csv` (this runner repository): latest aggregate snapshot. The `websites` field is the number of website records in the database, **not** the number of published websites.
- [`submissions.csv`](https://github.com/shkrelitechnologies-cloud/coco/blob/master/submissions.csv) (private COCO repository): detailed per-site event ledger, including timestamp, IST date, status, domain, URL, verified flag, moderation state and evidence/confirmation text.
- [`daily_counts.csv`](https://github.com/shkrelitechnologies-cloud/coco/blob/master/daily_counts.csv) (private COCO repository): private mirror of the IST daily summary.
- Private `silk.db`: underlying durable record store. The workflow periodically checkpoints it and the detailed CSV to the private repository.

## Daily target and reset

- Target: 666 verified publications per IST calendar day.
- Timezone: `Asia/Kolkata`.
- The ledger assigns each submission event to its IST calendar date. A new daily row is created at 00:00 IST and starts at zero; historical rows are retained.
- `daily_counts.csv` includes the target, remaining gap, unique verified domains, and lifetime verified-publication count.

## Counting rules

- Only rows with `verified=true`, a confirmed/success/accepted status, a non-empty confirmation field, and no pending-moderation cue count as verified publications.
- Attempted, failed, rejected, uncertain, skipped, queued, and pending-moderation records remain separately visible and do not count toward 666.
- The per-site ledger preserves the URL and domain so the number of unique published websites can be calculated separately from the number of publication URLs.
- Repeated records for the same URL on the same IST day are counted once in that day's verified total.
- A public summary is an aggregate; use the private `submissions.csv` for website-by-website evidence.

## Persistence and limitations

The workflow refreshes public aggregate files during its run and checkpoints the detailed per-site ledger/database to the private COCO repository periodically and at shutdown. If a run is interrupted between checkpoints, inspect the latest private commit and Actions artifact before assuming every recent event was persisted. Do not treat an Actions run as proof of publication.

COCO must continue respecting its current explicit permission, robots, CAPTCHA, login-wall, rate-limit and site-rule checks. The target is a goal, not a guarantee.

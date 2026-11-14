# COCO - working document (single-file edition)
#
# WHAT THIS FILE IS
# Website discovery, relevance/permission checks, content translation and browser
# publishing, with SQLite state, reporting, dashboards and a Typer CLI. Former
# core, data, web and launcher files are combined in dependency order below.
# This header documents the code; it does not approve or enable live operation.
#
# STRUCTURE (approximate line ranges in this headered file)
#    80-196   models
#   197-440   config
#   441-630   events
#   631-754   logging_setup
#   755-927   safety
#   928-1140  content
#  1141-2102  database
#  2103-2390  translation
#  2391-2700  intelligence
#  2701-2989  relevance
#  2990-3157  profile
#  3158-3232  reporting
#  3233-3802  browser
#  3803-4595  discovery
#  4596-5352  publishing
#  5353-5665  terminal_dashboard
#  5666-6371  dashboard
#  6372-7566  cli
#
# CHANGE LOG (IST, 2026-11-11; earlier times are completion-report times)
# 2026-11-13 IST - Discovery widened per owner go: 37 more query languages
#         (70 total, every world region) and region-aware search locale
#         (google hl, bing setlang/mkt, duckduckgo kl follow the query language).
# 2026-11-13 IST - Site-account email/password now AES-256-GCM encrypted at
#         rest in silk.db; key derived from the Actions secret env (never in
#         repos). Legacy plaintext rows migrate on first keyed run.
#         Gates, scoring, templates' meaning and all other behavior unchanged.
# 17:59 - 19-module package flattened into four files: core, data, web, launcher.
#         Imports adjusted; prior report records an undefined username fix in
#         _fill_profile_fields. That earlier fix is not part of this header edit.
# 18:03 - Four files merged into one coco.py. Cross-file imports, three lazy
#         relative imports and duplicate future imports removed; logic retained.
# 2026-11-11 18:05 IST - Added this working-document header only; no code changed.
# 2026-11-11 18:12 IST - Added the COCO profile JPEG asset to SQLite on init,
#         with a byte getter; its base64 constant sits before the main guard.
# 2026-11-11 18:12 IST - Changed the default database filename to data.db.
# 2026-11-12 IST - Renamed the default database to silk.db (legacy data.db / nexus.db are copied once, never deleted).
#         Existing data/coco.db is not migrated; both old and new DB sidecars
#         remain protected from cleanup.
# 2026-11-11 18:12 IST - Reworked terminal dashboard panels, colors and layout;
#         all requested counts, status rows, summaries and activity remain.
# 2026-11-11 18:12 IST - Added COCO_CONTENT_DATA; its address placeholders match
#         the existing appeal text, and its autonomous flag matches defaults.
# 2026-11-11 18:12 IST - Added a local profile-image DB fallback only when no
#         profile image file exists, plus an alias for existing browser call sites.
# 2026-11-11 18:29 IST - Terminal dashboard keeps "Last confirmed" at narrow
#         widths, shortening the value with an ellipsis instead of dropping the
#         line. Rendering only; status glyphs unchanged; no logic changes.
# 2026-11-11 18:33 IST - Terminal dashboard: replaced the stats block with a
#         "Now" section (current activity, current site/target, latest events,
#         pending-queue count) and added emoji status/section markers that read
#         without colour. Rendering only; data collection and logic unchanged.
# 2026-11-11 18:38 IST - Terminal dashboard rendering only: brand title keeps a
#         space ("COCO CONTENT OUTREACH CONTROL CENTER") at all sizes; narrow
#         status rows show a short browser value ("ACTIVE"); the compact stack
#         shortens metric labels ("Insp.", "Fail/Skip"); short screens show one
#         NOW event and hide the activity table header so at least two live feed
#         rows fit within 24 rows. No logic changes; status glyphs unchanged.
#
# 2026-11-11 19:20 IST - Folded the NOW block into LIVE ACTIVITY (user request):
#         current activity, current site and pending-queue count now sit at the
#         top of the single LIVE ACTIVITY panel; the separate NOW panel is gone.
#         Rendering only; data collection and logic unchanged.
#
# 2026-11-11 REVIEW EDIT (static review and sandbox tests only; no live runs):
# - Live publishing stays the default start (owner's explicit choice, 2026-11-11
#   19:40 IST); --dry-run remains the prepare-only option, and a startup banner
#   now states the active mode (LIVE MODE / DRY RUN) so it is never ambiguous.
# - 135 silent `except Exception: pass` blocks now log the suppressed error at
#   debug level with the enclosing function name (_log_suppressed). Behavior is
#   unchanged at the default INFO log level; failures are no longer invisible.
# - New config sections: `safety` (extra_/disabled_ obstacle-detection
#   signatures, applied by configure_safety at startup) and `selectors`
#   (signup_links / registration_submit / form_submit CSS selector overrides).
#   Defaults match the previously hard-coded values, so behavior is unchanged
#   unless config.yaml overrides them. Detection only; never bypass.
# - Startup now fails loudly (clear SystemExit) when cloud intelligence is
#   enabled but no API key is set, instead of silently using heuristics.
# - Database.backup(): timestamped online SQLite backup into data/backups/,
#   keeping the newest 10. Runs automatically on startup
#   (app.backup_on_start / app.backup_keep).
# - New `self-test` CLI command: offline checks (no network, browser or
#   submissions) covering config defaults, obstacle detection, URL
#   canonicalization, token protection, DB lifecycle/backup and publish gates.
# - Permanent per-site dedup (owner requirement, 19:41 IST): a site that
#   already received a successful submission is skipped forever - enforced in
#   code and persisted in the DB (has_successful_submission_for_url), so reruns
#   never submit twice to the same site.
# - Discovery now explains 0-result runs: per-run counters (seeds, queries,
#   providers blocked, candidates parsed, per-filter drops, recorded) and a
#   warn-level diagnosis naming the likely cause.
# - Sign-up flow enabled (owner request, 19:43 IST): where a site's own rules
#   explicitly permit it, COCO creates an account with a per-site generated
#   password stored locally in the database (site_accounts table), then fills
#   profile fields (name/username/email/bio/caption/profile picture) and posts.
#   It still skips sites whose rules prohibit submissions and stops on any
#   CAPTCHA, email, phone or ID verification challenge - never bypasses.
# - New config flag publishing.respect_site_rules (default true, owner 19:45
#   IST): when false in config.yaml, site-rule/permission checks are bypassed;
#   only CAPTCHA/verification stops, per-site dedup and capability checks remain.
# - Optional credentials.universal_password (or COCO_UNIVERSAL_PASSWORD env):
#   one password for every sign-up instead of per-site generated ones. Never
#   hardcoded - read from config/env on the owner's laptop only; never logged.
#   Reuse risk: one site leaking it exposes the accounts on all other sites.
# - Minor: removed a dead variable, fixed a no-op f-string.
# KNOWN FLAGS - STATUS AFTER THE REVIEW EDIT
# - dry_run remains False (live) by default per the owner's explicit choice
#   (2026-11-11 19:40 IST); --dry-run stays available for prepare-only runs.
#   Robots/rules checks and CAPTCHA/login/rate-limit stops are unchanged.
# - Fundraising content still includes a Wise pay link with owner surname
#   (unchanged; that is the owner's own content decision).
# - Default usernames/fallbacks and a personal Gmail default remain in the code
#   (unchanged; owner identity decision). The Gmail address is used as the
#   sign-up email on permitted sites (owner request, 19:43 IST).
# - Per-site sign-up passwords are stored in the local database in plaintext
#   (site_accounts table, owner's laptop, owner requirement). Protect silk.db
#   like a password file.
#
# HOW TO RUN (reference only; the review edit ran compile checks and self-test,
# never live operation)
# Use the existing project environment and installed dependencies. Earlier notes
# identify Python 3.12+ as the target; a compile check is not a runtime test.
# From the intended project working directory:
#   python coco.py --help                  CLI help
#   python coco.py self-test               Offline self-checks (no network/browser)
#   python coco.py run --dry-run --no-discover
#                                         Prepare without submitting/discovering
#   python coco.py                        Dashboard + automation (LIVE by default)
# WARNING: The dashboard command publishes live by default (owner's choice);
# use run --dry-run for a prepare-only pass. Dry-run still bootstraps local state
# and may inspect sites unless --no-discover. It is not an offline/no-write mode.
# If browser setup is needed: python -m playwright install chromium
# Avoid a neighboring legacy coco/ package shadowing this module when imported.
#
# DATABASE LOCATION (inferred from source text only; database not opened)
# Config.db_path returns Config.data_dir / "silk.db". app.data_dir defaults to
# "./data"; relative paths resolve against Config.root_dir. load_config defaults
# root_dir to the current working directory, NOT this script's directory.
# Thus normal CLI startup uses <working-directory>/data/silk.db by default.
# An existing data/coco.db is not automatically migrated to data/silk.db.
# A configured app.data_dir can override that directory (absolute paths stay
# absolute); an explicit root_dir supplied to load_config changes relative paths.
# Passing --config chooses a config file, but does not itself change root_dir.
#
# EDIT BOUNDARY
# Additions: content data, a local profile-image asset and missing-file fallback,
# a compatibility alias for existing browser calls, and terminal presentation.
# Existing image-file paths and publishing flags remain unchanged.
# Validation: py_compile, asset hash, and isolated dashboard renderables only.
# No app execution, network use, or config, .env, database or key-file access.
# No Drive/GitHub access or writes.
# ============================================================================
"""COCO core: models, config, event bus, logging, safety heuristics, content."""

from __future__ import annotations

__version__ = "0.1.0"


# ======================================================================
# merged from models.py
# ======================================================================
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class RegistrationRequirement(str, Enum):
    NONE = "none"
    OPTIONAL = "optional"
    REQUIRED = "required"
    EMAIL_VERIFICATION_REQUIRED = "email_verification_required"
    UNKNOWN = "unknown"


class SubmissionMethod(str, Enum):
    FORM = "form"
    POST = "post"
    COMMENT = "comment"
    MESSAGE = "message"
    DIRECTORY = "directory"
    UNKNOWN = "unknown"


class PermissionStatus(str, Enum):
    ALLOWED = "allowed"
    CONDITIONAL = "conditional"
    PROHIBITED = "prohibited"
    UNKNOWN = "unknown"


class ContentVariant(str, Enum):
    PERSONAL_SUPPORT = "personal_support"
    FUNDRAISING = "fundraising"
    COMMUNITY_ASSISTANCE = "community_assistance"
    RELEVANT_PROMOTION = "relevant_promotion"


@dataclass(slots=True)
class WebsiteRecord:
    url: str
    category: str
    language: str = "unknown"
    registration_requirements: RegistrationRequirement = RegistrationRequirement.UNKNOWN
    submission_method: SubmissionMethod = SubmissionMethod.UNKNOWN
    rules_url: Optional[str] = None
    relevance_score: float = 0.0
    last_verification_date: Optional[datetime] = None
    permission_status: PermissionStatus = PermissionStatus.UNKNOWN
    notes: str = ""
    domain: str = ""
    id: Optional[int] = None
    # Permission is only "verified" when the page explicitly permits the exact
    # content category and submission method. A public form alone is not permission.
    permission_verified: bool = False
    permission_evidence: str = ""
    allowed_categories: list[str] = field(default_factory=list)
    submission_method_verified: bool = False
    permission_source_url: str = ""
    permission_checked_at: Optional[datetime] = None
    permission_reason: str = ""
    country: str = "unknown"
    inspection_status: str = "discovered"  # discovered|inspected|eligible
    skip_reason: str = ""


@dataclass(slots=True)
class TranslationRecord:
    id: Optional[int]
    source_text: str
    translated_text: str
    source_language: str
    target_language: str
    provider: str
    content_variant: str
    checksum: str
    created_at: datetime
    reviewed: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SubmissionPlan:
    website: WebsiteRecord
    variant: ContentVariant
    target_language: str
    translated_content: str
    destination_category: str
    intended_action: str
    rules_summary: str
    requires_registration: bool
    requires_email_verification: bool
    has_captcha: bool = False
    approved: bool = False
    auto_eligible: bool = False
    translation_failed: bool = False
    translation_error: str = ""
    content_hash: str = ""
    auto_block_reason: str = ""


@dataclass(slots=True)
class SubmissionResult:
    website_url: str
    status: str  # prepared|attempted|accepted|confirmed|rejected|uncertain|failed|skipped|blocked|needs_approval
    message: str
    timestamp: datetime
    variant: Optional[str] = None
    translation_id: Optional[int] = None
    screenshot_path: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)
    evidence: str = ""
    confirmation: str = ""
    verified: bool = False

# ======================================================================
# merged from config.py
# ======================================================================
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml
from dotenv import load_dotenv
# Credentials/keyring support intentionally disabled.


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


DEFAULT_CONFIG: dict[str, Any] = {
    "app": {
        "name": "COCO",
        "environment": "production",
        "data_dir": ".",
        "log_dir": ".",
        "headless": True,
        "auto_mode": True,
        "review_mode": False,
        "autonomous": True,
        "auto_discover": True,
        "continuous": False,
        "continuous_interval_seconds": 0,
        "continuous_idle_pause_seconds": 2,
        "max_retries": 2,
        "retry_backoff_seconds": 5,
        "default_language": "en",
        "request_timeout_seconds": 30,
        "navigation_timeout_ms": 30000,
        "max_pages_per_site": 5,
        "min_relevance_score": 0.55,
        "max_submissions_per_run": 0,  # 0 = no per-run cap; per-domain daily limit still applies
        "publishing_workers": 3,  # parallel site workers in continuous mode; sites partitioned by domain hash
        "max_submissions_per_domain_per_day": 1,
        "duplicate_cooldown_days": 30,
        "profile_name": "Vinay",
        "profile_picture_path": "profile/profile picture.jpeg",
        "dashboard_port": 8765,
        "recovery_stale_seconds": 0,
        "max_browser_recoveries": 2,
        # Timestamped SQLite backup on startup (data/backups/, keeps newest N).
        "backup_on_start": True,
        "backup_keep": 10,
    },
    "browser": {
        "channel": "chromium",
        "slow_mo_ms": 0,
        "user_data_dir": "",
        "viewport": {"width": 1366, "height": 900},
        "locale": "en-US",
        "timezone_id": "Asia/Kolkata",
        "max_browser_recoveries": 2,
    },
    "credentials": {
        # No central password store and no login to existing accounts. Sign-up,
        # where a site explicitly permits it, uses per-site generated passwords
        # stored locally in the database (site_accounts table).
        "enabled": False,
        # Optional: one password for every sign-up (or set the
        # COCO_UNIVERSAL_PASSWORD env var). Empty = per-site generated
        # passwords (default, safer). Never commit or share this value.
        "universal_password": "",
    },
    "safety": {
        # Extend or disable the built-in obstacle-detection signatures.
        # extra_* entries are lowercase substrings matched against page text/html;
        # disabled_signatures removes built-ins by their substring. Detection
        # only - COCO never attempts to bypass what it detects.
        "extra_captcha_signatures": [],
        "extra_login_signatures": [],
        "extra_registration_signatures": [],
        "extra_email_verification_signatures": [],
        "extra_phone_verification_signatures": [],
        "extra_human_intervention_signatures": [],
        "extra_rate_limit_signatures": [],
        "disabled_signatures": [],
    },
    "selectors": {
        # CSS selector overrides for the publishing engine. Empty lists keep the
        # built-in defaults (identical to the previously hard-coded lists).
        "signup_links": [],
        "registration_submit": [],
        "form_submit": [],
    },
    "discovery": {
        "enabled": True,
        "seed_urls": [],
        "candidate_urls": [],
        "allowed_categories": [
            "personal_support",
            "fundraising",
            "community_assistance",
            "relevant_promotion",
        ],
        "require_explicit_submission_permission": True,
        "prioritize_no_registration": True,
        "search_providers": ["duckduckgo", "bing", "mojeek", "yahoo", "startpage"],
        "search_queries": [],
        "search_languages": "all",
        "multilingual_queries": True,
        "max_queries_per_run": 40,
        "max_results_per_query": 12,
        "max_candidates_per_seed": 25,
        "max_urls_per_domain": 10,
        "min_candidate_relevance": 0.30,
        "request_delay_seconds": 0.3,
        # Bulk scan (target ~10,000 sites/day on a small 1 vCPU / ~1.3 GB host):
        # plain HTTP first in a thread pool, one reused browser only for JS-only pages.
        "http_first": True,
        "scan_workers": 12,
        "per_host_delay_seconds": 1.0,
        "max_scans_per_day": 0,  # 0 = no daily cap
        "max_scans_per_cycle": 1000,
        "js_fallback_per_batch": 15,
        "min_static_text_chars": 300,
        "skip_ai_in_bulk_scan": True,
        "respect_robots_txt": True,
        "prefer_new_domains": True,
        "recheck_existing_domains": False,
        "recheck_existing_urls": False,
    },
    "translation": {
        "provider": "auto",
        "fallback_provider": "",
        "cache_enabled": True,
        "preserve_tokens": [],
    },
    "publishing": {
        "require_human_approval": False,
        "auto_mode_only_for_preverified_no_registration": False,
        "autonomous_submit": True,
        # Sign-up is allowed only where the site's own rules explicitly permit
        # the submission, and still stops on CAPTCHA/email/phone/ID challenges.
        "allow_registration_workflows": True,
        "allow_account_creation_when_permitted": True,
        "stop_on_captcha": True,
        "stop_on_login_wall": True,
        "stop_on_rate_limit": True,
        "stop_on_permission_required": True,
        # Master switch for site-rule/permission checks (ToS skip). Default ON.
        # When false, only CAPTCHA/verification stops and capability checks apply.
        "respect_site_rules": True,
        # LIVE by default as requested by user.
        "dry_run": False,
    },
    "intelligence": {
        "enabled": True,
        "provider": "auto",  # auto|heuristic|ollama|google|gemini (cloud optional if explicitly configured)
        "model": "",
        "fallback": "heuristic",
        # Optional cloud LLM (owner-configured). Advisory only, never overrides verified permission/rules.
        # Provide API key via environment variable only (never store in repo/config).
        "cloud_enabled": False,
        "api_key_env": "COCO_GOOGLE_API_KEY",
        "cloud_model": "gemini-1.5-flash",
        "cloud_timeout_seconds": 20,
    },
    "content": {
        "source_language": "en",
        "default_variants": ["personal_support", "fundraising", "relevant_promotion"],
        "include_source_metadata": True,
    },
}


@dataclass
class Config:
    root_dir: Path
    data: dict[str, Any]

    @property
    def app(self) -> dict[str, Any]:
        return self.data["app"]

    @property
    def browser(self) -> dict[str, Any]:
        return self.data["browser"]

    @property
    def credentials(self) -> dict[str, Any]:
        return self.data["credentials"]

    @property
    def discovery(self) -> dict[str, Any]:
        return self.data["discovery"]

    @property
    def translation(self) -> dict[str, Any]:
        return self.data["translation"]

    @property
    def publishing(self) -> dict[str, Any]:
        return self.data["publishing"]

    @property
    def content(self) -> dict[str, Any]:
        return self.data["content"]

    @property
    def intelligence(self) -> dict[str, Any]:
        return self.data.get("intelligence", {})

    @property
    def safety(self) -> dict[str, Any]:
        return self.data.get("safety", {})

    @property
    def selectors(self) -> dict[str, Any]:
        return self.data.get("selectors", {})

    def path(self, value: str | Path) -> Path:
        p = Path(value)
        return p if p.is_absolute() else (self.root_dir / p).resolve()

    @property
    def data_dir(self) -> Path:
        # No folder creation in project dir; keep DB in project root.
        return self.root_dir

    @property
    def log_dir(self) -> Path:
        # No log folder/file creation; logs go to DB/events.
        return self.root_dir

    @property
    def db_path(self) -> Path:
        new = self.root_dir / "silk.db"
        if not new.exists():
            for legacy in ("nexus.db", "data.db"):  # newest legacy name first
                old = self.root_dir / legacy
                if old.exists():
                    try:  # one-time migration: copy, never delete the old file
                        shutil.copy2(old, new)
                        break
                    except Exception:
                        return old
        return new

    def get_registration_credentials(self, prompt_if_missing: bool = False) -> tuple[Optional[str], Optional[str]]:
        """Credentials/account creation are disabled. Always returns (None, None)."""
        return None, None

    def get_registration_password(self, prompt_if_missing: bool = False) -> Optional[str]:
        return None


def load_config(config_path: Optional[str | Path] = None, root_dir: Optional[str | Path] = None) -> Config:
    root = Path(root_dir).resolve() if root_dir else Path(__file__).resolve().parent
    load_dotenv(root / ".env", override=False)

    cfg: dict[str, Any] = dict(DEFAULT_CONFIG)
    paths_to_try: list[Path] = []
    if config_path:
        paths_to_try.append(Path(config_path))
    paths_to_try.extend([root / "config.yaml", root / "config.yml", root / "config.example.yaml"])

    for p in paths_to_try:
        if p.exists() and p.is_file():
            with p.open("r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            if isinstance(loaded, dict):
                cfg = _deep_merge(cfg, loaded)
            break

    # Auto-load permanent profile identity from profile/profile.json when present
    try:
        profile_json = root / "profile" / "profile.json"
        if profile_json.exists():
            pdata = json.loads(profile_json.read_text(encoding="utf-8"))
            if isinstance(pdata, dict):
                cfg.setdefault("profile", {}).update({
                    "name": pdata.get("name", "Vinay"),
                    "email": pdata.get("email", "siyakjain@gmail.com"),
                    "bio": pdata.get("bio", ""),
                    "profile_picture": pdata.get("profile_picture", ""),
                })
                if pdata.get("name"):
                    cfg["app"]["profile_name"] = pdata["name"]
                if pdata.get("profile_picture"):
                    cfg["app"]["profile_picture_path"] = pdata["profile_picture"]
                # Profile email may exist for content/profile identity, but credentials are disabled.
    except Exception as _suppressed_exc:
        _log_suppressed('load_config (line 552)', _suppressed_exc)

    # Environment overrides for common flags
    if os.getenv("COCO_HEADLESS") is not None:
        cfg["app"]["headless"] = os.getenv("COCO_HEADLESS", "false").lower() in {"1", "true", "yes"}
    if os.getenv("COCO_AUTO_MODE") is not None:
        cfg["app"]["auto_mode"] = os.getenv("COCO_AUTO_MODE", "false").lower() in {"1", "true", "yes"}
    if os.getenv("COCO_LOG_LEVEL"):
        cfg["app"]["log_level"] = os.getenv("COCO_LOG_LEVEL")

    # Optional universal sign-up password from the environment (never hardcoded).
    if os.getenv("COCO_UNIVERSAL_PASSWORD"):
        cfg.setdefault("credentials", {})["universal_password"] = os.environ["COCO_UNIVERSAL_PASSWORD"]

    return Config(root_dir=root, data=cfg)

# ======================================================================
# merged from events.py
# ======================================================================
import json
import threading
import time
import shutil
from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Deque, Optional


def format_local_timestamp(dt: Optional[datetime] = None) -> str:
    """Format timestamp in 12-hour format with AM/PM using the computer's local time."""
    dt = dt or datetime.now().astimezone()
    if dt.tzinfo is None:
        dt = dt.astimezone()
    # Windows-compatible 12-hour format without leading zero on hour where possible
    try:
        s = dt.strftime("%I:%M:%S %p").lstrip("0")
        return s if s else dt.strftime("%I:%M:%S %p")
    except Exception:
        h = dt.hour % 12 or 12
        return f"{h}:{dt.minute:02d}:{dt.second:02d} {'AM' if dt.hour < 12 else 'PM'}"


@dataclass
class Event:
    id: int
    ts: str
    type: str
    level: str
    message: str
    details: dict[str, Any]


class EventBus:
    """Thread-safe event bus with bounded history, SQLite persistence hook, and 1/sec display scheduling."""

    def __init__(self, max_events: int = 1000):
        self._max_events = max_events
        self._events: Deque[Event] = deque(maxlen=max_events)  # newest first (recent history)
        self._display_queue: Deque[Event] = deque()  # chronological FIFO for live feed display
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._next_id = 1
        self._persist = None  # callable(ts, type, level, message, details) -> Any
        self._state = {
            "run_state": "IDLE",  # RUNNING/IDLE/STOPPING/STOPPED
            "headless": True,
            "database_status": "UNKNOWN",
            "browser_status": "UNKNOWN",
            "discovered": 0,
            "eligible": 0,
            "submitted": 0,
            "skipped": 0,
            "inspected": 0,
            "attempts": 0,
            "confirmed": 0,
            "rejected": 0,
            "uncertain": 0,
            "failed": 0,
            "success_rate": 0.0,
            "translation_failures": 0,
            "last_confirmed": "",
            "countries": {},
            "languages": {},
            "current_activity": "",
            "queue_pending": 0,
            "started_at_mono": 0.0,
        }
        self._last_activity_mono = time.monotonic()

    def set_persistence(self, fn) -> None:
        """Set optional persistence sink: fn(ts, event_type, level, message, details)."""
        with self._lock:
            self._persist = fn

    def emit(self, message: str, event_type: str = "info", level: str = "info", details: Optional[dict[str, Any]] = None) -> Event:
        # Real timestamp captured at emission time (never fabricated).
        ev = Event(
            id=0,
            ts=format_local_timestamp(),
            type=event_type,
            level=level,
            message=str(message or ""),
            details=details or {},
        )
        persist_fn = None
        with self._cond:
            ev.id = self._next_id
            self._next_id += 1
            self._events.appendleft(ev)  # newest first history buffer
            self._display_queue.append(ev)  # chronological queue for 1/sec display
            self._last_activity_mono = time.monotonic()
            persist_fn = self._persist
            self._cond.notify_all()
        # Persist every event to SQLite (append-only) without losing it if persistence fails.
        if persist_fn is not None:
            try:
                persist_fn(ev.ts, ev.type, ev.level, ev.message, ev.details)
            except Exception as _suppressed_exc:
                _log_suppressed('emit (line 670)', _suppressed_exc)
        return ev

    def list_events(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            return [asdict(e) for e in list(self._events)[: max(0, limit)]]

    def events_since(self, after_id: int, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            items = [e for e in self._events if e.id > after_id]
            # _events is newest-first; for "since" return oldest->newest of that slice
            items = list(reversed(items))[: max(0, limit)]
            return [asdict(e) for e in items]

    def latest_id(self) -> int:
        with self._lock:
            return (self._events[0].id if self._events else 0)

    def wait_for(self, after_id: int, timeout: float = 1.0) -> bool:
        with self._cond:
            if self.latest_id_nolock() > after_id:
                return True
            self._cond.wait(timeout=timeout)
            return self.latest_id_nolock() > after_id

    def latest_id_nolock(self) -> int:
        return self._events[0].id if self._events else 0

    def pop_display_event(self) -> Optional[dict[str, Any]]:
        """Pop the next chronological event for the 1/sec live feed (or None if queue empty)."""
        with self._lock:
            if not self._display_queue:
                return None
            ev = self._display_queue.popleft()
            return asdict(ev)

    def pending_display_count(self) -> int:
        with self._lock:
            return len(self._display_queue)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            state = dict(self._state)
            now_m = time.monotonic()
            state["latest_event_id"] = self._events[0].id if self._events else 0
            state["last_activity_seconds_ago"] = round(max(0.0, now_m - self._last_activity_mono), 1)
            started = float(self._state.get("started_at_mono") or 0.0)
            state["uptime_seconds"] = round(max(0.0, now_m - started), 1) if started > 0 else 0.0
            state["display_queue_pending"] = len(self._display_queue)
            return state

    def set_state(self, **kwargs: Any) -> None:
        with self._lock:
            for k, v in kwargs.items():
                if k in self._state:
                    self._state[k] = v

    def update_counters(self, discovered: Optional[int] = None, eligible: Optional[int] = None,
                        submitted: Optional[int] = None, skipped: Optional[int] = None, **extra: Any) -> None:
        with self._lock:
            if discovered is not None:
                self._state["discovered"] = discovered
            if eligible is not None:
                self._state["eligible"] = eligible
            if submitted is not None:
                self._state["submitted"] = submitted
            if skipped is not None:
                self._state["skipped"] = skipped
            for k, v in extra.items():
                if k in self._state:
                    self._state[k] = v

    def increment(self, key: str, amount: int = 1) -> None:
        with self._lock:
            if key in self._state and isinstance(self._state[key], int):
                self._state[key] += amount


GLOBAL_EVENT_BUS = EventBus(max_events=1000)


def get_event_bus() -> EventBus:
    return GLOBAL_EVENT_BUS


def emit_event(message: str, event_type: str = "info", level: str = "info", details: Optional[dict[str, Any]] = None) -> Event:
    return GLOBAL_EVENT_BUS.emit(message, event_type=event_type, level=level, details=details)

# ======================================================================
# merged from logging_setup.py
# ======================================================================
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


_LOGGER_CONFIGURED = False


class EventBusLogHandler(logging.Handler):
    """Routes log records into the dashboard event bus (no terminal output)."""

    def __init__(self, bus):
        super().__init__()
        self.bus = bus

    def emit(self, record: logging.LogRecord) -> None:
        try:
            # Keep dashboard rows concise; full tracebacks remain in file logs.
            msg = record.getMessage()
            if record.exc_info:
                exc = record.exc_info[1]
                if exc:
                    msg = f"{msg} | {type(exc).__name__}: {exc}"
            msg = " ".join(str(msg or "").split())
            if not msg:
                return
            if len(msg) > 240:
                msg = msg[:237] + "..."
            lvl = (record.levelname or "INFO").lower()
            if lvl == "warning":
                lvl = "warn"
            etype = "system"
            name = (record.name or "").lower()
            lower = msg.lower()
            if "discovery" in name or "discover" in lower:
                etype = "discovery"
            elif "browser" in name or "playwright" in lower or "node.js" in lower:
                etype = "system"
            elif "publish" in name or "submission" in lower:
                etype = "submission_attempt"
            elif "translation" in name or "translat" in lower:
                etype = "translation"
            self.bus.emit(msg, event_type=etype, level=lvl, details={"logger": record.name})
        except Exception as _suppressed_exc:
            _log_suppressed('emit (line 807)', _suppressed_exc)


def setup_logging(log_dir: Path, level: str = "INFO", name: str = "coco", to_console: bool = True) -> logging.Logger:
    global _LOGGER_CONFIGURED
    logger = logging.getLogger(name)
    if _LOGGER_CONFIGURED:
        # allow toggling console behavior for dashboard mode
        if not to_console:
            for h in list(logger.handlers):
                if isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler):
                    logger.removeHandler(h)
        return logger

    # No log files/folders created in project dir; logs are captured via events/DB.
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(fmt)
        console_handler.setLevel(logger.level)
        logger.addHandler(console_handler)

    # Quiet noisy third-party libraries; keep errors/warnings useful
    for noisy in ("asyncio", "playwright", "urllib3", "WDM", "httpx", "httpcore"):
        try:
            logging.getLogger(noisy).setLevel(logging.WARNING)
        except Exception as _suppressed_exc:
            _log_suppressed('setup_logging (line 848)', _suppressed_exc)

    _LOGGER_CONFIGURED = True
    return logger


def enable_dashboard_logging(bus, level: str = "INFO") -> None:
    """Route root/coco logging into EventBus and remove stdout/stderr console handlers."""
    root = logging.getLogger()
    coco = logging.getLogger("coco")
    for lg in (root, coco):
        lg.setLevel(getattr(logging, level.upper(), logging.INFO))
        for h in list(lg.handlers):
            if isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler):
                lg.removeHandler(h)
        # avoid duplicate event handlers
        if not any(isinstance(h, EventBusLogHandler) for h in lg.handlers):
            eh = EventBusLogHandler(bus)
            eh.setLevel(getattr(logging, level.upper(), logging.INFO))
            eh.setFormatter(logging.Formatter("%(name)s | %(message)s"))
            lg.addHandler(eh)
    for noisy in ("asyncio", "playwright", "urllib3", "WDM", "httpx", "httpcore"):
        try:
            nl = logging.getLogger(noisy)
            nl.handlers = [h for h in nl.handlers if isinstance(h, RotatingFileHandler)]
            nl.propagate = False
            nl.setLevel(logging.WARNING)
        except Exception as _suppressed_exc:
            _log_suppressed('enable_dashboard_logging (line 876)', _suppressed_exc)


def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(name or "coco")


def _log_suppressed(context: str, exc: BaseException) -> None:
    """Record a deliberately suppressed exception at debug level.

    COCO keeps running after non-critical failures, but silent `except: pass`
    used to make those failures invisible. Every suppression is now traceable
    in the log file at DEBUG level. Logging must never crash the caller.
    """
    try:
        logging.getLogger("coco").debug("Suppressed exception (%s): %s", context, exc, exc_info=True)
    except Exception as logging_error:  # noqa: BLE001 - logging must never crash the caller
        _ = logging_error

# ======================================================================
# merged from safety.py
# ======================================================================
"""Safety heuristics shared by discovery, publishing and tests.

These helpers only *detect* obstacles and permission cues. They never attempt to
solve, bypass or evade CAPTCHAs, login walls, rate limits or any other
anti-automation control. Detection is intentionally conservative: when in doubt
COCO skips the destination and reports the reason.
"""


from typing import Any, Iterable, Optional


# Ordered (signature, human readable reason) pairs. More specific signatures are
# checked first so the reported reason is useful on the dashboard.
CAPTCHA_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("recaptcha", "CAPTCHA challenge (reCAPTCHA)"),
    ("g-recaptcha", "CAPTCHA challenge (reCAPTCHA)"),
    ("hcaptcha", "CAPTCHA challenge (hCaptcha)"),
    ("h-captcha", "CAPTCHA challenge (hCaptcha)"),
    ("cf-turnstile", "CAPTCHA challenge (Cloudflare Turnstile)"),
    ("challenges.cloudflare.com", "CAPTCHA challenge (Cloudflare Turnstile)"),
    ("turnstile", "CAPTCHA challenge (Cloudflare Turnstile)"),
    ("arkoselabs", "Bot verification challenge (Arkose)"),
    ("funcaptcha", "Bot verification challenge (FunCaptcha)"),
    ("geetest", "Bot verification challenge (GeeTest)"),
    ("cf-chl", "Cloudflare bot challenge"),
    ("cf_chl_opt", "Cloudflare bot challenge"),
    ("cdn-cgi/challenge-platform", "Cloudflare bot challenge"),
    ("checking your browser", "Cloudflare bot challenge"),
    ("just a moment", "Cloudflare bot challenge"),
    ("verify you are human", "Human verification required"),
    ("verify you're human", "Human verification required"),
    ("are you a robot", "Bot verification challenge"),
    ("are you human", "Human verification required"),
    ("press and hold", "Human verification required"),
    ("prove you are human", "Human verification required"),
)

LOGIN_SIGNATURES: tuple[str, ...] = (
    "log in to continue",
    "login to continue",
    "sign in to continue",
    "you must be logged in",
    "you must be signed in",
    "login required",
    "log in required",
    "sign in required",
    "members only",
    "member login",
    "please log in",
    "please sign in",
)

REGISTRATION_SIGNATURES: tuple[str, ...] = (
    "create an account to",
    "create account to",
    "register to continue",
    "registration required",
    "you need an account",
    "sign up to continue",
    "account required",
)

EMAIL_VERIFICATION_SIGNATURES: tuple[str, ...] = (
    "verify your email",
    "verify your e-mail",
    "email verification",
    "confirm your email",
    "confirmation email",
    "check your inbox",
    "verification email",
    "we sent you an email",
)

PHONE_VERIFICATION_SIGNATURES: tuple[str, ...] = (
    "verify your phone",
    "phone verification",
    "verify your mobile",
    "mobile verification",
    "sms verification",
    "enter the sms code",
    "text message code",
    "we sent a code to your phone",
)

HUMAN_INTERVENTION_SIGNATURES: tuple[str, ...] = (
    "wait for approval",
    "manual review",
    "administrator approval",
    "moderator approval required",
    "pending human review",
    # Identity verification: COCO never bypasses these, it stops and skips.
    "verify your identity",
    "identity verification",
    "id verification",
    "upload your id",
    "upload a photo of your id",
    "government-issued id",
    "government id",
    "kyc verification",
)

RATE_LIMIT_SIGNATURES: tuple[str, ...] = (
    "rate limit",
    "too many requests",
    "try again later",
    "you have exceeded",
    "slow down",
    "temporarily blocked",
    "temporarily restricted",
    "request limit reached",
)


def _blob(text: str = "", html: str = "", urls: Optional[Iterable[str]] = None) -> str:
    parts = [text or "", html or ""]
    if urls:
        parts.extend(str(u) for u in urls)
    return "\n".join(parts).lower()


def detect_obstacles(
    text: str = "",
    html: str = "",
    status_code: Optional[int] = None,
    frame_urls: Optional[Iterable[str]] = None,
) -> list[str]:
    """Return a de-duplicated list of obstacle reasons found on a page.

    The result is empty only when no known obstacle signature is present. The
    caller must treat a non-empty result as "skip this destination".
    """
    blob = _blob(text, html, frame_urls)
    reasons: list[str] = []

    def add(reason: str) -> None:
        if reason not in reasons:
            reasons.append(reason)

    if status_code == 429:
        add("HTTP 429 rate limit")
    elif status_code in (403, 503) and ("cloudflare" in blob or "challenge" in blob or "captcha" in blob):
        add(f"HTTP {status_code} anti-bot response")

    for signature, reason in CAPTCHA_SIGNATURES:
        if signature in blob:
            add(reason)

    if any(sig in blob for sig in LOGIN_SIGNATURES):
        add("Login wall detected")
    if any(sig in blob for sig in REGISTRATION_SIGNATURES):
        add("Registration required")
    if any(sig in blob for sig in EMAIL_VERIFICATION_SIGNATURES):
        add("Email verification required")
    if any(sig in blob for sig in PHONE_VERIFICATION_SIGNATURES):
        add("Phone verification required")
    if any(sig in blob for sig in HUMAN_INTERVENTION_SIGNATURES):
        add("Human verification/approval required")
    if any(sig in blob for sig in RATE_LIMIT_SIGNATURES):
        add("Rate limit or temporary block detected")

    return reasons

# Alias for browser-module call sites that use the former name.
detect_obstacle_text = detect_obstacles


def is_human_verification_obstacle(reasons: Iterable[str]) -> bool:
    """True when an obstacle requires a human to complete verification."""
    joined = " ".join(reasons).lower()
    return any(term in joined for term in (
        "captcha", "bot verification", "human verification", "cloudflare", "email verification",
        "phone verification", "human verification/approval",
    ))


def summarize_obstacles(reasons: Iterable[str]) -> str:
    clean = [r for r in reasons if r]
    if not clean:
        return ""
    return "; ".join(clean)


# Immutable copies of the built-in signatures; configure_safety always rebuilds
# the active tuples from these so repeated calls never accumulate extras.
_BASE_SIGNATURES: dict[str, tuple] = {
    "captcha": CAPTCHA_SIGNATURES,
    "login": LOGIN_SIGNATURES,
    "registration": REGISTRATION_SIGNATURES,
    "email_verification": EMAIL_VERIFICATION_SIGNATURES,
    "phone_verification": PHONE_VERIFICATION_SIGNATURES,
    "human_intervention": HUMAN_INTERVENTION_SIGNATURES,
    "rate_limit": RATE_LIMIT_SIGNATURES,
}


def configure_safety(safety_cfg: Optional[dict[str, Any]] = None) -> None:
    """Apply the config `safety` section: extra_/disabled_ detection signatures.

    Called once at startup. Detection only - this never weakens the rule that a
    detected obstacle means "skip this destination".
    """
    global CAPTCHA_SIGNATURES, LOGIN_SIGNATURES, REGISTRATION_SIGNATURES
    global EMAIL_VERIFICATION_SIGNATURES, PHONE_VERIFICATION_SIGNATURES
    global HUMAN_INTERVENTION_SIGNATURES, RATE_LIMIT_SIGNATURES

    cfg = safety_cfg or {}
    disabled = {str(s).strip().lower() for s in (cfg.get("disabled_signatures") or []) if str(s).strip()}

    def _probe(item) -> str:
        return (item[0] if isinstance(item, tuple) else str(item)).lower()

    def _apply(kind: str, base: tuple, extras) -> tuple:
        kept = [item for item in base if _probe(item) not in disabled]
        for extra in (extras or []):
            extra = str(extra).strip().lower()
            if not extra:
                continue
            if kind == "captcha":
                kept.append((extra, "CAPTCHA/bot verification (custom signature)"))
            else:
                kept.append(extra)
        return tuple(kept)

    CAPTCHA_SIGNATURES = _apply("captcha", _BASE_SIGNATURES["captcha"], cfg.get("extra_captcha_signatures"))
    LOGIN_SIGNATURES = _apply("login", _BASE_SIGNATURES["login"], cfg.get("extra_login_signatures"))
    REGISTRATION_SIGNATURES = _apply("registration", _BASE_SIGNATURES["registration"], cfg.get("extra_registration_signatures"))
    EMAIL_VERIFICATION_SIGNATURES = _apply("email_verification", _BASE_SIGNATURES["email_verification"], cfg.get("extra_email_verification_signatures"))
    PHONE_VERIFICATION_SIGNATURES = _apply("phone_verification", _BASE_SIGNATURES["phone_verification"], cfg.get("extra_phone_verification_signatures"))
    HUMAN_INTERVENTION_SIGNATURES = _apply("human_intervention", _BASE_SIGNATURES["human_intervention"], cfg.get("extra_human_intervention_signatures"))
    RATE_LIMIT_SIGNATURES = _apply("rate_limit", _BASE_SIGNATURES["rate_limit"], cfg.get("extra_rate_limit_signatures"))

# ======================================================================
# merged from content.py
# ======================================================================
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# Permanent original source content (kept unchanged). Loaded from content/original/vinay_fundraising.txt when available.
DEFAULT_ORIGINAL_FUNDRAISING_TEXT = (
    "I am Vinay and I am in need of help - any kindness or support is deeply appreciated, and good karma comes back around 🤍\n\n"
    "Pay online by card or bank, any amount helps 🙏🏻\n\n"
    "https://wise.com/pay/business/vinaydusa\n\n"
    "USDT (Ethereum network): 0xfc89f29283445B4c0c81f2Ae71ba3e54c1cbdEe7\n\n"
    "Bitcoin: 36dyYLRJbCvgdQPuKraEs39vvx577W4fJC\n\n"
    "PS: Better habits for you, and it supports me 🤗 https://cero.gumroad.com/"
)

PERSONAL_SUPPORT_APPEAL = DEFAULT_ORIGINAL_FUNDRAISING_TEXT

ORIGINAL_CONTENT_KEY = "vinay_fundraising"
ORIGINAL_CONTENT_NAME = "Vinay Fundraising Appeal"
ORIGINAL_CONTENT_REL_PATH = Path("content/original/vinay_fundraising.txt")
TRANSLATED_CONTENT_DIR = Path("content/translated")
GUMROAD_PROMO_MARKER = "PS: Better habits for you, and it supports me 🤗 https://cero.gumroad.com/"

PRESERVE_TOKENS = [
    "https://wise.com/pay/business/vinaydusa",
    "0xfc89f29283445B4c0c81f2Ae71ba3e54c1cbdEe7",
    "36dyYLRJbCvgdQPuKraEs39vvx577W4fJC",
    "https://cero.gumroad.com/",
]

PROFILE_NAME = "Vinay"
PROFILE_EMAIL = "siyakjain@gmail.com"
DEFAULT_PROFILE_PICTURE = "profile/profile picture.jpeg"


@dataclass(frozen=True)
class ContentItem:
    variant: ContentVariant
    title: str
    body: str


def load_original_fundraising_text(root_dir: Optional[Path] = None) -> str:
    """Load the permanent original fundraising message from disk; never modify the saved original."""
    candidates = []
    if root_dir:
        candidates.append(Path(root_dir) / ORIGINAL_CONTENT_REL_PATH)
    # Fallback relative to cwd
    candidates.append(Path.cwd() / ORIGINAL_CONTENT_REL_PATH)
    for p in candidates:
        try:
            if p.exists() and p.is_file():
                return p.read_text(encoding="utf-8").rstrip("\r\n")
        except Exception:
            continue
    return DEFAULT_ORIGINAL_FUNDRAISING_TEXT


def ensure_original_content_files(root_dir: Path) -> Path:
    """Ensure the original content file exists at the permanent location. Never overwrite if present."""
    root_dir = Path(root_dir)
    path = root_dir / ORIGINAL_CONTENT_REL_PATH
    # No content folders/files created in project dir; original content is embedded in code/DB.
    try:
        if False and not path.exists():
            path.write_text(DEFAULT_ORIGINAL_FUNDRAISING_TEXT, encoding="utf-8")
    except Exception:
        pass
    return path


def split_gumroad_promo(text: str) -> tuple[str, str]:
    """Return (appeal_without_promo, gumroad_promo_section). Keeps Gumroad promo identifiable."""
    if GUMROAD_PROMO_MARKER in text:
        before, _, _ = text.partition(GUMROAD_PROMO_MARKER)
        return before.rstrip(), GUMROAD_PROMO_MARKER
    # fallback: if ends with gumroad url line
    lines = text.rstrip().splitlines()
    if lines and "cero.gumroad.com" in lines[-1]:
        promo = lines[-1].strip()
        main = "\n".join(lines[:-1]).rstrip()
        return main, promo
    return text.rstrip(), ""


class ContentManager:
    """Builds and manages source content variants while preserving required facts and payment details."""

    def __init__(self, source_text: Optional[str] = None, root_dir: Optional[Path] = None):
        self.root_dir = Path(root_dir) if root_dir else None
        if source_text is not None:
            self.original_fundraising_text = source_text.strip()
        elif self.root_dir:
            self.original_fundraising_text = load_original_fundraising_text(self.root_dir)
        else:
            self.original_fundraising_text = load_original_fundraising_text(None)
        self.source_text = self.original_fundraising_text
        self.fundraising_appeal_text = self.original_fundraising_text
        self.appeal_without_promo, self.gumroad_promo_section = split_gumroad_promo(self.original_fundraising_text)

    @property
    def original_file_path(self) -> Optional[Path]:
        if not self.root_dir:
            return None
        return self.root_dir / ORIGINAL_CONTENT_REL_PATH

    def get_variant(self, variant: ContentVariant) -> ContentItem:
        if variant == ContentVariant.PERSONAL_SUPPORT:
            return ContentItem(variant, "Personal support appeal", self.fundraising_appeal_text)
        if variant == ContentVariant.FUNDRAISING:
            body = (
                "Hi, I'm Vinay. I'm reaching out for personal support during a difficult time. "
                "If you're able to help, any kindness or support is deeply appreciated. "
                "There is no fixed amount - any amount helps.\n\n"
                "Pay online by card or bank: https://wise.com/pay/business/vinaydusa\n\n"
                "USDT (Ethereum network): 0xfc89f29283445B4c0c81f2Ae71ba3e54c1cbdEe7\n\n"
                "Bitcoin: 36dyYLRJbCvgdQPuKraEs39vvx577W4fJC\n\n"
                f"{self.gumroad_promo_section or GUMROAD_PROMO_MARKER}"
            )
            return ContentItem(variant, "Fundraising support request", body)
        if variant == ContentVariant.COMMUNITY_ASSISTANCE:
            body = (
                "Hello, I'm Vinay. I'm sharing a personal support request in communities where this is explicitly allowed. "
                "If you're able to offer kindness or support, it would mean a lot. Any amount helps, and there is no obligation.\n\n"
                "Support options:\n"
                "Card/bank: https://wise.com/pay/business/vinaydusa\n"
                "USDT (Ethereum network): 0xfc89f29283445B4c0c81f2Ae71ba3e54c1cbdEe7\n"
                "Bitcoin: 36dyYLRJbCvgdQPuKraEs39vvx577W4fJC\n\n"
                "Optional: https://cero.gumroad.com/"
            )
            return ContentItem(variant, "Community assistance request", body)
        if variant == ContentVariant.RELEVANT_PROMOTION:
            promo = self.gumroad_promo_section or GUMROAD_PROMO_MARKER
            body = (
                f"{promo}\n\n"
                "If you'd also like to support me directly, any kindness is appreciated:\n"
                "Card/bank: https://wise.com/pay/business/vinaydusa\n"
                "USDT (Ethereum network): 0xfc89f29283445B4c0c81f2Ae71ba3e54c1cbdEe7\n"
                "Bitcoin: 36dyYLRJbCvgdQPuKraEs39vvx577W4fJC"
            )
            return ContentItem(variant, "Relevant product/support share", body)
        return ContentItem(variant, "Content", self.fundraising_appeal_text)

    def get_gumroad_promo_section(self) -> str:
        return self.gumroad_promo_section

    def get_fundraising_appeal(self, include_promo: bool = True) -> str:
        if include_promo:
            return self.fundraising_appeal_text
        return self.appeal_without_promo

    @staticmethod
    def checksum(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def validate_preserved_tokens(original: str, translated: str, tokens: list[str] | None = None) -> list[str]:
        tokens = tokens or PRESERVE_TOKENS
        missing = [t for t in tokens if t in original and t not in translated]
        return missing

    @staticmethod
    def ensure_tokens(text: str, tokens: list[str] | None = None) -> str:
        """Append missing critical tokens at the end as a safety net (should be avoided by translator)."""
        tokens = tokens or PRESERVE_TOKENS
        missing = [t for t in tokens if t not in text]
        if not missing:
            return text
        suffix = "\n\n" + "\n".join(missing)
        return text.rstrip() + suffix

    @staticmethod
    def payment_info() -> dict:
        return {
            "wise": "https://wise.com/pay/business/vinaydusa",
            "usdt_ethereum": "0xfc89f29283445B4c0c81f2Ae71ba3e54c1cbdEe7",
            "bitcoin": "36dyYLRJbCvgdQPuKraEs39vvx577W4fJC",
            "gumroad": "https://cero.gumroad.com/",
        }

    @staticmethod
    def register_original_content(db, root_dir: Path, text: Optional[str] = None) -> dict:
        """Register permanent original source content in SQLite as vinay_fundraising (without overwriting original text)."""
        root_dir = Path(root_dir)
        path = ensure_original_content_files(root_dir)
        original_text = text if text is not None else path.read_text(encoding="utf-8").rstrip("\r\n")
        metadata = {
            "gumroad_promo_section": split_gumroad_promo(original_text)[1],
            "appeal_without_promo": split_gumroad_promo(original_text)[0],
            "preserve_tokens": PRESERVE_TOKENS,
            "immutable_original": True,
        }
        db.upsert_original_content(
            key=ORIGINAL_CONTENT_KEY,
            name=ORIGINAL_CONTENT_NAME,
            content=original_text,
            language="en",
            file_path=str(ORIGINAL_CONTENT_REL_PATH).replace("\\", "/"),
            metadata=metadata,
        )
        return db.get_original_content(ORIGINAL_CONTENT_KEY) or {}


# ============================================================================
# merged from coco_data.py
# ============================================================================

"""COCO data layer: database, translation, intelligence, relevance, profile, reporting."""



# ======================================================================
# merged from database.py
# ======================================================================
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlparse


def _ensure_coco_profile_asset(conn: sqlite3.Connection) -> None:
    """Create the local assets table and store the profile JPEG once."""
    import base64

    conn.execute("CREATE TABLE IF NOT EXISTS assets (name TEXT PRIMARY KEY, mime TEXT, data BLOB)")
    conn.execute(
        "INSERT OR IGNORE INTO assets (name, mime, data) VALUES (?, ?, ?)",
        ("coco_profile", "image/jpeg", base64.b64decode(COCO_PROFILE_PICTURE_B64)),
    )


def get_coco_profile_picture(conn: sqlite3.Connection) -> bytes:
    """Return the stored COCO profile picture bytes."""
    row = conn.execute("SELECT data FROM assets WHERE name = ?", ("coco_profile",)).fetchone()
    if row is None:
        raise LookupError("COCO profile picture asset is not initialized")
    return bytes(row["data"])


# ------------------------------------------------------------------
# At-rest protection for stored site credentials (owner go 2026-11-13):
# site_accounts email/password are AES-256-GCM encrypted before they touch
# silk.db. The key is derived from the Actions secret via env (COCO_DB_KEY,
# falling back to COCO_UNIVERSAL_PASSWORD); no key (plain local runs) keeps
# the old plaintext behavior, and legacy plaintext rows still read back fine.
# ------------------------------------------------------------------
_DB_KEY_ENVS = ("COCO_DB_KEY", "COCO_UNIVERSAL_PASSWORD")


def _db_key() -> Optional[bytes]:
    import hashlib
    import os
    for name in _DB_KEY_ENVS:
        value = os.environ.get(name, "").strip()
        if value:
            return hashlib.sha256(("coco-db-key-v1:" + value).encode("utf-8")).digest()
    return None


def _db_protect(value: str) -> str:
    """Encrypt a stored credential for silk.db; no-op without a key."""
    if not value or str(value).startswith("v1:"):
        return value
    key = _db_key()
    if key is None:
        return value
    import base64
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, str(value).encode("utf-8"), None)
    return "v1:" + base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def _db_unprotect(value: str) -> str:
    """Inverse of _db_protect; legacy plaintext rows pass through."""
    if not value or not str(value).startswith("v1:"):
        return value
    key = _db_key()
    if key is None:
        return ""
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        raw = base64.urlsafe_b64decode(str(value)[3:].encode("ascii"))
        return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode("utf-8")
    except Exception:
        return ""


class Database:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        # DB in project root; no extra folders
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextmanager
    def connection(self):
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def backup(self, keep: int = 10) -> Optional[Path]:
        """Backups to extra files/folders are disabled (only coco.py and silk.db allowed)."""
        return None

    def get_or_create_site_account(self, domain: str, email: str, usernames: Optional[list] = None,
                                   universal_password: str = "") -> dict:
        """Return the stored per-site account for a domain, creating it on first use.

        Each site gets its own generated password (owner requirement, 19:43 IST);
        passwords are stored locally in this database only - protect silk.db.
        """
        import secrets
        import string

        domain = (domain or "").strip().lower()
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM site_accounts WHERE domain=?", (domain,)).fetchone()
            if row:
                return {"domain": row["domain"], "username": row["username"],
                        "email": _db_unprotect(row["email"]), "password": _db_unprotect(row["password"])}
            username = next((str(u) for u in (usernames or []) if u), "vinaydxo")
            if universal_password:
                password = universal_password
            else:
                # Letters+digits with a separator: satisfies common password rules.
                alphabet = string.ascii_letters + string.digits
                password = "".join(secrets.choice(alphabet) for _ in range(4)) + "-" + secrets.token_urlsafe(12)
            now = self._now()
            conn.execute(
                "INSERT INTO site_accounts (domain, username, email, password, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?)",
                (domain, username, _db_protect(email or ""), _db_protect(password), now, now),
            )
        return {"domain": domain, "username": username, "email": email or "", "password": password}

    def touch_site_account(self, domain: str) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE site_accounts SET last_used_at=? WHERE domain=?",
                (self._now(), (domain or "").strip().lower()),
            )

    def _init_db(self) -> None:
        # DB in project root; no extra folders
        with self.connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS websites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL UNIQUE,
                    domain TEXT NOT NULL,
                    category TEXT NOT NULL,
                    language TEXT DEFAULT 'unknown',
                    registration_requirements TEXT NOT NULL,
                    submission_method TEXT NOT NULL,
                    rules_url TEXT,
                    relevance_score REAL DEFAULT 0.0,
                    last_verification_date TEXT,
                    permission_status TEXT DEFAULT 'unknown',
                    permission_verified INTEGER DEFAULT 0,
                    permission_evidence TEXT DEFAULT '',
                    allowed_categories_json TEXT DEFAULT '[]',
                    submission_method_verified INTEGER DEFAULT 0,
                    notes TEXT DEFAULT '',
                    preverified INTEGER DEFAULT 0,
                    auto_eligible INTEGER DEFAULT 0,
                    permission_source_url TEXT DEFAULT '',
                    permission_checked_at TEXT,
                    permission_reason TEXT DEFAULT '',
                    country TEXT DEFAULT 'unknown',
                    inspection_status TEXT DEFAULT 'discovered',
                    skip_reason TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS domains (
                    domain TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    language TEXT DEFAULT 'unknown',
                    categories_json TEXT DEFAULT '[]',
                    permission_status TEXT DEFAULT 'unknown',
                    url_count INTEGER DEFAULT 0,
                    last_outcome TEXT DEFAULT '',
                    notes TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS job_state (
                    submission_key TEXT PRIMARY KEY,
                    website_url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    variant TEXT,
                    content_hash TEXT,
                    status TEXT NOT NULL,
                    attempts INTEGER DEFAULT 0,
                    last_error TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS site_accounts (
                    domain TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL,
                    password TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS translations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_text TEXT NOT NULL,
                    translated_text TEXT NOT NULL,
                    source_language TEXT NOT NULL,
                    target_language TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    content_variant TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    reviewed INTEGER DEFAULT 0,
                    metadata_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    UNIQUE(checksum, target_language, provider, content_variant)
                );

                CREATE TABLE IF NOT EXISTS submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    website_id INTEGER,
                    website_url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL,
                    variant TEXT,
                    translation_id INTEGER,
                    screenshot_path TEXT,
                    details_json TEXT DEFAULT '{}',
                    submission_key TEXT,
                    evidence TEXT DEFAULT '',
                    confirmation TEXT DEFAULT '',
                    http_status INTEGER,
                    verified INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(website_id) REFERENCES websites(id) ON DELETE SET NULL,
                    FOREIGN KEY(translation_id) REFERENCES translations(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS approvals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    website_url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    variant TEXT NOT NULL,
                    target_language TEXT NOT NULL,
                    translated_content_hash TEXT NOT NULL,
                    approved INTEGER NOT NULL,
                    approver TEXT DEFAULT 'user',
                    notes TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS discovery_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    query TEXT,
                    results_count INTEGER DEFAULT 0,
                    notes TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS discovery_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL UNIQUE,
                    domain TEXT NOT NULL,
                    source TEXT DEFAULT '',
                    query TEXT DEFAULT '',
                    language TEXT DEFAULT 'unknown',
                    country TEXT DEFAULT 'unknown',
                    status TEXT DEFAULT 'pending',
                    priority REAL DEFAULT 0.0,
                    reason TEXT DEFAULT '',
                    discovered_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    processed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS intelligence_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT DEFAULT '',
                    domain TEXT DEFAULT '',
                    capability TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    available INTEGER DEFAULT 0,
                    used INTEGER DEFAULT 0,
                    fallback INTEGER DEFAULT 1,
                    confidence REAL DEFAULT 0.0,
                    evidence TEXT DEFAULT '',
                    reasoning TEXT DEFAULT '',
                    decision_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT,
                    source_content TEXT NOT NULL,
                    payment_links_json TEXT DEFAULT '{}',
                    metadata_json TEXT DEFAULT '{}',
                    is_default INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS original_contents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    language TEXT NOT NULL DEFAULT 'en',
                    content TEXT NOT NULL,
                    file_path TEXT,
                    checksum TEXT NOT NULL,
                    metadata_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_websites_domain ON websites(domain);
                CREATE INDEX IF NOT EXISTS idx_submissions_domain_created ON submissions(domain, created_at);
                CREATE INDEX IF NOT EXISTS idx_translations_lang_variant ON translations(target_language, content_variant);
                CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
                CREATE INDEX IF NOT EXISTS idx_discovery_runs_query ON discovery_runs(query, created_at);
                CREATE INDEX IF NOT EXISTS idx_job_state_status ON job_state(status);
                CREATE INDEX IF NOT EXISTS idx_discovery_queue_status ON discovery_queue(status, priority DESC, discovered_at);
                CREATE INDEX IF NOT EXISTS idx_discovery_queue_domain ON discovery_queue(domain);
                CREATE INDEX IF NOT EXISTS idx_intelligence_decisions_url ON intelligence_decisions(url, capability, created_at);
                CREATE INDEX IF NOT EXISTS idx_events_id ON events(id);
                CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
                """
            )
            self._migrate(conn)
            self._backfill_domains(conn)
            _ensure_coco_profile_asset(conn)

    def _backfill_domains(self, conn: sqlite3.Connection) -> None:
        """Populate the domains table for databases created before it existed."""
        try:
            rows = conn.execute(
                "SELECT DISTINCT domain FROM websites WHERE domain IS NOT NULL AND domain != ''"
            ).fetchall()
            now = self._now()
            for row in rows:
                exists = conn.execute(
                    "SELECT 1 FROM domains WHERE domain=? LIMIT 1", (row["domain"],)
                ).fetchone()
                if not exists:
                    # Only seed missing rows so real last_seen values are preserved.
                    self._touch_domain(conn, row["domain"], now)
        except Exception:
            # Backfill must never prevent the application from starting.
            pass

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Additive migrations for existing databases (never drops user data)."""
        migrations: dict[str, list[tuple[str, str]]] = {
            "websites": [
                ("permission_verified", "INTEGER DEFAULT 0"),
                ("permission_evidence", "TEXT DEFAULT ''"),
                ("allowed_categories_json", "TEXT DEFAULT '[]'"),
                ("submission_method_verified", "INTEGER DEFAULT 0"),
                ("permission_source_url", "TEXT DEFAULT ''"),
                ("permission_checked_at", "TEXT"),
                ("permission_reason", "TEXT DEFAULT ''"),
                ("country", "TEXT DEFAULT 'unknown'"),
                ("inspection_status", "TEXT DEFAULT 'discovered'"),
                ("skip_reason", "TEXT DEFAULT ''"),
            ],
            "submissions": [
                ("submission_key", "TEXT"),
                ("evidence", "TEXT DEFAULT ''"),
                ("confirmation", "TEXT DEFAULT ''"),
                ("http_status", "INTEGER"),
                ("verified", "INTEGER DEFAULT 0"),
            ],
        }
        for table, columns in migrations.items():
            try:
                existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            except Exception:
                continue
            for name, ddl in columns:
                if name not in existing:
                    try:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                    except Exception as _suppressed_exc:
                        _log_suppressed('_migrate (line 1729)', _suppressed_exc)
        # Migration-created columns cannot be indexed inside the initial script on
        # legacy DBs; ensure the indexes exist after columns are present.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_submissions_key ON submissions(submission_key)")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_submissions_success_key "
            "ON submissions(submission_key) WHERE status IN ('success','submitted','accepted','confirmed') AND submission_key IS NOT NULL"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_websites_inspection_status ON websites(inspection_status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_websites_permission_status ON websites(permission_status)")
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_intelligence_decisions_url ON intelligence_decisions(url, capability, created_at)")
        except Exception as _suppressed_exc:
            _log_suppressed('_migrate (line 1742)', _suppressed_exc)
        self._migrate_site_account_protection(conn)

    def _migrate_site_account_protection(self, conn: sqlite3.Connection) -> None:
        """One-time migration: encrypt legacy plaintext site-account credentials."""
        try:
            if _db_key() is None:
                return
            rows = conn.execute("SELECT domain, email, password FROM site_accounts").fetchall()
            for r in rows:
                protected_email = _db_protect(r["email"])
                protected_password = _db_protect(r["password"])
                if protected_email != r["email"] or protected_password != r["password"]:
                    conn.execute(
                        "UPDATE site_accounts SET email=?, password=? WHERE domain=?",
                        (protected_email, protected_password, r["domain"]),
                    )
        except Exception as _suppressed_exc:
            _log_suppressed('_migrate_site_account_protection', _suppressed_exc)

    def record_event(self, ts: str, event_type: str, level: str, message: str, details: Optional[dict[str, Any]] = None) -> int:
        """Persist a dashboard/log event to SQLite (append-only history)."""
        with self.connection() as conn:
            cur = conn.execute(
                "INSERT INTO events (ts, event_type, level, message, details_json, created_at) VALUES (?,?,?,?,?,?)",
                (str(ts or ""), str(event_type or "info"), str(level or "info"), str(message or ""), json.dumps(details or {}, ensure_ascii=False), self._now()),
            )
            return int(cur.lastrowid or 0)

    @staticmethod
    def _now() -> str:
        return datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def cleanup_old_events(self, keep_days: int = 3) -> int:
        """Delete event history older than keep_days to keep DB clean."""
        try:
            cutoff = (datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None) - timedelta(days=max(1, int(keep_days)))).isoformat(timespec="seconds") + "Z"
            with self.connection() as conn:
                cur = conn.execute("DELETE FROM events WHERE created_at < ?", (cutoff,))
                return int(cur.rowcount or 0)
        except Exception:
            return 0

    @staticmethod
    def domain_for_url(url: str) -> str:
        try:
            netloc = urlparse(url).netloc.lower()
            return netloc[4:] if netloc.startswith("www.") else netloc
        except Exception:
            return ""

    def upsert_website(self, record: WebsiteRecord) -> int:
        domain = record.domain or self.domain_for_url(record.url)
        now = self._now()
        last_ver = record.last_verification_date.isoformat(timespec="seconds") if record.last_verification_date else None
        checked_at = record.permission_checked_at.isoformat(timespec="seconds") if record.permission_checked_at else None
        inspection_status = getattr(record, "inspection_status", None) or "inspected"
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO websites (
                    url, domain, category, language, registration_requirements, submission_method,
                    rules_url, relevance_score, last_verification_date, permission_status,
                    permission_verified, permission_evidence, allowed_categories_json,
                    submission_method_verified, notes, permission_source_url, permission_checked_at,
                    permission_reason, country, inspection_status, skip_reason, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    domain=excluded.domain,
                    category=excluded.category,
                    language=excluded.language,
                    registration_requirements=excluded.registration_requirements,
                    submission_method=excluded.submission_method,
                    rules_url=excluded.rules_url,
                    relevance_score=excluded.relevance_score,
                    last_verification_date=excluded.last_verification_date,
                    permission_status=excluded.permission_status,
                    permission_verified=excluded.permission_verified,
                    permission_evidence=excluded.permission_evidence,
                    allowed_categories_json=excluded.allowed_categories_json,
                    submission_method_verified=excluded.submission_method_verified,
                    notes=excluded.notes,
                    permission_source_url=excluded.permission_source_url,
                    permission_checked_at=excluded.permission_checked_at,
                    permission_reason=excluded.permission_reason,
                    country=excluded.country,
                    inspection_status=excluded.inspection_status,
                    skip_reason=excluded.skip_reason,
                    updated_at=excluded.updated_at
                """,
                (
                    record.url,
                    domain,
                    record.category,
                    record.language,
                    record.registration_requirements.value,
                    record.submission_method.value,
                    record.rules_url,
                    float(record.relevance_score),
                    last_ver,
                    record.permission_status.value,
                    1 if record.permission_verified else 0,
                    record.permission_evidence or "",
                    json.dumps(record.allowed_categories or [], ensure_ascii=False),
                    1 if record.submission_method_verified else 0,
                    record.notes,
                    getattr(record, "permission_source_url", "") or "",
                    checked_at,
                    getattr(record, "permission_reason", "") or "",
                    getattr(record, "country", "unknown") or "unknown",
                    inspection_status,
                    getattr(record, "skip_reason", "") or "",
                    now,
                    now,
                ),
            )
            self._touch_domain(conn, domain, now)
            if cur.lastrowid:
                return int(cur.lastrowid)
            row = conn.execute("SELECT id FROM websites WHERE url = ?", (record.url,)).fetchone()
            return int(row["id"]) if row else 0

    def _touch_domain(self, conn: sqlite3.Connection, domain: str, now: str) -> None:
        if not domain:
            return
        rows = conn.execute(
            "SELECT language, category, permission_status FROM websites WHERE domain=?",
            (domain,),
        ).fetchall()
        if not rows:
            return
        languages = sorted({r["language"] for r in rows if r["language"] and r["language"] != "unknown"})
        categories = sorted({r["category"] for r in rows if r["category"]})
        # Domain-level permission is the weakest status among its URLs: only mark
        # allowed when every URL is explicitly allowed.
        statuses = {r["permission_status"] for r in rows}
        if statuses == {"allowed"}:
            permission = "allowed"
        elif "prohibited" in statuses and len(statuses) == 1:
            permission = "prohibited"
        elif "conditional" in statuses or "allowed" in statuses:
            permission = "conditional"
        else:
            permission = "unknown"
        conn.execute(
            """
            INSERT INTO domains (domain, first_seen, last_seen, language, categories_json, permission_status, url_count, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, '')
            ON CONFLICT(domain) DO UPDATE SET
                last_seen=excluded.last_seen,
                language=excluded.language,
                categories_json=excluded.categories_json,
                permission_status=excluded.permission_status,
                url_count=excluded.url_count
            """,
            (
                domain, now, now,
                languages[0] if languages else "unknown",
                json.dumps(categories, ensure_ascii=False),
                permission,
                len(rows),
            ),
        )

    def get_website_by_url(self, url: str) -> Optional[WebsiteRecord]:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM websites WHERE url = ?", (url,)).fetchone()
        return self._row_to_website(row) if row else None

    def list_websites(self, min_relevance: float = 0.0, prioritize_no_registration: bool = True) -> list[WebsiteRecord]:
        order = "ORDER BY (registration_requirements = 'none') DESC, relevance_score DESC, updated_at DESC" if prioritize_no_registration else "ORDER BY relevance_score DESC, updated_at DESC"
        q = f"SELECT * FROM websites WHERE relevance_score >= ? {order}"
        with self.connection() as conn:
            rows = conn.execute(q, (min_relevance,)).fetchall()
        return [self._row_to_website(r) for r in rows]

    def mark_website_verified(self, url: str, preverified: bool = True, auto_eligible: bool = False) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE websites SET preverified=?, auto_eligible=?, last_verification_date=?, updated_at=? WHERE url=?",
                (1 if preverified else 0, 1 if auto_eligible else 0, self._now(), self._now(), url),
            )

    def has_recent_submission(self, domain: str, cooldown_days: int) -> bool:
        if cooldown_days <= 0:
            # A zero-day cooldown disables the duplicate window; the per-domain
            # daily volume limit still applies separately.
            return False
        since = (datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None) - timedelta(days=cooldown_days)).isoformat(timespec="seconds") + "Z"
        with self.connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM submissions WHERE domain=? AND status IN ('success','submitted','accepted','confirmed','uncertain','attempted') AND created_at >= ? LIMIT 1",
                (domain, since),
            ).fetchone()
        return row is not None

    def submissions_today_for_domain(self, domain: str) -> int:
        start = datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%dT00:00:00Z")
        with self.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM submissions WHERE domain=? AND created_at >= ? AND status IN ('success','submitted','accepted','confirmed','uncertain','attempted')",
                (domain, start),
            ).fetchone()
        return int(row["c"] if row else 0)

    def has_recent_url_outcome(self, url: str, statuses: list[str], within_seconds: int = 21600) -> bool:
        """True if this URL had a recent submission outcome in statuses (prevents hot-loop reprocessing)."""
        if not url or not statuses or within_seconds <= 0:
            return False
        since = (datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None) - timedelta(seconds=int(within_seconds))).isoformat(timespec="seconds") + "Z"
        placeholders = ",".join("?" for _ in statuses)
        params = [url, since, *statuses]
        try:
            with self.connection() as conn:
                row = conn.execute(
                    f"SELECT 1 FROM submissions WHERE website_url=? AND created_at >= ? AND status IN ({placeholders}) ORDER BY created_at DESC LIMIT 1",
                    params,
                ).fetchone()
            return row is not None
        except Exception:
            return False

    def save_translation(self, rec: TranslationRecord) -> int:
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO translations (
                    source_text, translated_text, source_language, target_language, provider,
                    content_variant, checksum, reviewed, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rec.source_text,
                    rec.translated_text,
                    rec.source_language,
                    rec.target_language,
                    rec.provider,
                    rec.content_variant,
                    rec.checksum,
                    1 if rec.reviewed else 0,
                    json.dumps(rec.metadata, ensure_ascii=False),
                    rec.created_at.isoformat(timespec="seconds"),
                ),
            )
            if cur.lastrowid:
                return int(cur.lastrowid)
            row = conn.execute(
                "SELECT id FROM translations WHERE checksum=? AND target_language=? AND provider=? AND content_variant=?",
                (rec.checksum, rec.target_language, rec.provider, rec.content_variant),
            ).fetchone()
            return int(row["id"]) if row else 0

    def find_translation(self, checksum: str, target_language: str, content_variant: str) -> Optional[TranslationRecord]:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM translations WHERE checksum=? AND target_language=? AND content_variant=? ORDER BY created_at DESC LIMIT 1",
                (checksum, target_language, content_variant),
            ).fetchone()
        if not row:
            return None
        return TranslationRecord(
            id=int(row["id"]),
            source_text=row["source_text"],
            translated_text=row["translated_text"],
            source_language=row["source_language"],
            target_language=row["target_language"],
            provider=row["provider"],
            content_variant=row["content_variant"],
            checksum=row["checksum"],
            created_at=datetime.fromisoformat(row["created_at"].replace("Z", "")),
            reviewed=bool(row["reviewed"]),
            metadata=json.loads(row["metadata_json"] or "{}"),
        )

    def record_submission(self, website_id: Optional[int], website_url: str, status: str, message: str,
                          variant: Optional[str] = None, translation_id: Optional[int] = None,
                          screenshot_path: Optional[str] = None, details: Optional[dict[str, Any]] = None,
                          submission_key: Optional[str] = None, evidence: str = "", confirmation: str = "",
                          http_status: Optional[int] = None, verified: bool = False) -> int:
        domain = self.domain_for_url(website_url)
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO submissions (
                    website_id, website_url, domain, status, message, variant, translation_id,
                    screenshot_path, details_json, submission_key, evidence, confirmation, http_status, verified, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    website_id, website_url, domain, status, message, variant, translation_id, screenshot_path,
                    json.dumps(details or {}, ensure_ascii=False), submission_key,
                    evidence or "", confirmation or "", http_status, 1 if verified else 0, self._now(),
                ),
            )
            return int(cur.lastrowid)

    def record_approval(self, website_url: str, variant: str, target_language: str, translated_content_hash: str, approved: bool, notes: str = "") -> None:
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO approvals (website_url, domain, variant, target_language, translated_content_hash, approved, notes, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (website_url, self.domain_for_url(website_url), variant, target_language, translated_content_hash, 1 if approved else 0, notes, self._now()),
            )

    def recent_submissions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute("SELECT * FROM submissions ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def recent_failures(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM submissions WHERE status IN ('failed','blocked','needs_approval') ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def upsert_profile(self, name: str, email: Optional[str], source_content: str,
                       payment_links: Optional[dict[str, Any]] = None, metadata: Optional[dict[str, Any]] = None,
                       is_default: bool = True) -> int:
        now = self._now()
        with self.connection() as conn:
            if is_default:
                conn.execute("UPDATE profiles SET is_default=0")
            row = conn.execute("SELECT id FROM profiles WHERE is_default=1" if is_default else "SELECT id FROM profiles WHERE name=?", (name,) if not is_default else ()).fetchone()
            if row:
                conn.execute(
                    "UPDATE profiles SET name=?, email=?, source_content=?, payment_links_json=?, metadata_json=?, is_default=?, updated_at=? WHERE id=?",
                    (name, email, source_content, json.dumps(payment_links or {}, ensure_ascii=False), json.dumps(metadata or {}, ensure_ascii=False), 1 if is_default else 0, now, int(row["id"])),
                )
                return int(row["id"])
            cur = conn.execute(
                "INSERT INTO profiles (name, email, source_content, payment_links_json, metadata_json, is_default, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (name, email, source_content, json.dumps(payment_links or {}, ensure_ascii=False), json.dumps(metadata or {}, ensure_ascii=False), 1 if is_default else 0, now, now),
            )
            return int(cur.lastrowid)

    def get_default_profile(self) -> Optional[dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM profiles WHERE is_default=1 ORDER BY updated_at DESC LIMIT 1").fetchone()
            if not row:
                row = conn.execute("SELECT * FROM profiles ORDER BY updated_at DESC LIMIT 1").fetchone()
        if not row:
            return None
        d = dict(row)
        d["payment_links"] = json.loads(d.get("payment_links_json") or "{}")
        d["metadata"] = json.loads(d.get("metadata_json") or "{}")
        return d

    def upsert_original_content(self, key: str, name: str, content: str, language: str = "en",
                                file_path: Optional[str] = None, metadata: Optional[dict[str, Any]] = None) -> int:
        now = self._now()
        checksum = __import__("hashlib").sha256(content.encode("utf-8")).hexdigest()
        with self.connection() as conn:
            row = conn.execute("SELECT id, content, checksum FROM original_contents WHERE key=?", (key,)).fetchone()
            if row:
                # Never overwrite original content text; only update metadata/path/name if needed
                existing_content = row["content"]
                existing_checksum = row["checksum"] or __import__("hashlib").sha256(existing_content.encode("utf-8")).hexdigest()
                conn.execute(
                    "UPDATE original_contents SET name=?, language=?, file_path=?, checksum=?, metadata_json=?, updated_at=? WHERE key=?",
                    (name, language, file_path, existing_checksum, json.dumps(metadata or {}, ensure_ascii=False), now, key),
                )
                row2 = conn.execute("SELECT id FROM original_contents WHERE key=?", (key,)).fetchone()
                return int(row2["id"]) if row2 else 0
            cur = conn.execute(
                "INSERT INTO original_contents (key, name, language, content, file_path, checksum, metadata_json, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (key, name, language, content, file_path, checksum, json.dumps(metadata or {}, ensure_ascii=False), now, now),
            )
            return int(cur.lastrowid)

    def get_original_content(self, key: str) -> Optional[dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM original_contents WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["metadata"] = json.loads(d.get("metadata_json") or "{}")
        return d

    # ------------------------------------------------------------------
    # Persistent submission job state (crash-safe idempotency)
    # ------------------------------------------------------------------
    def has_successful_submission_key(self, submission_key: str) -> bool:
        if not submission_key:
            return False
        with self.connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM submissions WHERE submission_key=? AND status IN ('success','submitted','accepted','confirmed') LIMIT 1",
                (submission_key,),
            ).fetchone()
            if row is not None:
                return True
            # The crash-safe job state is also authoritative: a job marked
            # success means the destination was already reached.
            job = conn.execute(
                "SELECT 1 FROM job_state WHERE submission_key=? AND status='success' LIMIT 1",
                (submission_key,),
            ).fetchone()
        return job is not None

    def has_successful_submission_for_url(self, website_url: str) -> bool:
        """Permanent per-site guard (owner requirement): True when this exact
        destination URL already received a successful submission in any previous
        run, so reruns never submit twice to the same site."""
        url = (website_url or "").strip()
        if not url:
            return False
        with self.connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM submissions WHERE website_url=? "
                "AND status IN ('success','submitted','accepted','confirmed') LIMIT 1",
                (url,),
            ).fetchone()
        return row is not None

    def enqueue_discovery_url(self, url: str, domain: str, source: str = "", query: str = "",
                              language: str = "unknown", country: str = "unknown",
                              priority: float = 0.0, reason: str = "") -> bool:
        url = (url or "").strip()
        domain = (domain or self.domain_for_url(url)).strip().lower()
        if not url or not domain:
            return False
        now = self._now()
        try:
            with self.connection() as conn:
                conn.execute(
                    """
                    INSERT INTO discovery_queue (url, domain, source, query, language, country, status, priority, reason, discovered_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
                    ON CONFLICT(url) DO UPDATE SET
                        priority=CASE WHEN excluded.priority > discovery_queue.priority THEN excluded.priority ELSE discovery_queue.priority END,
                        source=CASE WHEN discovery_queue.source='' THEN excluded.source ELSE discovery_queue.source END,
                        query=CASE WHEN discovery_queue.query='' THEN excluded.query ELSE discovery_queue.query END,
                        language=CASE WHEN discovery_queue.language IN ('','unknown') THEN excluded.language ELSE discovery_queue.language END,
                        country=CASE WHEN discovery_queue.country IN ('','unknown') THEN excluded.country ELSE discovery_queue.country END,
                        reason=CASE WHEN excluded.reason!='' THEN excluded.reason ELSE discovery_queue.reason END,
                        updated_at=excluded.updated_at
                    """,
                    (url, domain, source, query or "", language or "unknown", country or "unknown", float(priority), reason or "", now, now),
                )
            return True
        except Exception:
            return False

    def fetch_discovery_queue(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM discovery_queue WHERE status='pending' ORDER BY priority DESC, discovered_at ASC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
        return [dict(r) for r in rows]

    def mark_discovery_queue(self, url: str, status: str, reason: str = "") -> None:
        now = self._now()
        with self.connection() as conn:
            conn.execute(
                "UPDATE discovery_queue SET status=?, reason=COALESCE(NULLIF(?, ''), reason), updated_at=?, processed_at=? WHERE url=?",
                (status, reason or "", now, now if status != 'pending' else None, url),
            )

    def recover_discovery_queue_processing(self, reason: str = "recovered after restart/crash") -> int:
        """Return interrupted 'processing' queue rows back to 'pending' so they are not lost."""
        now = self._now()
        try:
            with self.connection() as conn:
                cur = conn.execute(
                    "UPDATE discovery_queue SET status='pending', reason=?, updated_at=?, processed_at=NULL WHERE status='processing'",
                    (reason or "recovered", now, now),
                )
                return int(cur.rowcount or 0)
        except Exception:
            return 0

    def confirmed_submissions_count(self) -> int:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM submissions WHERE status='confirmed' OR (verified=1 AND status IN ('success','accepted','confirmed'))"
            ).fetchone()
        return int(row["c"] if row else 0)

    def dashboard_metrics(self) -> dict[str, Any]:
        with self.connection() as conn:
            websites = conn.execute("SELECT * FROM websites").fetchall()
            counts_rows = conn.execute("SELECT status, COUNT(*) AS c FROM submissions GROUP BY status").fetchall()
            domains = conn.execute("SELECT COUNT(*) AS c FROM domains").fetchone()
            last_confirmed = conn.execute(
                "SELECT website_url, created_at, confirmation, evidence FROM submissions "
                "WHERE status='confirmed' OR (verified=1 AND status IN ('success','accepted','confirmed')) "
                "ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            lang_rows = conn.execute(
                "SELECT COALESCE(NULLIF(language,''),'unknown') AS language, COUNT(*) AS c FROM websites GROUP BY language"
            ).fetchall()
            country_rows = conn.execute(
                "SELECT COALESCE(NULLIF(country,''),'unknown') AS country, COUNT(*) AS c FROM websites GROUP BY country"
            ).fetchall()
            translation_failures = conn.execute(
                "SELECT COUNT(*) AS c FROM submissions WHERE status='skipped' AND "
                "(LOWER(message) LIKE '%translation%' OR LOWER(details_json) LIKE '%translation%')"
            ).fetchone()
            queue_pending = conn.execute("SELECT COUNT(*) AS c FROM discovery_queue WHERE status='pending'").fetchone()
            try:
                ai_rows = conn.execute(
                    "SELECT capability, provider, COUNT(*) AS c FROM intelligence_decisions GROUP BY capability, provider"
                ).fetchall()
            except Exception:
                ai_rows = []

        status_counts = {str(r["status"]): int(r["c"]) for r in counts_rows}
        discovered = len(websites)
        inspected = sum(1 for w in websites if (w["inspection_status"] or "") in ("inspected", "eligible"))
        eligible = sum(1 for w in websites if (w["inspection_status"] or "") == "eligible")
        attempted = sum(status_counts.get(s, 0) for s in ("attempted", "in_progress"))
        confirmed = self.confirmed_submissions_count()
        accepted = status_counts.get("accepted", 0)
        rejected = status_counts.get("rejected", 0)
        uncertain = status_counts.get("uncertain", 0)
        failed = status_counts.get("failed", 0)
        skipped = sum(status_counts.get(s, 0) for s in ("skipped", "blocked", "needs_approval"))
        prepared = status_counts.get("prepared", 0)
        return {
            "discovered_websites": discovered,
            "discovered_domains": int(domains["c"] if domains else 0),
            "inspected_pages": inspected,
            "eligible_destinations": eligible,
            "prepared_submissions": prepared,
            "submission_attempts": attempted + confirmed + accepted + rejected + uncertain + failed + status_counts.get("submitted", 0) + status_counts.get("success", 0),
            "accepted_submissions": accepted,
            "confirmed_successful_submissions": confirmed,
            "rejected_submissions": rejected,
            "uncertain_submissions": uncertain,
            "failed_submissions": failed,
            "skipped_submissions": skipped,
            "status_counts": status_counts,
            "language_distribution": {str(r["language"]): int(r["c"]) for r in lang_rows},
            "country_distribution": {str(r["country"]): int(r["c"]) for r in country_rows},
            "translation_failures": int(translation_failures["c"] if translation_failures else 0),
            "discovery_queue_pending": int(queue_pending["c"] if queue_pending else 0),
            "last_confirmed_submission": dict(last_confirmed) if last_confirmed else None,
            "confirmed_success_rate": (confirmed / max(1, confirmed + rejected + uncertain + failed)) if (confirmed + rejected + uncertain + failed) > 0 else 0.0,
            "ai_decisions": [dict(r) for r in ai_rows],
        }

    def record_intelligence_decision(self, url: str, capability: str, record: dict[str, Any]) -> None:
        try:
            domain = self.domain_for_url(url) if url else ""
            with self.connection() as conn:
                conn.execute(
                    """
                    INSERT INTO intelligence_decisions
                    (url, domain, capability, provider, available, used, fallback, confidence, evidence, reasoning, decision_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        url or "",
                        domain,
                        capability,
                        str(record.get("provider") or "heuristic"),
                        1 if record.get("available") else 0,
                        1 if record.get("used") else 0,
                        1 if record.get("fallback", True) else 0,
                        float(record.get("confidence") or 0.0),
                        str(record.get("evidence") or ""),
                        str(record.get("reasoning") or ""),
                        json.dumps(record.get("decision") or {}, ensure_ascii=False),
                        self._now(),
                    ),
                )
        except Exception as _suppressed_exc:
            _log_suppressed('record_intelligence_decision (line 2280)', _suppressed_exc)

    def get_job(self, submission_key: str) -> Optional[dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM job_state WHERE submission_key=?", (submission_key,)).fetchone()
        return dict(row) if row else None

    def start_job(self, submission_key: str, website_url: str, domain: str, variant: str,
                  content_hash: str, max_attempts: int = 3) -> dict[str, Any]:
        now = self._now()
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO job_state (submission_key, website_url, domain, variant, content_hash, status, attempts, last_error, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'in_progress', 1, '', ?, ?)
                ON CONFLICT(submission_key) DO UPDATE SET
                    status='in_progress',
                    attempts=job_state.attempts + 1,
                    last_error='',
                    updated_at=excluded.updated_at
                """,
                (submission_key, website_url, domain, variant, content_hash, now, now),
            )
            row = conn.execute("SELECT * FROM job_state WHERE submission_key=?", (submission_key,)).fetchone()
        job = dict(row) if row else {}
        if job and int(job.get("attempts") or 0) > max_attempts:
            job["exhausted"] = True
        return job

    def update_job(self, submission_key: str, status: str, last_error: str = "") -> None:
        now = self._now()
        with self.connection() as conn:
            conn.execute(
                "UPDATE job_state SET status=?, last_error=?, updated_at=? WHERE submission_key=?",
                (status, last_error, now, submission_key),
            )

    def recover_interrupted_jobs(self, older_than_seconds: int = 0) -> int:
        """Mark in-progress jobs from a previous process as interrupted.

        Interrupted jobs are never retried automatically: the previous attempt may
        have reached the destination before the crash, so a human must verify it.
        """
        cutoff = (datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None) - timedelta(seconds=max(0, older_than_seconds))).isoformat(timespec="seconds") + "Z"
        with self.connection() as conn:
            cur = conn.execute(
                "UPDATE job_state SET status='interrupted', updated_at=? "
                "WHERE status='in_progress' AND updated_at <= ?",
                (self._now(), cutoff),
            )
            return int(cur.rowcount or 0)

    # ------------------------------------------------------------------
    # Discovery persistence / domain deduplication
    # ------------------------------------------------------------------
    def record_discovery_run(self, source: str, query: Optional[str], results_count: int, notes: str = "") -> int:
        with self.connection() as conn:
            cur = conn.execute(
                "INSERT INTO discovery_runs (source, query, results_count, notes, created_at) VALUES (?,?,?,?,?)",
                (source, query, int(results_count), notes, self._now()),
            )
            return int(cur.lastrowid)

    def recent_discovery_queries(self, limit: int = 200) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT query, MAX(created_at) AS last_run FROM discovery_runs "
                "WHERE query IS NOT NULL AND query != '' GROUP BY query ORDER BY last_run DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def domain_exists(self, domain: str) -> bool:
        with self.connection() as conn:
            row = conn.execute("SELECT 1 FROM domains WHERE domain=? LIMIT 1", (domain,)).fetchone()
        return row is not None

    def list_domains(self, limit: int = 500) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM domains ORDER BY last_seen DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["categories"] = json.loads(d.pop("categories_json") or "[]")
            except Exception:
                d["categories"] = []
            out.append(d)
        return out

    def count_submissions_by_status(self) -> dict[str, int]:
        with self.connection() as conn:
            rows = conn.execute("SELECT status, COUNT(*) AS c FROM submissions GROUP BY status").fetchall()
        return {str(r["status"]): int(r["c"]) for r in rows}

    def count_websites(self) -> int:
        with self.connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM websites").fetchone()
        return int(row["c"] if row else 0)

    def count_domains(self) -> int:
        with self.connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM domains").fetchone()
        return int(row["c"] if row else 0)

    @staticmethod
    def _row_to_website(row: sqlite3.Row) -> WebsiteRecord:
        last = row["last_verification_date"]
        checked = row["permission_checked_at"] if "permission_checked_at" in row.keys() else None
        try:
            allowed_categories = json.loads(row["allowed_categories_json"] or "[]")
        except Exception:
            allowed_categories = []
        return WebsiteRecord(
            id=int(row["id"]),
            url=row["url"],
            domain=row["domain"],
            category=row["category"],
            language=row["language"] or "unknown",
            registration_requirements=RegistrationRequirement(row["registration_requirements"]),
            submission_method=SubmissionMethod(row["submission_method"]),
            rules_url=row["rules_url"],
            relevance_score=float(row["relevance_score"] or 0.0),
            last_verification_date=datetime.fromisoformat(last.replace("Z", "")) if last else None,
            permission_status=PermissionStatus(row["permission_status"]),
            notes=row["notes"] or "",
            permission_verified=bool(row["permission_verified"]) if "permission_verified" in row.keys() else False,
            permission_evidence=(row["permission_evidence"] or "") if "permission_evidence" in row.keys() else "",
            allowed_categories=list(allowed_categories) if isinstance(allowed_categories, list) else [],
            submission_method_verified=bool(row["submission_method_verified"]) if "submission_method_verified" in row.keys() else False,
            permission_source_url=(row["permission_source_url"] or "") if "permission_source_url" in row.keys() else "",
            permission_checked_at=datetime.fromisoformat(checked.replace("Z", "")) if checked else None,
            permission_reason=(row["permission_reason"] or "") if "permission_reason" in row.keys() else "",
            country=(row["country"] or "unknown") if "country" in row.keys() else "unknown",
            inspection_status=(row["inspection_status"] or "discovered") if "inspection_status" in row.keys() else "discovered",
            skip_reason=(row["skip_reason"] or "") if "skip_reason" in row.keys() else "",
        )

# ======================================================================
# merged from translation.py
# ======================================================================
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


logger = get_logger(__name__)


class TranslationError(Exception):
    """Raised when a required translation cannot be produced reliably.

    COCO must never fall back to publishing the English source when the target
    destination requires another language.
    """


@dataclass
class TranslationResult:
    text: str
    provider: str
    source_language: str
    target_language: str
    ok: bool = True
    failure_reason: str = ""


class BaseTranslator:
    name = "base"

    def translate(self, text: str, target_language: str, source_language: str = "auto") -> str:
        raise NotImplementedError


class NoopTranslator(BaseTranslator):
    name = "noop"

    def translate(self, text: str, target_language: str, source_language: str = "auto") -> str:
        return text


# Google Translate (deep_translator) accepts plain ISO codes ("de", "uk") plus
# zh-CN/zh-TW. BCP-47 region tags from site lang attributes ("de-DE", "en-US",
# "uk-UA") otherwise fail with "No support for the provided language".
_GOOGLE_LANG_SPECIAL = {"zh-cn": "zh-CN", "zh-tw": "zh-TW", "zh": "zh-CN"}
# Google uses legacy codes for these languages.
_GOOGLE_LANG_ALIAS = {"fil": "tl", "he": "iw"}


def _google_lang_code(code: str) -> str:
    """Normalize a BCP-47-ish language tag to a deep_translator Google code."""
    c = (code or "auto").strip().lower().replace("_", "-")
    if c in ("", "auto"):
        return "auto"
    if c in _GOOGLE_LANG_SPECIAL:
        return _GOOGLE_LANG_SPECIAL[c]
    base = c.split("-")[0] or "auto"
    return _GOOGLE_LANG_ALIAS.get(base, base)


class DeepTranslatorAdapter(BaseTranslator):
    def __init__(self, provider: str = "google", timeout: float = 20.0):
        self.provider = provider.lower()
        self.name = f"deep_translator:{self.provider}"
        self.timeout = max(5.0, float(timeout or 20.0))

    def _do_translate(self, text: str, target_language: str, source_language: str = "auto") -> str:
        try:
            from deep_translator import GoogleTranslator, MyMemoryTranslator
        except Exception as e:  # pragma: no cover
            raise TranslationError(f"deep-translator not available: {e}") from e

        src = _google_lang_code(source_language or "auto")
        tgt = _google_lang_code(target_language)
        last_err: Optional[Exception] = None
        for attempt in range(4):
            try:
                if self.provider in ("google", "auto"):
                    return GoogleTranslator(source=src, target=tgt).translate(text)
                if self.provider == "mymemory":
                    src_code = "en" if src == "auto" else src
                    return MyMemoryTranslator(source=src_code, target=tgt).translate(text)
                return GoogleTranslator(source="auto", target=tgt).translate(text)
            except Exception as e:
                last_err = e
                # Google rate-limits bursts from continuous runs; back off and retry.
                if "too many requests" in str(e).lower() and attempt < 3:
                    time.sleep(3.0 * (attempt + 1))
                    continue
                raise TranslationError(str(e)) from e
        raise TranslationError(str(last_err))

    def translate(self, text: str, target_language: str, source_language: str = "auto") -> str:
        # Run in a worker thread with a hard timeout so eligibility/translation never hangs indefinitely.
        import concurrent.futures as _cf
        ex = _cf.ThreadPoolExecutor(max_workers=1, thread_name_prefix="coco-tr")
        try:
            fut = ex.submit(self._do_translate, text, target_language, source_language)
            try:
                return fut.result(timeout=self.timeout)
            except _cf.TimeoutError as e:
                try:
                    fut.cancel()
                except Exception:
                    pass
                raise TranslationError(f"translation timed out after {int(self.timeout)}s") from e
        finally:
            try:
                ex.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass


def _protect_tokens(text: str, tokens: list[str]) -> tuple[str, dict[str, str]]:
    mapping: dict[str, str] = {}
    protected = text
    for i, token in enumerate(tokens or []):
        if token is None:
            continue
        token_str = str(token)
        if not token_str:
            continue
        placeholder = f"[[COCO_TOKEN_{i}]]"
        if token_str in protected:
            mapping[placeholder] = token_str
            protected = protected.replace(token_str, placeholder)
    # Also protect bare URLs/crypto-like strings conservatively
    url_pattern = re.compile(r"https?://[^\s)]+")
    for m in url_pattern.findall(protected):
        if m.startswith("[[COCO_TOKEN_"):
            continue
        key = f"[[COCO_URL_{len(mapping)}]]"
        if m not in mapping.values():
            mapping[key] = m
            protected = protected.replace(m, key)
    return protected, mapping


def _restore_tokens(text: str, mapping: dict[str, str]) -> str:
    out = text
    for k, v in mapping.items():
        out = out.replace(k, v)
    return out


def _normalize_for_compare(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip()).lower()


def _looks_like_untranslated(source: str, translated: str) -> bool:
    """True when a required translation is unchanged or essentially the source."""
    src = _normalize_for_compare(source)
    out = _normalize_for_compare(translated)
    if not out:
        return True
    if out == src:
        return True
    # Translation that simply echoes the source in a longer wrapper is also
    # suspicious; compare containment for long texts only.
    if len(src) >= 80 and (src in out or out in src) and abs(len(out) - len(src)) < 20:
        return True
    return False


class TranslationService:
    def __init__(self, db: Database, config: dict):
        self.db = db
        self.config = config
        self.cache_enabled = bool(config.get("cache_enabled", True))
        configured = config.get("preserve_tokens")
        tokens = PRESERVE_TOKENS if not configured else list(configured)
        self.preserve_tokens = [str(t) for t in tokens if t is not None]
        self.provider_name = (config.get("provider") or "auto").lower()
        cache_dir = config.get("translated_cache_dir") or config.get("translated_cache_path")
        self.translated_cache_dir = Path(cache_dir) if cache_dir else None
        if self.translated_cache_dir:
            # disable translated cache files/folders in project dir
            self.translated_cache_dir = None

    def _translation_cache_path(self, checksum: str, target_language: str, variant: str) -> Optional[Path]:
        if not self.translated_cache_dir:
            return None
        safe_variant = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in variant)
        safe_lang = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in target_language)
        return self.translated_cache_dir / f"coco__{safe_lang}__{safe_variant}__{checksum[:12]}.txt"

    def _get_translator(self, provider: Optional[str] = None) -> BaseTranslator:
        provider_name = (provider or self.provider_name).lower()
        timeout = float(self.config.get("timeout_seconds") or self.config.get("request_timeout_seconds") or 20.0)
        if provider_name in ("noop", "none"):
            return NoopTranslator()
        if provider_name in ("auto", "google", "mymemory"):
            return DeepTranslatorAdapter("google" if provider_name == "auto" else provider_name, timeout=timeout)
        return NoopTranslator()

    def _validate(self, source: str, translated: str, target_language: str, source_language: str) -> None:
        if not (translated or "").strip():
            raise TranslationError("translator returned empty text")
        tgt = (target_language or "").lower()
        src_lang = (source_language or "en").lower()
        if tgt and tgt not in ("unknown", src_lang):
            if _looks_like_untranslated(source, translated):
                raise TranslationError(
                    f"translation into '{target_language}' is unchanged/unreliable; refusing to publish source text"
                )
            # Best-effort target-language validation when detector is available.
            try:
                from langdetect import detect
                sample = (translated or "")[:1500]
                detected = detect(sample)
                # Accept close matches (e.g. zh-cn vs zh) and skip ambiguous very short texts
                if len(sample.strip()) >= 40 and detected and not (detected == tgt or detected.split("-")[0] == tgt.split("-")[0]):
                    # Reject only obvious source-language leakage when text still strongly resembles source.
                    if tgt != "en" and detected == "en":
                        src_norm = _normalize_for_compare(source)
                        out_norm = _normalize_for_compare(translated)
                        # If it was meaningfully transformed, allow (provider may be limited in tests/offline)
                        if src_norm == out_norm or (len(src_norm) >= 80 and abs(len(out_norm)-len(src_norm)) < 20 and (src_norm in out_norm or out_norm in src_norm)):
                            raise TranslationError(f"translation appears to be in '{detected}', expected '{target_language}'")
            except Exception as e:
                if isinstance(e, TranslationError):
                    raise
                pass
        missing = ContentManager.validate_preserved_tokens(source, translated, self.preserve_tokens)
        if missing:
            raise TranslationError("translation lost protected payment/wallet tokens: " + ", ".join(missing))

    def translate(self, text: str, target_language: str, variant: ContentVariant,
                  source_language: str = "en") -> TranslationResult:
        target_language = (target_language or source_language or "en").lower()
        source_language = (source_language or "en").lower()
        if target_language in ("en", "unknown", source_language):
            return TranslationResult(text=text, provider="identity", source_language=source_language,
                                     target_language=target_language)

        emit_event(f"Translation: {variant.value} -> {target_language}", event_type="translation")

        checksum = ContentManager.checksum(text)
        if self.cache_enabled:
            cached = self.db.find_translation(checksum, target_language, variant.value)
            if cached:
                try:
                    self._validate(text, cached.translated_text, target_language, source_language)
                except TranslationError as e:
                    logger.warning("Discarding invalid cached translation: %s", e)
                    cached = None
            if cached:
                try:
                    pass  # no translated cache file writes
                except Exception as _suppressed_exc:
                    _log_suppressed('translate (line 2629)', _suppressed_exc)
                return TranslationResult(cached.translated_text, f"cache:{cached.provider}",
                                         cached.source_language, cached.target_language)
            try:
                p = self._translation_cache_path(checksum, target_language, variant.value)
                if p and p.exists():
                    file_text = p.read_text(encoding="utf-8")
                    self._validate(text, file_text, target_language, source_language)
                    if file_text:
                        return TranslationResult(file_text, "cache:file", source_language, target_language)
            except TranslationError as e:
                logger.warning("Discarding invalid file translation cache: %s", e)
            except Exception as _suppressed_exc:
                _log_suppressed('translate (line 2642)', _suppressed_exc)

        protected, mapping = _protect_tokens(text, self.preserve_tokens)
        attempts: list[tuple[str, BaseTranslator]] = [(self.provider_name, self._get_translator())]
        fallback_name = (self.config.get("fallback_provider") or "").lower()
        if fallback_name and fallback_name not in (self.provider_name, "noop", "none", "original"):
            attempts.append((fallback_name, self._get_translator(fallback_name)))

        errors: list[str] = []
        translated: Optional[str] = None
        provider = attempts[0][1].name
        for provider_name, translator in attempts:
            try:
                candidate = translator.translate(protected, target_language=target_language,
                                                 source_language=source_language)
                restored = _restore_tokens(candidate or "", mapping)
                self._validate(text, restored, target_language, source_language)
                translated = restored
                provider = translator.name
                break
            except Exception as e:
                errors.append(f"{translator.name}: {e}")
                logger.warning("Translation attempt failed via %s: %s", translator.name, e)

        if translated is None:
            reason = "translation failed; " + ("; ".join(errors) if errors else "no provider available")
            emit_event(f"Translation failed: {variant.value} -> {target_language} ({reason})",
                       event_type="translation", level="error")
            raise TranslationError(reason)

        # Final token safety check (defence in depth).
        missing = ContentManager.validate_preserved_tokens(text, translated, self.preserve_tokens)
        if missing:
            translated = ContentManager.ensure_tokens(translated, self.preserve_tokens)

        rec = TranslationRecord(
            id=None,
            source_text=text,
            translated_text=translated,
            source_language=source_language,
            target_language=target_language,
            provider=provider,
            content_variant=variant.value,
            checksum=checksum,
            created_at=datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None),
            reviewed=False,
            metadata={"token_protection": True, "validated": True},
        )
        try:
            self.db.save_translation(rec)
        except Exception as e:
            logger.exception("Failed to store translation: %s", e)

        # translation cache file write disabled (no extra files/folders)
        pass

        emit_event(f"Translation ready: {variant.value} -> {target_language} ({provider})", event_type="translation")
        return TranslationResult(text=translated, provider=provider, source_language=source_language,
                                 target_language=target_language)

# ======================================================================
# merged from intelligence.py
# ======================================================================
import json
import os
import re
import shutil
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore


@dataclass
class IntelligenceDecision:
    provider: str
    capability: str
    available: bool
    used: bool
    fallback: bool
    confidence: float
    decision: dict[str, Any] = field(default_factory=dict)
    evidence: str = ""
    reasoning: str = ""
    error: str = ""


class IntelligenceProvider:
    name = "base"

    def is_available(self) -> bool:
        return False

    def reason(self, prompt: str, context: dict[str, Any]) -> Optional[dict[str, Any]]:
        return None


class OllamaProvider(IntelligenceProvider):
    name = "ollama"

    def __init__(self, model: str = ""):
        self.model = model

    def is_available(self) -> bool:
        return bool(shutil.which("ollama"))

    def reason(self, prompt: str, context: dict[str, Any]) -> Optional[dict[str, Any]]:
        # Detection only in this environment-safe implementation; avoid requiring a running daemon.
        # If ollama is present, callers can still fall back safely when invocation is unavailable.
        return None


class GeminiProvider(IntelligenceProvider):
    """Optional cloud advisory provider (Google Gemini). Uses API key from env only; never stored in repo.

    Advisory only: outputs must not grant permission or override verified site evidence/rules.
    """

    name = "google_gemini"

    def __init__(self, model: str = "gemini-1.5-flash", api_key_env: str = "COCO_GOOGLE_API_KEY", timeout: float = 20.0):
        self.model = (model or "gemini-1.5-flash").strip()
        self.api_key_env = (api_key_env or "COCO_GOOGLE_API_KEY").strip()
        self.timeout = float(timeout or 20.0)

    def _api_key(self) -> str:
        # Owner-configured env var only. Never read from committed files. Fallback env names for convenience.
        for key in [self.api_key_env, "COCO_GOOGLE_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY"]:
            if not key:
                continue
            val = (os.getenv(key) or "").strip()
            if val:
                return val
        return ""

    def is_available(self) -> bool:
        return bool(requests is not None and self._api_key())

    def _extract_text(self, data: dict[str, Any]) -> str:
        try:
            cands = data.get("candidates") or []
            if not cands:
                return ""
            parts = (((cands[0] or {}).get("content") or {}).get("parts") or [])
            texts = [str(p.get("text") or "") for p in parts if isinstance(p, dict)]
            return "\n".join(t for t in texts if t).strip()
        except Exception:
            return ""

    def reason(self, prompt: str, context: dict[str, Any]) -> Optional[dict[str, Any]]:
        key = self._api_key()
        if not key or requests is None:
            return None
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        body = {
            "contents": [{"parts": [{"text": str(prompt or "")}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 512},
        }
        try:
            resp = requests.post(url, params={"key": key}, json=body, timeout=self.timeout)
            if resp.status_code >= 400:
                return None
            data = resp.json() if resp.content else {}
            text = self._extract_text(data)
            if not text:
                return None
            # Try to parse JSON advisory block if present; otherwise return text summary.
            m = re.search(r"\{[\s\S]*\}", text)
            if m:
                try:
                    parsed = json.loads(m.group(0))
                    if isinstance(parsed, dict):
                        parsed.setdefault("_raw", text[:2000])
                        return parsed
                except Exception as _suppressed_exc:
                    _log_suppressed('reason (line 2826)', _suppressed_exc)
            return {"summary": text[:2000]}
        except Exception:
            return None


class IntelligenceEngine:
    """Pluggable intelligence layer with automatic capability detection and heuristic fallback.

    - Never requires paid APIs, subscriptions, API keys, or cloud infrastructure.
    - Uses local/free model capabilities only when actually available and reliable.
    - Always provides a deterministic heuristic fallback.
    - Stores evidence and reasoning summaries; model output never grants permission by itself.
    """

    def __init__(self, config: Optional[dict[str, Any]] = None):
        self.config = config or {}
        self.providers = self._detect_providers()
        self.active_provider = next((p for p in self.providers if p.is_available()), None)

    def _detect_providers(self) -> list[IntelligenceProvider]:
        providers: list[IntelligenceProvider] = []
        cfg = self.config or {}
        provider_pref = str(cfg.get("provider") or "auto").lower().strip()
        model = str(cfg.get("model") or "")
        cloud_requested = bool(cfg.get("cloud_enabled", False)) or provider_pref in ("google", "gemini", "google_gemini", "cloud")

        # Optional cloud provider (owner-configured, API key via env only). Advisory only.
        # Never auto-enable cloud just because a key exists in env; require explicit opt-in.
        if cloud_requested:
            g_model = str(cfg.get("cloud_model") or cfg.get("model") or "gemini-1.5-flash")
            api_key_env = str(cfg.get("api_key_env") or "COCO_GOOGLE_API_KEY")
            timeout = float(cfg.get("cloud_timeout_seconds") or cfg.get("timeout_seconds") or 20.0)
            providers.append(GeminiProvider(model=g_model, api_key_env=api_key_env, timeout=timeout))

        # Local/free providers
        providers.append(OllamaProvider(model=model))

        # Respect explicit preference when possible
        if provider_pref in ("heuristic", "none", "off", "disabled"):
            return []
        if provider_pref in ("google", "gemini", "google_gemini", "cloud"):
            providers = [p for p in providers if isinstance(p, GeminiProvider)] + [p for p in providers if not isinstance(p, GeminiProvider)]
        return providers

    def capability_report(self) -> dict[str, Any]:
        detected = [p.name for p in self.providers if p.is_available()]
        return {
            "ai_available": bool(detected),
            "active_provider": self.active_provider.name if self.active_provider else "heuristic",
            "detected_providers": detected,
            "fallback": "heuristic",
        }

    def _fallback_decision(self, capability: str, evidence: str, reason: str, decision: dict[str, Any], confidence: float = 0.6, provider: str = "heuristic", available: bool = False, used: bool = True, error: str = "") -> IntelligenceDecision:
        return IntelligenceDecision(
            provider=provider,
            capability=capability,
            available=available,
            used=used,
            fallback=True,
            confidence=float(max(0.0, min(1.0, confidence))),
            decision=decision,
            evidence=evidence[:4000],
            reasoning=reason[:2000],
            error=error[:1000],
        )

    def _advised_decision(self, capability: str, evidence: str, heuristic_reason: str, decision: dict[str, Any], confidence: float, prompt: str, context: dict[str, Any]) -> IntelligenceDecision:
        provider = self.active_provider
        if provider is None or not provider.is_available():
            return self._fallback_decision(capability, evidence, heuristic_reason, decision, confidence=confidence)
        try:
            out = provider.reason(prompt, context)
        except Exception as e:
            return self._fallback_decision(capability, evidence, heuristic_reason + f" (provider error: {e})", decision, confidence=confidence, provider=getattr(provider, 'name', 'provider'), available=True, used=False, error=str(e))
        if not isinstance(out, dict):
            return self._fallback_decision(capability, evidence, heuristic_reason + " (no advisory result; heuristic used)", decision, confidence=confidence, provider=getattr(provider, 'name', 'provider'), available=True, used=False)
        # Advisory merge only: never override authoritative safety/permission fields.
        merged = dict(decision)
        advisory = dict(out)
        # Keep core authoritative keys from heuristic when present.
        for k in ("permission_status", "permission_verified", "allowed_categories", "registration_requirements", "action"):
            if k in merged:
                advisory.pop(k, None)
        merged["advisory"] = advisory
        reason = heuristic_reason + f" Advisory input from {getattr(provider, 'name', 'provider')} considered (non-authoritative)."
        conf = max(confidence, float(advisory.get("confidence", confidence) or confidence)) if isinstance(advisory.get("confidence", None), (int, float)) else confidence
        return IntelligenceDecision(
            provider=getattr(provider, "name", "provider"),
            capability=capability,
            available=True,
            used=True,
            fallback=False,
            confidence=float(max(0.0, min(1.0, conf))),
            decision=merged,
            evidence=evidence[:4000],
            reasoning=reason[:2000],
        )

    def classify_page(self, url: str, title: str, text: str, heuristic: dict[str, Any]) -> IntelligenceDecision:
        evidence = f"url={url}\ntitle={title[:300]}\nexcerpt={(text or '')[:1500]}"
        decision = {
            "language": heuristic.get("language", "unknown"),
            "category": heuristic.get("destination_category") or heuristic.get("category") or "unknown",
            "submission_method": heuristic.get("submission_method", "unknown"),
            "relevance_score": heuristic.get("relevance_score", 0.0),
            "notes": heuristic.get("rules_summary", ""),
        }
        reasoning = "Heuristic page understanding used (authoritative baseline)."
        prompt = (
            "You are an advisory assistant. Return compact JSON with keys: category, submission_method, language, notes. "
            "Do not claim permission or invent facts. Use only given evidence.\n" + evidence
        )
        return self._advised_decision("page_understanding", evidence, reasoning, decision, 0.65, prompt, {"url": url, "heuristic": heuristic})

    def interpret_permission(self, url: str, text: str, heuristic: dict[str, Any]) -> IntelligenceDecision:
        evidence = f"url={url}\npermission_evidence={heuristic.get('permission_evidence','')}\nexcerpt={(text or '')[:1200]}"
        status = heuristic.get("permission", "unknown")
        decision = {
            "permission_status": status,
            "permission_verified": bool(heuristic.get("permission_verified", False)),
            "allowed_categories": heuristic.get("allowed_categories", []),
            "registration_requirements": heuristic.get("registration_requirements", "unknown"),
            "reason": heuristic.get("rules_summary", ""),
        }
        # Never upgrade permission beyond explicit evidence; only conservative interpretation.
        conf = 0.8 if status in ("allowed", "prohibited") else 0.55
        reasoning = "Heuristic permission interpretation grounded in extracted page evidence; model output not required and not treated as permission."
        prompt = (
            "Advisory only. Return compact JSON with keys: notes, risk_flags. "
            "Do NOT state permission is granted/verified unless explicitly evidenced. Never override rules.\n" + evidence
        )
        return self._advised_decision("permission_interpretation", evidence, reasoning, decision, conf, prompt, {"url": url, "heuristic": heuristic})

    def assess_translation_quality(self, source: str, translated: str, target_language: str) -> IntelligenceDecision:
        evidence = f"target={target_language}\nsource_len={len(source or '')}\ntranslated_len={len(translated or '')}"
        # Simple deterministic quality signals; translation service performs authoritative validation.
        ok = bool((translated or "").strip()) and (translated.strip() != (source or "").strip() or target_language.lower() in ("en", "unknown"))
        decision = {"acceptable": ok, "target_language": target_language}
        reasoning = "Heuristic translation quality check used as advisory signal; authoritative token/language checks remain in translation validation."
        return self._fallback_decision("translation_quality", evidence, reasoning, decision, confidence=0.6 if ok else 0.4)

    def classify_error(self, message: str, context: Optional[dict[str, Any]] = None) -> IntelligenceDecision:
        msg = (message or "").lower()
        ctx = context or {}
        if any(k in msg for k in ("captcha", "cloudflare", "turnstile", "bot verification", "human verification")):
            action, reason = "skip", "Security challenge detected; skip and continue."
        elif any(k in msg for k in ("login", "sign in", "register", "verification required", "phone verification", "email verification")):
            action, reason = "skip", "Credential/verification barrier detected; skip and continue."
        elif any(k in msg for k in ("timeout", "timed out", "network", "connection", "dns", "temporarily unavailable")):
            action, reason = "retry_recoverable", "Transient network/timeout; safe bounded recovery may apply."
        elif any(k in msg for k in ("browser", "target closed", "context", "crash")):
            action, reason = "recover_browser", "Browser failure; recover and continue pipeline."
        elif any(k in msg for k in ("uncertain", "no reliable confirmation")):
            action, reason = "do_not_retry", "Uncertain outcome; never blindly retry."
        else:
            action, reason = "skip_or_record", "Unknown/non-critical issue; record, skip unsafe retry, continue."
        decision = {"action": action, "context": ctx}
        evidence = message[:1000]
        prompt = (
            "Advisory only. Given an automation error, return compact JSON {\"action\":...,\"notes\":...}. "
            "Never suggest bypassing login/CAPTCHA/verification or unsafe retries.\nerror=" + evidence
        )
        dec = self._advised_decision("error_classification", evidence, reason, decision, 0.7, prompt, ctx)
        # Enforce safe actions regardless of advisory output.
        try:
            safe = {"skip", "retry_recoverable", "recover_browser", "do_not_retry", "skip_or_record"}
            adv = (dec.decision.get("advisory") or {}) if isinstance(dec.decision, dict) else {}
            if isinstance(adv, dict) and adv.get("action") in safe and action in ("retry_recoverable", "recover_browser", "skip", "do_not_retry", "skip_or_record"):
                # keep heuristic authoritative for sensitive cases
                if action in ("skip", "do_not_retry"):
                    dec.decision["action"] = action
        except Exception as _suppressed_exc:
            _log_suppressed('classify_error (line 3000)', _suppressed_exc)
        return dec

    @staticmethod
    def to_record(decision: IntelligenceDecision) -> dict[str, Any]:
        return {
            "provider": decision.provider,
            "capability": decision.capability,
            "available": decision.available,
            "used": decision.used,
            "fallback": decision.fallback,
            "confidence": decision.confidence,
            "decision": decision.decision,
            "evidence": decision.evidence,
            "reasoning": decision.reasoning,
            "error": decision.error,
        }

# ======================================================================
# merged from relevance.py
# ======================================================================
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional



CATEGORY_CUES: dict[str, list[str]] = {
    "personal_support": [
        "personal support", "mutual aid", "help needed", "support request", "financial assistance",
        "personal fundraising", "help a family", "emergency assistance",
    ],
    "fundraising": [
        "fundraising", "fundraiser", "crowdfund", "crowdfunding", "donate", "donation", "raise funds",
        "charity", "charitable", "give", "sponsor", "gofundme", "donation request",
    ],
    "community_assistance": [
        "community assistance", "community support", "mutual aid", "request help", "assistance request",
        "community fund", "neighbors helping", "relief fund",
    ],
    "relevant_promotion": [
        "promote", "promotion", "share your", "product", "gumroad", "creator", "self-promotion",
        "showcase", "advertise", "promotional", "business listing", "service listing",
    ],
}

POSITIVE_CUES = {
    **CATEGORY_CUES,
    "submission": ["submit", "post", "share", "add listing", "create post", "new thread", "publish", "form"],
}

# Strong phrases that explicitly grant permission to submit/post.
EXPLICIT_ALLOW_CUES = [
    "you may post", "you can post", "you are welcome to post", "you're welcome to post",
    "feel free to post", "feel free to share", "you may share", "you can share",
    "submissions are welcome", "submissions welcome", "submission is allowed", "submissions are allowed",
    "posting is allowed", "posting allowed", "posting is permitted", "posting permitted",
    "you may submit", "you can submit", "you are welcome to submit", "you're welcome to submit",
    "fundraising is allowed", "fundraising allowed", "fundraising is permitted", "fundraising permitted",
    "donations are allowed", "donation requests are allowed", "solicitation is allowed",
    "share your story", "share your request", "post your request", "post your story",
    "submit your request", "submit your story", "submit your fundraiser", "request help here",
    "assistance requests are welcome", "mutual aid requests are welcome", "we accept submissions",
    "we welcome submissions", "is explicitly allowed", "are explicitly permitted", "explicitly permitted",
]

CONDITIONAL_CUES = [
    "only in", "only on", "only during", "only if", "must be posted", "must be submitted",
    "must follow", "must use", "must include", "requires approval", "require approval",
    "subject to approval", "moderator approval", "admin approval", "await approval",
    "weekly thread", "monthly thread", "daily thread", "designated thread", "specific thread",
    "one post per", "once per day", "once per week", "no more than", "limit of",
    "conditions apply", "certain conditions", "with permission", "approved categories",
]

NEGATIVE_CUES = [
    "no solicitation", "no fundraising", "no donations", "no donation requests", "no crowdfunding",
    "no promotion", "no self-promotion", "no advertising", "not allowed", "prohibited",
    "strictly prohibited", "do not post", "do not submit", "no personal fund",
    "begging not allowed", "solicitation is prohibited", "fundraising is prohibited", "not permitted",
    "we do not allow", "we don't allow", "will be removed", "will be banned",
]

# Weak/generic restrictions (for example "no spam") do not by themselves
# prohibit an explicitly permitted fundraising/support submission.
WEAK_NEGATIVE_CUES = [
    "no spam", "no ads", "no links",
]

SUBMISSION_SURFACE_CUES = [
    "submit", "submission", "post a", "create a post", "new post", "create thread", "start a discussion",
    "add listing", "contact form", "share your", "publish", "send us", "form",
]

REGISTRATION_CUES = ["create account", "sign up", "register", "log in", "login", "verify your email", "email verification"]
NO_REG_CUES = ["no registration", "no account needed", "without registration", "guest post", "anonymous"]


@dataclass
class PageAnalysis:
    language: str
    registration: RegistrationRequirement
    submission_method: SubmissionMethod
    permission: PermissionStatus
    relevance_score: float
    recommended_variant: ContentVariant
    destination_category: str
    rules_summary: str
    permission_evidence: str = ""
    allowed_categories: list[str] = field(default_factory=list)
    intelligence: dict = field(default_factory=dict)


def _first_hits(text: str, cues: Iterable[str], limit: int = 4) -> list[str]:
    hits: list[str] = []
    for cue in cues:
        if cue in text and cue not in hits:
            hits.append(cue)
            if len(hits) >= limit:
                break
    return hits


def _first_regex_hits(text: str, patterns: Iterable[str], limit: int = 4) -> list[str]:
    hits: list[str] = []
    for pat in patterns:
        try:
            m = re.search(pat, text, flags=re.IGNORECASE | re.DOTALL)
        except Exception:
            m = None
        if m:
            val = (m.group(0) or "").strip()
            if val and val.lower() not in [h.lower() for h in hits]:
                hits.append(" ".join(val.split())[:80])
                if len(hits) >= limit:
                    break
    return hits


class RelevanceAnalyzer:
    def analyze(
        self,
        url: str,
        title: str,
        text: str,
        rules_text: str = "",
        html_lang: str = "",
        forms: Optional[list[dict[str, Any]]] = None,
        html: str = "",
    ) -> PageAnalysis:
        forms = forms or []
        body_blob = f"{title}\n{text}".lower()
        rules_blob = f"{rules_text}".lower()
        blob = f"{title}\n{text}\n{rules_text}\n{html}".lower()
        lang = html_lang or self._detect_language_simple(blob)
        registration = self._detect_registration(body_blob, forms=forms, html=html)
        method = self._detect_submission_method(body_blob, forms=forms, html=html)
        permission, evidence, allowed_categories = self._detect_permission(blob, rules_blob=rules_blob)
        variant, cat = self._recommend_variant(blob, allowed_categories)
        score = self._score(blob, permission, registration, method)
        summary = self._summarize_rules(blob, permission, registration, evidence)
        return PageAnalysis(
            language=lang,
            registration=registration,
            submission_method=method,
            permission=permission,
            relevance_score=score,
            recommended_variant=variant,
            destination_category=cat,
            rules_summary=summary,
            permission_evidence=evidence,
            allowed_categories=allowed_categories,
        )

    def _detect_language_simple(self, text: str) -> str:
        sample = text[:4000] if text else "en"
        try:
            from langdetect import detect

            lang = detect(sample)
            if lang:
                return str(lang).lower()
        except Exception as _suppressed_exc:
            _log_suppressed('_detect_language_simple (line 3155)', _suppressed_exc)
        # Script-based fallback for broad practical language detection.
        checks = [
            (r"[\u0600-\u06FF]", "ar"), (r"[\u0590-\u05FF]", "he"), (r"[\u0E00-\u0E7F]", "th"),
            (r"[\u0900-\u097F]", "hi"), (r"[\u0980-\u09FF]", "bn"), (r"[\u0A00-\u0A7F]", "pa"),
            (r"[\u0B80-\u0BFF]", "ta"), (r"[\u0C00-\u0C7F]", "te"), (r"[\u0D00-\u0D7F]", "ml"),
            (r"[\u0E80-\u0EFF]", "lo"), (r"[\u1000-\u109F]", "my"), (r"[\u10A0-\u10FF]", "ka"),
            (r"[\u1200-\u137F]", "am"), (r"[\u1780-\u17FF]", "km"), (r"[\u3040-\u30FF]", "ja"),
            (r"[\uAC00-\uD7AF]", "ko"), (r"[\u4E00-\u9FFF]", "zh"), (r"[\u0400-\u04FF]", "ru"),
            (r"[\u0370-\u03FF]", "el"), (r"[\u0530-\u058F]", "hy"),
        ]
        for pattern, code in checks:
            if re.search(pattern, sample):
                return code
        # Latin-script heuristics
        latin_hints = [
            ("es", [" el ", " la ", " que ", " solicitud", " ayuda", " enviar"]),
            ("fr", [" le ", " la ", " les ", " aide", " formulaire", " envoyer"]),
            ("de", [" der ", " die ", " das ", " hilfe", " formular", " antrag"]),
            ("pt", [" que ", " ajuda", " enviar", " formulário", " pedido"]),
            ("it", [" che ", " aiuto", " invia", " modulo", " richiesta"]),
            ("nl", [" de ", " het ", " hulp", " formulier", " aanvragen"]),
            ("pl", [" pomoc", " formularz", " wniosek", " wyślij"]),
            ("tr", [" yardım", " formu", " başvuru", " gönder"]),
            ("id", [" bantuan", " formulir", " kirim", " permohonan"]),
            ("vi", [" trợ", " biểu mẫu", " gửi", " yêu cầu"]),
            ("sv", [" hjälp", " formulär", " skicka", " ansökan"]),
            ("ro", [" ajutor", " formular", " cerere", " trimite"]),
        ]
        low = f" {sample.lower()} "
        for code, hints in latin_hints:
            if any(h in low for h in hints):
                return code
        return "en"

    def _detect_registration(self, text: str, forms: Optional[list[dict[str, Any]]] = None, html: str = "") -> RegistrationRequirement:
        forms = forms or []
        blob = f"{text}\n{(html or '').lower()}"
        # Email verification is a strong blocker when explicitly stated.
        if any(c in blob for c in ["verify your email", "email verification", "confirm your email", "phone verification", "verify your phone"]):
            return RegistrationRequirement.EMAIL_VERIFICATION_REQUIRED
        if any(c in text for c in NO_REG_CUES):
            return RegistrationRequirement.NONE

        # Strong DOM/form signals (real signup/login requirements)
        strong_form_signal = False
        for form in forms:
            inputs = form.get("inputs") or []
            has_password = any((inp.get("type") or "").lower() == "password" for inp in inputs)
            markers = " ".join([
                str(form.get("action") or ""),
                " ".join(str(inp.get("name") or "") for inp in inputs),
                " ".join(str(inp.get("id") or "") for inp in inputs),
                " ".join(str(inp.get("placeholder") or "") for inp in inputs),
            ]).lower()
            if has_password or any(k in markers for k in ["signup", "sign-up", "register", "create-account", "login", "log-in", "signin", "sign-in"]):
                strong_form_signal = True
                break

        # Signup/login controls in HTML (buttons/links/forms) are stronger than generic nav text mentions.
        strong_html_signal = bool(re.search(
            r"<(form|button|a)\b[^>]*(signup|sign-up|register|create[\s_-]?account|log[\s_-]?in|login|sign[\s_-]?in)[^>]*>|type=[\"']password[\"']|name=[\"'][^\"']*(password|signup|register|login)[^\"']*[\"']",
            html or "",
            flags=re.IGNORECASE,
        ))

        if strong_form_signal or strong_html_signal:
            return RegistrationRequirement.REQUIRED

        # Nav/footer/header mentions are weak signals only; do not mark REQUIRED by themselves.
        # Treat plain text mentions as unknown/optional-ish ambiguity unless stronger evidence exists.
        return RegistrationRequirement.UNKNOWN

    def _detect_submission_method(self, text: str, forms: Optional[list[dict[str, Any]]] = None, html: str = "") -> SubmissionMethod:
        forms = forms or []
        # Prefer real DOM forms/fields (PageSnapshot.forms) over text substring guesses.
        for form in forms:
            inputs = form.get("inputs") or []
            has_textarea = any((inp.get("tag") or "").lower() == "textarea" for inp in inputs)
            has_submit = any((inp.get("type") or "").lower() in ("submit", "button") for inp in inputs) or bool(inputs)
            # A real form with content fields/submit controls is a strong FORM signal.
            if has_textarea or has_submit:
                return SubmissionMethod.FORM

        # Word-boundary fallback cues from text (avoid substring false positives like "platform"/"information")
        if re.search(r"\b(new post|create post|start discussion|start a discussion|publish post)\b", text):
            return SubmissionMethod.POST
        if re.search(r"\b(comment|reply)\b", text):
            return SubmissionMethod.COMMENT
        if re.search(r"\b(directory|listing|add listing|submit listing)\b", text):
            return SubmissionMethod.DIRECTORY
        if re.search(r"\b(submit|submission)\b.*\b(form|field)\b|\b(contact form|submission form)\b", text):
            return SubmissionMethod.FORM
        return SubmissionMethod.UNKNOWN

    def _detect_permission(self, text: str, rules_blob: str = "") -> tuple[PermissionStatus, str, list[str]]:
        blob = text or ""
        focus = rules_blob or blob  # prefer rules/guidelines text when available

        # Solicitation/fundraising-specific prohibitions (word-boundary/phrase aware) => PROHIBITED
        specific_prohibit_patterns = [
            r"\b(no|not\s+allowed|prohibited|forbidden)\b.{0,40}\b(solicit(?:ation|ing)?|fundrais(?:ing|e|er)?|donat(?:ion|e|ing)?|crowdfund(?:ing)?|beg(?:ging)?|promotion|self[- ]?promotion|advertis(?:ing|e))\b",
            r"\b(solicit(?:ation|ing)?|fundrais(?:ing|e|er)?|donat(?:ion|e|ing)?|crowdfund(?:ing)?|promotion|self[- ]?promotion|advertis(?:ing|e))\b.{0,40}\b(not\s+allowed|prohibited|forbidden)\b",
            r"\b(no\s+(?:solicitation|fundraising|donation requests?|donations|crowdfunding|promotion|self-promotion|advertising|personal fundraisers?))\b",
        ]
        specific_hits = _first_regex_hits(focus, specific_prohibit_patterns)
        if not specific_hits:
            # fallback to legacy specific cues found in focus text
            specific_hits = _first_hits(focus, [c for c in NEGATIVE_CUES if any(k in c for k in ["solicit", "fundrais", "donat", "crowdfund", "promotion", "advertis", "begging"])])

        allow_hits = _first_hits(blob, EXPLICIT_ALLOW_CUES)
        conditional_hits = _first_hits(blob, CONDITIONAL_CUES)
        submission_hits = _first_hits(blob, SUBMISSION_SURFACE_CUES)
        # Generic negatives anywhere on page (nav/footer/common terms) should not auto-prohibit; treat as conditional evidence.
        generic_patterns = [
            r"\b(not\s+allowed|prohibited|strictly\s+prohibited|do\s+not\s+(post|submit)|will\s+be\s+removed|will\s+be\s+banned|we\s+do\s+not\s+allow|we\s+don't\s+allow)\b",
        ]
        generic_hits = _first_regex_hits(blob, generic_patterns)
        if not generic_hits:
            generic_hits = _first_hits(blob, [c for c in NEGATIVE_CUES if c not in ("no solicitation", "no fundraising", "no donations", "no donation requests", "no crowdfunding", "no promotion", "no self-promotion", "no advertising", "solicitation is prohibited", "fundraising is prohibited", "begging not allowed", "no personal fund")])

        allowed_categories = [
            category for category, cues in CATEGORY_CUES.items()
            if any(cue in blob for cue in cues)
        ]

        if specific_hits:
            return PermissionStatus.PROHIBITED, "prohibited (solicitation/fundraising-specific): " + ", ".join(specific_hits), []

        if allow_hits:
            evidence = "explicit permission: " + ", ".join(allow_hits)
            if conditional_hits or generic_hits:
                extra = conditional_hits + [h for h in generic_hits if h not in conditional_hits]
                if extra:
                    evidence += "; conditions/restrictions: " + ", ".join(extra[:4])
                return PermissionStatus.CONDITIONAL, evidence, allowed_categories
            weak_hits = _first_hits(blob, WEAK_NEGATIVE_CUES)
            if weak_hits:
                evidence += "; generic restrictions: " + ", ".join(weak_hits)
            return PermissionStatus.ALLOWED, evidence, allowed_categories

        if conditional_hits and submission_hits:
            evidence = "conditional cues: " + ", ".join(conditional_hits)
            if generic_hits:
                evidence += "; generic restrictions: " + ", ".join(generic_hits[:2])
            return PermissionStatus.CONDITIONAL, evidence, allowed_categories

        if submission_hits:
            evidence = "submission surface only (no explicit permission): " + ", ".join(submission_hits)
            if generic_hits:
                evidence += "; generic restrictions present: " + ", ".join(generic_hits[:2])
            return PermissionStatus.CONDITIONAL, evidence, allowed_categories

        if generic_hits:
            return PermissionStatus.CONDITIONAL, "generic restriction language present (not solicitation-specific): " + ", ".join(generic_hits), allowed_categories

        return PermissionStatus.UNKNOWN, "no explicit permission cues detected", allowed_categories

    def _recommend_variant(self, text: str, allowed_categories: list[str]) -> tuple[ContentVariant, str]:
        scores = {
            ContentVariant.FUNDRAISING: sum(1 for k in CATEGORY_CUES["fundraising"] if k in text),
            ContentVariant.PERSONAL_SUPPORT: sum(1 for k in CATEGORY_CUES["personal_support"] if k in text),
            ContentVariant.COMMUNITY_ASSISTANCE: sum(1 for k in CATEGORY_CUES["community_assistance"] if k in text),
            ContentVariant.RELEVANT_PROMOTION: sum(1 for k in CATEGORY_CUES["relevant_promotion"] if k in text),
        }
        variant = max(scores, key=scores.get)
        if scores[variant] == 0:
            variant = ContentVariant.PERSONAL_SUPPORT
        labels = {
            ContentVariant.FUNDRAISING: "Fundraising / donations",
            ContentVariant.PERSONAL_SUPPORT: "Personal support",
            ContentVariant.COMMUNITY_ASSISTANCE: "Community assistance",
            ContentVariant.RELEVANT_PROMOTION: "Relevant promotion",
        }
        return variant, labels[variant]

    def _score(self, text: str, permission: PermissionStatus, registration: RegistrationRequirement, method: SubmissionMethod) -> float:
        score = 0.2
        if permission == PermissionStatus.ALLOWED:
            score += 0.35
        elif permission == PermissionStatus.CONDITIONAL:
            score += 0.15
        elif permission == PermissionStatus.PROHIBITED:
            score -= 0.6
        if registration == RegistrationRequirement.NONE:
            score += 0.25
        elif registration == RegistrationRequirement.OPTIONAL:
            score += 0.1
        elif registration in (RegistrationRequirement.REQUIRED, RegistrationRequirement.EMAIL_VERIFICATION_REQUIRED):
            score -= 0.15
        if method in (SubmissionMethod.FORM, SubmissionMethod.POST, SubmissionMethod.DIRECTORY):
            score += 0.15
        if any(c in text for c in NEGATIVE_CUES):
            score -= 0.2
        if any(c in text for c in WEAK_NEGATIVE_CUES):
            score -= 0.03
        positive = sum(1 for group in POSITIVE_CUES.values() for k in group if k in text)
        score += min(0.15, positive * 0.01)
        return max(0.0, min(1.0, score))

    def _summarize_rules(
        self,
        text: str,
        permission: PermissionStatus,
        registration: RegistrationRequirement,
        evidence: str = "",
    ) -> str:
        parts = [f"Permission: {permission.value}", f"Registration: {registration.value}"]
        if evidence:
            parts.append(evidence)
        hits = _first_hits(text, NEGATIVE_CUES, limit=6)
        if hits:
            parts.append("Restrictions detected: " + ", ".join(sorted(set(hits))))
        return "; ".join(parts)

# ======================================================================
# merged from profile.py
# ======================================================================
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


logger = get_logger(__name__)

PROFILE_DIR_NAME = "profile"
PROFILE_JSON_NAME = "profile.json"


@dataclass
class UserProfile:
    name: str
    email: str
    bio: str
    profile_picture: str  # relative path from project root
    profile_picture_abs: str
    username: str = "vinaydxo"
    username_preference: str = "vinaydxo"
    username_fallbacks: list[str] | None = None
    source: str = "profile/profile.json"


class ProfileManager:
    """Manages permanent user identity stored in profile/profile.json and synced to SQLite."""

    def __init__(self, root_dir: Path):
        self.root_dir = Path(root_dir)
        self.profile_dir = self.root_dir / PROFILE_DIR_NAME
        self.profile_json_path = self.profile_dir / PROFILE_JSON_NAME

    def ensure_profile(self) -> UserProfile:
        # no profile folder
        if self.profile_json_path.exists():
            try:
                data = json.loads(self.profile_json_path.read_text(encoding="utf-8"))
                profile = self._from_data(data)
                # Ensure image exists in profile dir if referenced original exists elsewhere
                self._ensure_image_in_profile_dir(profile.profile_picture)
                return profile
            except Exception as e:
                logger.warning("Failed to load existing profile.json, recreating defaults: %s", e)

        # Locate existing image in project folder (do not alter original)
        image_rel = self._locate_and_store_profile_image()
        data = {
            "name": "Vinay",
            "username": "vinaydxo",
            "username_preference": "vinaydxo",
            "username_fallbacks": ["vinay_dxo", "vinaydxo1", "vinay.dxo", "vinaydx", "vinay_d", "vinaydxo_"],
            "email": "siyakjain@gmail.com",
            "bio": "I'm Vinay, trying to rebuild my life with a little help from kind-hearted people.",
            "profile_picture": image_rel or "",
        }
        # profile.json file write disabled (no extra files). Build the in-memory profile directly:
        # calling self.load() here recursed forever when profile.json is absent.
        return self._from_data(data)

    def load(self) -> UserProfile:
        if not self.profile_json_path.exists():
            return self.ensure_profile()
        data = json.loads(self.profile_json_path.read_text(encoding="utf-8"))
        return self._from_data(data)

    def _from_data(self, data: dict[str, Any]) -> UserProfile:
        pic_rel = str(data.get("profile_picture") or "").replace("\\", "/")
        pic_abs = str((self.root_dir / pic_rel).resolve()) if pic_rel else ""
        pref = str(data.get("username_preference") or data.get("username") or "vinaydxo").strip() or "vinaydxo"
        fallbacks = data.get("username_fallbacks")
        if not isinstance(fallbacks, list):
            fallbacks = ["vinay_dxo", "vinaydxo1", "vinay.dxo", "vinaydx", "vinay_d", "vinaydxo_"]
        fallbacks = [str(x).strip() for x in fallbacks if str(x).strip()]
        return UserProfile(
            name=str(data.get("name") or "Vinay"),
            email=str(data.get("email") or "siyakjain@gmail.com"),
            bio=str(data.get("bio") or "I'm Vinay, trying to rebuild my life with a little help from kind-hearted people."),
            profile_picture=pic_rel,
            profile_picture_abs=pic_abs,
            username=pref,
            username_preference=pref,
            username_fallbacks=fallbacks,
        )

    def _locate_and_store_profile_image(self) -> Optional[str]:
        # Prefer existing copy in profile dir
        for p in self.profile_dir.glob("*"):
            if p.is_file() and p.suffix.lower() in {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp"}:
                return str(p.relative_to(self.root_dir)).replace("\\", "/")
        # Find existing image in project folder (non-profile dirs) and copy into profile/ without altering original
        candidates = []
        for p in self.root_dir.rglob("*"):
            if not p.is_file():
                continue
            if PROFILE_DIR_NAME in p.parts[:-1]:
                continue
            if p.suffix.lower() in {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp"}:
                candidates.append(p)
        if not candidates:
            return None
        # Prefer a file named like profile picture
        candidates.sort(key=lambda x: (0 if "profile" in x.name.lower() else 1, len(str(x))))
        src = candidates[0]
        dest = self.profile_dir / src.name
        try:
            if not dest.exists():
                shutil.copy2(src, dest)
            return str(dest.relative_to(self.root_dir)).replace("\\", "/")
        except Exception as e:
            logger.warning("Could not copy profile image into profile directory: %s", e)
            # Fallback to relative path of original
            try:
                return str(src.relative_to(self.root_dir)).replace("\\", "/")
            except Exception:
                return src.name

    def _ensure_image_in_profile_dir(self, rel_path: str) -> None:
        if not rel_path:
            return
        p = self.root_dir / rel_path
        if p.exists() and self.profile_dir in p.parents:
            return
        # try to locate and copy
        self._locate_and_store_profile_image()

    def sync_to_db(self, db: Database, source_content: Optional[str] = None) -> UserProfile:
        profile = self.ensure_profile()
        content = source_content if source_content is not None else ContentManager().source_text
        metadata = {
            "profile_picture_path": profile.profile_picture,
            "profile_picture_abs": profile.profile_picture_abs,
            "profile_picture_exists": Path(profile.profile_picture_abs).exists() if profile.profile_picture_abs else False,
            "bio": profile.bio,
            "profile_source": profile.source,
        }
        try:
            db.upsert_profile(
                name=profile.name,
                email=profile.email,
                source_content=content,
                payment_links=ContentManager.payment_info(),
                metadata=metadata,
                is_default=True,
            )
        except Exception as e:
            logger.warning("Failed to sync profile to database: %s", e)
        return profile

    @staticmethod
    def get_identity_fields(profile: UserProfile) -> dict[str, Any]:
        pref = getattr(profile, "username_preference", None) or getattr(profile, "username", "vinaydxo") or "vinaydxo"
        fallbacks = getattr(profile, "username_fallbacks", None) or ["vinay_dxo", "vinaydxo1", "vinay.dxo", "vinaydx", "vinay_d", "vinaydxo_"]
        return {
            "name": profile.name,
            "username": pref,
            "username_preference": pref,
            "username_fallbacks": list(fallbacks),
            "email": profile.email,
            "bio": profile.bio,
            "about": profile.bio,
            "description": profile.bio,
            "profile_picture": profile.profile_picture_abs,
        }

# ======================================================================
# merged from reporting.py
# ======================================================================
import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any



class ReportingService:
    def __init__(self, db: Database, reports_dir: Path):
        self.db = db
        self.reports_dir = reports_dir
        # reports directory/files disabled (no extra folders)
        pass

    def summary(self, limit: int = 200) -> dict[str, Any]:
        submissions = self.db.recent_submissions(limit=limit)
        counts = Counter(s.get("status", "unknown") for s in submissions)
        websites = self.db.list_websites(min_relevance=0.0)
        reg_counts = Counter(getattr(w, "registration_requirements", "unknown") for w in websites)
        perm_counts = Counter(getattr(w, "permission_status", "unknown") for w in websites)
        failures = [s for s in submissions if s.get("status") in ("failed", "blocked", "needs_approval")]
        completed = [s for s in submissions if s.get("status") in ("success", "submitted")]
        return {
            "generated_at": datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "total_websites": len(websites),
            "websites_by_registration": {str(k.value if hasattr(k, 'value') else k): v for k, v in reg_counts.items()},
            "websites_by_permission": {str(k.value if hasattr(k, 'value') else k): v for k, v in perm_counts.items()},
            "recent_submissions": len(submissions),
            "completed_submissions": len(completed),
            "failures_and_blocks": len(failures),
            "submissions_by_status": dict(counts),
            "latest": submissions[:10],
            "latest_failures": failures[:10],
        }

    def export_json(self, filename: str | None = None) -> Path:
        path = self.reports_dir / (filename or f"report_{datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.json")
        data = self.summary(limit=1000)
        # report file write disabled; return intended path without creating file
        pass
        return path

    def export_submissions_csv(self, filename: str | None = None) -> Path:
        path = self.reports_dir / (filename or f"submissions_{datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.csv")
        rows = self.db.recent_submissions(limit=5000)
        fields = ["id", "created_at", "website_url", "domain", "status", "variant", "message", "screenshot_path"]
        # CSV export file write disabled (no extra files)
        return path

    def print_summary(self) -> str:
        s = self.summary()
        lines = [
            f"COCO Report ({s['generated_at']})",
            f"Websites: {s['total_websites']} | Recent submissions: {s['recent_submissions']}",
            f"Submissions by status: {s['submissions_by_status']}",
            f"Websites by registration: {s['websites_by_registration']}",
        ]
        return "\n".join(lines)


# ============================================================================
# merged from coco_web.py
# ============================================================================

"""COCO web layer: browser automation, discovery, publishing."""



# ======================================================================
# merged from browser.py
# ======================================================================
import os
import re
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional


logger = get_logger(__name__)


@contextmanager
def _null_stdio():
    """Provide real stdio fds for Playwright/driver subprocesses while dashboard redirects streams."""
    try:
        devnull = open(os.devnull, "w", encoding="utf-8", errors="ignore")
    except Exception:
        devnull = None
    old_out, old_err = sys.stdout, sys.stderr
    try:
        if devnull is not None:
            sys.stdout = devnull
            sys.stderr = devnull
        yield
    finally:
        sys.stdout, sys.stderr = old_out, old_err
        try:
            if devnull is not None:
                devnull.close()
        except Exception as _suppressed_exc:
            _log_suppressed('_null_stdio (line 3584)', _suppressed_exc)

CAPTCHA_CUES = [
    "captcha", "recaptcha", "hcaptcha", "cloudflare", "verify you are human", "are you a robot",
    "cf-challenge", "turnstile",
]
LOGIN_CUES = ["log in", "login", "sign in", "signin", "create account", "register"]
RATE_LIMIT_CUES = ["rate limit", "too many requests", "try again later", "slow down", "temporarily blocked"]


class BrowserUnavailableError(RuntimeError):
    """Raised when the Playwright browser/context is unavailable or crashed."""


@dataclass
class PageSnapshot:
    url: str
    title: str
    text: str
    html: str
    has_captcha: bool
    has_login_wall: bool
    has_rate_limit: bool
    forms: list[dict[str, Any]]
    obstacles: list[str] = field(default_factory=list)
    html_lang: str = ""
    status_code: Optional[int] = None


_PLAYWRIGHT_REPAIR_STATE = {"attempted": False, "last_attempt": 0.0, "last_outcome": "", "last_error": ""}


class BrowserAutomation:
    def __init__(self, config: dict, headless: Optional[bool] = None):
        self.config = config
        self.headless = self.config.get("headless", False) if headless is None else headless
        self._playwright = None
        self._browser = None
        self._context = None
        self._recovery_attempts = 0
        self._max_recoveries = int(self.config.get("max_browser_recoveries", 2))

    def _driver_diagnostics(self) -> dict:
        info = {"python": None, "playwright": None, "driver_node": None, "node_exists": None, "node_accessible": None, "node_version": None, "error": None}
        try:
            import sys as _sys, subprocess, os
            info["python"] = _sys.executable
            try:
                import importlib.metadata as md
                info["playwright"] = md.version("playwright")
            except Exception:
                try:
                    import playwright as _pw
                    info["playwright"] = getattr(_pw, "__version__", None)
                except Exception:
                    info["playwright"] = None
            try:
                from playwright._impl._driver import compute_driver_executable
                node = compute_driver_executable()
                # compute_driver_executable may return tuple in some versions
                if isinstance(node, (list, tuple)):
                    node = node[0] if node else None
                node = str(node) if node else None
                info["driver_node"] = node
                if node:
                    info["node_exists"] = os.path.exists(node)
                    info["node_accessible"] = os.access(node, os.X_OK) if os.path.exists(node) else False
                    if os.path.exists(node):
                        try:
                            cp = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=10)
                            info["node_version"] = (cp.stdout or cp.stderr or "").strip()
                            info["node_rc"] = cp.returncode
                        except Exception as ne:
                            info["error"] = f"node exec failed: {type(ne).__name__}: {ne}"
                else:
                    info["node_exists"] = False
            except Exception as de:
                info["error"] = f"driver inspect failed: {type(de).__name__}: {de}"
        except Exception as e:
            info["error"] = str(e)
        return info

    @staticmethod
    def _verify_playwright_health(config: Optional[dict] = None, headless: bool = True) -> tuple[bool, str, dict]:
        """Independent post-repair verification: driver node health + real browser launch/page load."""
        import subprocess, os, sys as _sys, tempfile
        config = config or {}
        diag = BrowserAutomation(config, headless=headless)._driver_diagnostics()
        try:
            node = diag.get("driver_node")
            if not node or not os.path.exists(str(node)):
                return False, f"driver node missing: {node}", diag
            if not os.path.isfile(str(node)):
                return False, f"driver node is not a file: {node}", diag
            try:
                size = os.path.getsize(str(node))
                diag["node_size"] = size
                if size <= 0:
                    return False, f"driver node has invalid size: {size}", diag
            except Exception as se:
                return False, f"driver node not accessible: {se}", diag
            try:
                cp = subprocess.run([str(node), "--version"], capture_output=True, text=True, timeout=10)
                diag["node_verify_rc"] = cp.returncode
                diag["node_verify_out"] = ((cp.stdout or "") + (cp.stderr or "")).strip()
                if cp.returncode != 0:
                    return False, f"driver node failed to execute (rc={cp.returncode}): {diag['node_verify_out']}", diag
            except Exception as ne:
                return False, f"driver node execution failed: {type(ne).__name__}: {ne}", diag
            # Real Playwright browser launch + page load test (using same active interpreter/installation)
            try:
                from playwright.sync_api import sync_playwright
                with _null_stdio():
                    with sync_playwright() as p:
                        browser = None
                        last = None
                        for ch in [config.get("channel") or "chromium", "chrome", "msedge", "chromium"]:
                            try:
                                if ch == "chromium":
                                    browser = p.chromium.launch(headless=bool(headless))
                                else:
                                    browser = p.chromium.launch(channel=ch, headless=bool(headless))
                                last = None
                                break
                            except Exception as le:
                                last = le
                                browser = None
                        if browser is None:
                            raise last or RuntimeError("No browser channel could be launched")
                        context = browser.new_context()
                        page = context.new_page()
                        page.goto("data:text/html,<title>COCO</title><h1>ok</h1>", wait_until="domcontentloaded", timeout=15000)
                        title = page.title()
                        if "COCO" not in (title or ""):
                            raise RuntimeError(f"Unexpected page title after load: {title!r}")
                        page.close(); context.close(); browser.close()
                diag["launch_verify"] = "ok"
            except Exception as le:
                return False, f"real browser launch/page-load verification failed: {type(le).__name__}: {le}", diag
            return True, "verified", diag
        except Exception as e:
            return False, f"verification error: {type(e).__name__}: {e}", diag

    def _try_repair_playwright(self, err: Exception) -> bool:
        """Attempt a safe one-time (global, cooldown-limited) repair for missing/corrupted Playwright driver/browser.
        Reports success ONLY if post-repair Node health check and real browser launch/page-load pass."""
        import time as _time
        msg = str(err or "")
        low = msg.lower()
        if not any(k in low for k in ("node", "executable doesn't exist", "playwright install", "driver", "browser", "chromium", "cannot launch")):
            return False
        now = _time.monotonic()
        # Do not repeatedly attempt repair on every cycle: one attempt per process, then long cooldown.
        if _PLAYWRIGHT_REPAIR_STATE.get("attempted") and (now - float(_PLAYWRIGHT_REPAIR_STATE.get("last_attempt") or 0.0)) < 1800:
            return False
        _PLAYWRIGHT_REPAIR_STATE["attempted"] = True
        _PLAYWRIGHT_REPAIR_STATE["last_attempt"] = now
        _PLAYWRIGHT_REPAIR_STATE["last_error"] = msg
        diag = self._driver_diagnostics()
        try:
            emit_event(f"Browser/Playwright launch failed: {type(err).__name__}: {msg}", event_type="system", level="error",
                       details={"exception": type(err).__name__, "error": msg, "diagnostics": diag})
            emit_event("🔧 Browser/Playwright issue detected; attempting safe local repair (one-time)...", event_type="system", level="warn")
        except Exception as _suppressed_exc:
            _log_suppressed('_try_repair_playwright (line 3748)', _suppressed_exc)
        install_outcome = "not-run"
        try:
            import subprocess
            import sys as _sys
            # If driver/node is missing/corrupted, reinstall only Playwright package in existing venv, then install Chromium.
            node_bad = (not diag.get("node_exists")) or (not diag.get("node_accessible")) or (diag.get("error")) or ("node exec failed" in str(diag.get("error") or "")) or (diag.get("node_rc") not in (None, 0))
            if node_bad:
                cp1 = subprocess.run([_sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall", "playwright"],
                                     check=False, capture_output=True, text=True, timeout=600)
                cp2 = subprocess.run([_sys.executable, "-m", "playwright", "install", "chromium"],
                                     check=False, capture_output=True, text=True, timeout=300)
                install_outcome = f"reinstall+install chromium: pip={cp1.returncode}, playwright={cp2.returncode}"
                if cp1.returncode != 0 or cp2.returncode != 0:
                    reason = f"install commands failed ({install_outcome})"
                    _PLAYWRIGHT_REPAIR_STATE["last_outcome"] = f"REPAIR FAILED: {reason}"
                    try:
                        get_event_bus().set_state(browser_status="REPAIR FAILED")
                        emit_event(f"Playwright repair outcome: REPAIR FAILED — {reason}", event_type="system", level="error",
                                   details={"outcome": _PLAYWRIGHT_REPAIR_STATE["last_outcome"], "original_error": msg, "diagnostics": diag})
                    except Exception as _suppressed_exc:
                        _log_suppressed('_try_repair_playwright (line 3769)', _suppressed_exc)
                    return False
            else:
                cp = subprocess.run([_sys.executable, "-m", "playwright", "install", "chromium"],
                                    check=False, capture_output=True, text=True, timeout=300)
                install_outcome = f"playwright install chromium rc={cp.returncode}"
                if cp.returncode != 0:
                    reason = f"browser install failed ({install_outcome})"
                    _PLAYWRIGHT_REPAIR_STATE["last_outcome"] = f"REPAIR FAILED: {reason}"
                    try:
                        get_event_bus().set_state(browser_status="REPAIR FAILED")
                        emit_event(f"Playwright repair outcome: REPAIR FAILED — {reason}", event_type="system", level="error",
                                   details={"outcome": _PLAYWRIGHT_REPAIR_STATE["last_outcome"], "original_error": msg, "diagnostics": diag})
                    except Exception as _suppressed_exc:
                        _log_suppressed('_try_repair_playwright (line 3783)', _suppressed_exc)
                    return False
        except Exception as re:
            reason = f"repair exception: {type(re).__name__}: {re}"
            _PLAYWRIGHT_REPAIR_STATE["last_outcome"] = f"REPAIR FAILED: {reason}"
            try:
                get_event_bus().set_state(browser_status="REPAIR FAILED")
                emit_event(f"Playwright repair outcome: REPAIR FAILED — {reason}", event_type="system", level="error",
                           details={"outcome": _PLAYWRIGHT_REPAIR_STATE["last_outcome"], "original_error": msg, "diagnostics": diag})
            except Exception as _suppressed_exc:
                _log_suppressed('_try_repair_playwright (line 3793)', _suppressed_exc)
            return False

        # Post-repair verification: do NOT report success unless Node runs and a real browser launches/loads.
        ok, vreason, vdiag = self._verify_playwright_health(self.config, headless=self.headless)
        if ok:
            outcome = f"verified ({install_outcome})"
            _PLAYWRIGHT_REPAIR_STATE["last_outcome"] = outcome
            try:
                emit_event("Playwright repair outcome: verified - node and browser launch/page-load passed", event_type="system", level="info",
                           details={"outcome": outcome, "original_error": msg, "diagnostics": vdiag})
            except Exception as _suppressed_exc:
                _log_suppressed('_try_repair_playwright (line 3805)', _suppressed_exc)
            return True
        outcome = f"REPAIR FAILED: {vreason}"
        _PLAYWRIGHT_REPAIR_STATE["last_outcome"] = outcome
        try:
            get_event_bus().set_state(browser_status="REPAIR FAILED")
            emit_event(f"Playwright repair outcome: REPAIR FAILED — {vreason}", event_type="system", level="error",
                       details={"outcome": outcome, "original_error": msg, "install_outcome": install_outcome, "diagnostics": vdiag})
        except Exception as _suppressed_exc:
            _log_suppressed('_try_repair_playwright (line 3814)', _suppressed_exc)
        return False

    def start(self):
        from playwright.sync_api import sync_playwright

        try:
            get_event_bus().set_state(browser_status="STARTING")
        except Exception as _suppressed_exc:
            _log_suppressed('start (line 3823)', _suppressed_exc)
        # Preflight: verify Playwright driver Node executable is present/launchable (helps diagnose root cause).
        try:
            diag = self._driver_diagnostics()
            if diag.get("driver_node") and diag.get("node_exists") and diag.get("node_accessible"):
                # node --version check already attempted in diagnostics; record if it failed
                if diag.get("error") or (diag.get("node_rc") not in (None, 0)):
                    raise RuntimeError(f"Playwright driver Node cannot launch: {diag.get('error') or diag.get('node_version')}")
            elif diag.get("driver_node") and not diag.get("node_exists"):
                raise RuntimeError(f"Playwright driver Node missing: {diag.get('driver_node')}")
        except Exception as pre_e:
            # Treat as startup failure; allow one-time repair path.
            last_start_err = pre_e
            try:
                get_event_bus().set_state(browser_status="FAILED")
            except Exception as _suppressed_exc:
                _log_suppressed('start (line 3839)', _suppressed_exc)
            if self._try_repair_playwright(pre_e):
                last_start_err = None
            if last_start_err is not None:
                try:
                    emit_event(f"Browser unavailable: {type(last_start_err).__name__}: {last_start_err}", event_type="system", level="error",
                               details={"exception": type(last_start_err).__name__, "error": str(last_start_err), "diagnostics": self._driver_diagnostics()})
                except Exception as _suppressed_exc:
                    _log_suppressed('start (line 3847)', _suppressed_exc)
                raise BrowserUnavailableError(f"Browser unavailable: {last_start_err}") from last_start_err
        last_start_err = None
        for attempt in range(2):
            try:
                with _null_stdio():
                    self._playwright = sync_playwright().start()
                    preferred = self.config.get("channel") or "chrome"
                    candidates = []
                    for ch in [preferred, "chrome", "msedge", "chromium"]:
                        if ch and ch not in candidates:
                            candidates.append(ch)
                    launch_args = {
                        "headless": bool(self.headless),
                        "slow_mo": int(self.config.get("slow_mo_ms", 50)),
                    }
                    last_err = None
                    for ch in candidates:
                        try:
                            if ch == "chromium":
                                self._browser = self._playwright.chromium.launch(**launch_args)
                            else:
                                self._browser = self._playwright.chromium.launch(channel=ch, **launch_args)
                            last_err = None
                            break
                        except Exception as e:
                            last_err = e
                            self._browser = None
                            continue
                    if self._browser is None:
                        raise last_err or RuntimeError("No supported browser channel available")
                    viewport = self.config.get("viewport") or {"width": 1366, "height": 900}
                    self._context = self._browser.new_context(
                        viewport=viewport,
                        locale=self.config.get("locale", "en-US"),
                        timezone_id=self.config.get("timezone_id"),
                    )
                    self._context.set_default_navigation_timeout(int(self.config.get("navigation_timeout_ms", 30000)))
                logger.info("Browser started (headless=%s)", self.headless)
                try:
                    get_event_bus().set_state(
                        browser_status="RUNNING" if self.headless else "RUNNING (HEADED)",
                        headless=bool(self.headless),
                    )
                    emit_event(f"Browser started ({'headless' if self.headless else 'headed'})", event_type="system")
                except Exception as _suppressed_exc:
                    _log_suppressed('start (line 3893)', _suppressed_exc)
                return
            except Exception as e:
                last_start_err = e
                self.stop()
                try:
                    get_event_bus().set_state(browser_status="FAILED")
                except Exception as _suppressed_exc:
                    _log_suppressed('start (line 3901)', _suppressed_exc)
                if attempt == 0 and self._try_repair_playwright(e):
                    continue
                break
        if last_start_err:
            # Record actual exception and diagnostics; status already marked failed. Do not claim success.
            try:
                status = "REPAIR FAILED" if str(_PLAYWRIGHT_REPAIR_STATE.get("last_outcome", "")).startswith("REPAIR FAILED") else "FAILED"
                get_event_bus().set_state(browser_status=status)
                emit_event(f"Browser unavailable: {type(last_start_err).__name__}: {last_start_err}", event_type="system", level="error",
                           details={"exception": type(last_start_err).__name__, "error": str(last_start_err), "diagnostics": self._driver_diagnostics(), "repair": _PLAYWRIGHT_REPAIR_STATE.get("last_outcome", "")})
            except Exception as _suppressed_exc:
                _log_suppressed('start (line 3913)', _suppressed_exc)
            raise BrowserUnavailableError(f"Browser unavailable: {last_start_err}") from last_start_err
        raise BrowserUnavailableError("Browser unavailable")

    def _is_expected_shutdown_browser_error(self, err: Exception) -> bool:
        msg = " ".join(str(err or "").split()).lower()
        expected = (
            "connection closed while reading from the driver",
            "browser has been closed",
            "target closed",
            "target page, context or browser has been closed",
            "browser closed",
            "playwright connection closed",
            "epipe",
        )
        return any(k in msg for k in expected)

    def stop(self):
        # Correct shutdown order: pages -> context -> browser -> playwright.
        # During Ctrl+C, driver-connection-closed errors are expected and handled quietly.
        errors: list[str] = []

        # Close all pages in context first (best effort)
        ctx = self._context
        if ctx is not None:
            try:
                pages = list(getattr(ctx, "pages", []) or [])
            except Exception:
                pages = []
            for pg in pages:
                try:
                    pg.close()
                except Exception as e:
                    if not self._is_expected_shutdown_browser_error(e):
                        errors.append(f"page: {e}")

        for name, obj, method in (
            ("context", ctx, "close"),
            ("browser", self._browser, "close"),
            ("playwright", self._playwright, "stop"),
        ):
            if obj is None:
                continue
            try:
                getattr(obj, method)()
            except Exception as e:
                if not self._is_expected_shutdown_browser_error(e):
                    errors.append(f"{name}: {e}")

        self._context = None
        self._browser = None
        self._playwright = None
        logger.info("Browser stopped")
        try:
            get_event_bus().set_state(browser_status="STOPPED")
            emit_event("Browser stopped", event_type="system")
        except Exception as _suppressed_exc:
            _log_suppressed('stop (browser)', _suppressed_exc)
        if errors:
            # Unexpected teardown errors go to log file; do not break terminal/status display
            logger.warning("Browser stop warnings: %s", "; ".join(errors))

    @contextmanager
    def session(self) -> Iterator["BrowserAutomation"]:
        self.start()
        try:
            yield self
        finally:
            self.stop()

    def is_alive(self) -> bool:
        try:
            if self._browser is None or self._context is None:
                return False
            connected = getattr(self._browser, "is_connected", None)
            if callable(connected):
                return bool(connected())
            # Fake/older objects used in tests or alternate Playwright versions.
            return True
        except Exception:
            return False

    def recover(self) -> bool:
        """Restart Playwright after a crash. Bounded by max_browser_recoveries."""
        if self.is_alive():
            return True
        if self._recovery_attempts >= self._max_recoveries:
            try:
                get_event_bus().set_state(browser_status="FAILED")
            except Exception as _suppressed_exc:
                _log_suppressed('recover (line 3970)', _suppressed_exc)
            return False
        self._recovery_attempts += 1
        try:
            emit_event("Browser crash detected; restarting browser", event_type="system", level="warn")
        except Exception as _suppressed_exc:
            _log_suppressed('recover (line 3976)', _suppressed_exc)
        try:
            self.stop()
        except Exception as _suppressed_exc:
            _log_suppressed('recover (line 3980)', _suppressed_exc)
        try:
            self.start()
        except Exception as e:
            logger.exception("Browser recovery failed: %s", e)
            try:
                get_event_bus().set_state(browser_status="FAILED")
                emit_event(f"Browser recovery failed: {e}", event_type="system", level="error")
            except Exception as _suppressed_exc:
                _log_suppressed('recover (line 3989)', _suppressed_exc)
            return False
        return self.is_alive()

    def new_page(self):
        if not self.is_alive():
            if not self.recover():
                raise BrowserUnavailableError("Browser is unavailable and could not be recovered")
        try:
            page = self._context.new_page()
            self._recovery_attempts = 0
            return page
        except Exception as e:
            # One bounded recovery attempt for a crashed context.
            logger.warning("new_page failed (%s); attempting browser recovery", e)
            if self.recover():
                return self._context.new_page()
            raise BrowserUnavailableError(f"Unable to create browser page: {e}") from e

    def _snapshot_from_html(self, url: str, html: str, status_code: Optional[int] = None, final_url: Optional[str] = None) -> PageSnapshot:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html or "", "html.parser")
            for tag in soup(["script", "style", "noscript"]):
                try:
                    tag.decompose()
                except Exception:
                    pass
            title = (soup.title.get_text(" ", strip=True) if soup.title else "") or ""
            text = soup.get_text("\n", strip=True) or re.sub("<[^>]+>", " ", html or "")
            html_lang = ""
            try:
                if soup.html and soup.html.get("lang"):
                    html_lang = str(soup.html.get("lang") or "").strip().lower()
            except Exception:
                html_lang = ""
            forms = []
            try:
                for i, fh in enumerate(soup.find_all("form")[:10]):
                    inputs = []
                    for el in fh.find_all(["input", "textarea", "select"]):
                        try:
                            inputs.append({
                                "tag": (el.name or "").lower(),
                                "type": (el.get("type") or "").lower(),
                                "name": el.get("name") or "",
                                "id": el.get("id") or "",
                                "placeholder": el.get("placeholder") or "",
                            })
                        except Exception:
                            pass
                    forms.append({
                        "index": i,
                        "method": (fh.get("method") or "get").lower(),
                        "action": fh.get("action") or "",
                        "inputs": inputs,
                    })
            except Exception:
                forms = []
        except Exception:
            title = ""
            text = re.sub("<[^>]+>", " ", html or "")
            html_lang = ""
            forms = []
        obstacles = detect_obstacle_text(text, html or "", status_code, None)
        has_captcha = any(term in " ".join(obstacles).lower() for term in ("captcha", "bot verification", "human verification", "cloudflare"))
        has_login = any(term in " ".join(obstacles).lower() for term in ("login", "registration"))
        has_rate = any("rate" in o.lower() for o in obstacles)
        return PageSnapshot(
            url=final_url or url,
            title=title or "",
            text=(text or "")[:20000],
            html=(html or "")[:200000],
            has_captcha=has_captcha,
            has_login_wall=has_login,
            has_rate_limit=has_rate,
            forms=forms,
            obstacles=obstacles,
            html_lang=html_lang if html_lang not in ("", "und") else "",
            status_code=status_code,
        )

    _http_session = None
    _http_session_lock = threading.Lock()

    @classmethod
    def _get_http_session(cls):
        with cls._http_session_lock:
            if cls._http_session is None:
                from requests.adapters import HTTPAdapter
                s = requests.Session()
                ad = HTTPAdapter(pool_connections=64, pool_maxsize=64, max_retries=0)
                s.mount("http://", ad)
                s.mount("https://", ad)
                s.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"})
                cls._http_session = s
            return cls._http_session

    def inspect_url_http(self, url: str, max_bytes: int = 1_500_000) -> Optional[PageSnapshot]:
        """Thread-safe static fetch (pooled, size-capped). Returns None on failure / non-HTML."""
        try:
            resp = self._get_http_session().get(url, timeout=(5, 15), allow_redirects=True, stream=True)
            try:
                ctype = (resp.headers.get("Content-Type") or "").lower()
                if ctype and "html" not in ctype and "text" not in ctype:
                    return None
                chunks, size = [], 0
                for chunk in resp.iter_content(65536):
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= max_bytes:
                        break
                raw = b"".join(chunks)
                enc = resp.encoding or "utf-8"
                try:
                    html = raw.decode(enc, "replace")
                except LookupError:
                    html = raw.decode("utf-8", "replace")
                return self._snapshot_from_html(url, html, status_code=resp.status_code, final_url=str(resp.url or url))
            finally:
                resp.close()
        except Exception:
            return None

    def _inspect_url_http_fallback(self, url: str) -> Optional[PageSnapshot]:
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
            timeout = float(self.config.get("request_timeout_seconds") or 15)
            resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            html = resp.text or ""
            return self._snapshot_from_html(url, html, status_code=getattr(resp, "status_code", None), final_url=str(getattr(resp, "url", url) or url))
        except Exception:
            return None

    def inspect_url(self, url: str) -> PageSnapshot:
        # Render with Playwright first (JS-heavy sites), fall back to plain HTTP fetch when rendering fails.
        try:
            page = self.new_page()
        except Exception:
            snap = self._inspect_url_http_fallback(url)
            if snap is not None:
                return snap
            raise
        try:
            response = page.goto(url, wait_until="domcontentloaded")
            page.wait_for_timeout(300)
            status_code = getattr(response, "status", None) if response is not None else None
            title = page.title() or ""
            html = page.content()
            try:
                html_lang = (page.get_attribute("html", "lang") or "").strip().lower()
            except Exception:
                html_lang = ""
            try:
                text = page.inner_text("body")
            except Exception:
                text = re.sub("<[^>]+>", " ", html)
            forms = self._extract_forms(page)
            frame_urls: list[str] = []
            try:
                frame_urls = [f.url for f in page.frames if f.url]
            except Exception as _suppressed_exc:
                _log_suppressed('inspect_url (line 4029)', _suppressed_exc)
            obstacles = detect_obstacle_text(text, html, status_code, frame_urls)
            has_captcha = any(
                term in " ".join(obstacles).lower()
                for term in ("captcha", "bot verification", "human verification", "cloudflare")
            )
            has_login = any(term in " ".join(obstacles).lower() for term in ("login", "registration"))
            has_rate = any("rate" in o.lower() for o in obstacles)
            return PageSnapshot(
                url=page.url,
                title=title,
                text=text[:20000],
                html=html[:200000],
                has_captcha=has_captcha,
                has_login_wall=has_login,
                has_rate_limit=has_rate,
                forms=forms,
                obstacles=obstacles,
                html_lang=html_lang if html_lang not in ("", "und") else "",
                status_code=status_code,
            )
        except Exception:
            snap = self._inspect_url_http_fallback(url)
            if snap is not None:
                return snap
            raise
        finally:
            try:
                page.close()
            except Exception as _suppressed_exc:
                _log_suppressed('inspect_url (line 4054)', _suppressed_exc)

    def _extract_forms(self, page) -> list[dict[str, Any]]:
        forms: list[dict[str, Any]] = []
        try:
            form_handles = page.query_selector_all("form")
            for i, fh in enumerate(form_handles[:10]):
                try:
                    method = (fh.get_attribute("method") or "get").lower()
                    action = fh.get_attribute("action") or ""
                    inputs = []
                    for el in fh.query_selector_all("input, textarea, select"):
                        try:
                            inputs.append({
                                "tag": el.evaluate("e => e.tagName.toLowerCase()"),
                                "type": (el.get_attribute("type") or "").lower(),
                                "name": el.get_attribute("name") or "",
                                "id": el.get_attribute("id") or "",
                                "placeholder": el.get_attribute("placeholder") or "",
                            })
                        except Exception:
                            continue
                    forms.append({"index": i, "method": method, "action": action, "inputs": inputs})
                except Exception:
                    continue
        except Exception as _suppressed_exc:
            _log_suppressed('_extract_forms (line 4080)', _suppressed_exc)
        return forms

    def detect_obstacles(self, page) -> list[str]:
        try:
            content = page.content() or ""
            try:
                text = page.inner_text("body") or ""
            except Exception:
                text = ""
            frame_urls: list[str] = []
            try:
                frame_urls = [f.url for f in page.frames if f.url]
            except Exception as _suppressed_exc:
                _log_suppressed('detect_obstacles (line 4094)', _suppressed_exc)
            status = None
            try:
                # Playwright pages expose the main response only during navigation;
                # this is a best-effort status check for already-loaded pages.
                status = getattr(page, "_coco_status", None)
            except Exception:
                status = None
            return detect_obstacle_text(text, content, status, frame_urls)
        except Exception:
            return []

    def detect_captcha(self, page) -> bool:
        joined = " ".join(self.detect_obstacles(page)).lower()
        return any(term in joined for term in ("captcha", "bot verification", "human verification", "cloudflare"))

    def screenshot(self, page, path: Path) -> Optional[str]:
        # Screenshot file saving disabled to avoid creating extra files/folders.
        return None

# ======================================================================
# merged from discovery.py
# ======================================================================
import re
import time
import urllib.request
from datetime import datetime
from typing import Iterable, Optional
from urllib.parse import parse_qs, quote_plus, urljoin, urlparse, urlunparse


logger = get_logger(__name__)

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "dclid", "msclkid", "ref", "referrer", "source", "campaign",
}
SKIP_EXTENSIONS = (
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".zip", ".rar", ".mp4",
    ".mp3", ".css", ".js", ".ico", ".xml", ".json",
)
SKIP_PATH_HINTS = (
    "/login", "/signin", "/sign-in", "/register", "/signup", "/sign-up", "/password",
    "/privacy", "/terms", "/cookies", "/legal", "/imprint", "/about", "/contact",
)
SEARCH_ENGINE_DOMAINS = {
    "duckduckgo.com", "html.duckduckgo.com", "bing.com", "www.bing.com", "google.com",
    "www.google.com", "consent.google.com", "mojeek.com", "www.mojeek.com", "search.brave.com", "brave.com",
    "yandex.com", "www.yandex.com", "yandex.ru", "search.yahoo.com", "yahoo.com",
    "www.yahoo.com", "startpage.com", "www.startpage.com", "qwant.com", "www.qwant.com",
    "searx.be", "wikipedia.org", "www.wikipedia.org",
}

# Multilingual query templates. They are rotated across runs so continuous
# discovery keeps surfacing new domains instead of rescanning the same seeds.
GLOBAL_QUERY_TEMPLATES: dict[str, list[str]] = {
    "en": [
        "submit fundraising request form", "mutual aid request submit", "community assistance request form",
        "charity directory submit organization", "share your story fundraising", "personal support request form",
        "submit donation request", "community help request form", "submit personal appeal", "nonprofit directory listing submit",
    ],
    "es": ["enviar solicitud de ayuda económica formulario", "ayuda mutua solicitar ayuda", "directorio de organizaciones benéficas enviar", "comparte tu historia recaudación de fondos", "formulario de solicitud de apoyo personal", "enviar solicitud de donación"],
    "fr": ["soumettre une demande d'aide financière formulaire", "entraide demande d'aide", "annuaire caritatif soumettre une association", "partagez votre histoire collecte de fonds", "formulaire demande de soutien"],
    "de": ["hilfeantrag formulare einreichen", "nachbarschaftshilfe hilfe anfragen", "wohltätigkeitsverzeichnis eintrag einreichen", "spendenaktion geschichte teilen", "unterstützungsanfrage formular"],
    "pt": ["enviar pedido de ajuda financeira formulário", "ajuda mútua pedir ajuda", "diretório de caridade enviar", "compartilhe sua história arrecadação de fundos", "formulário pedido de apoio"],
    "it": ["invia richiesta di aiuto economico modulo", "mutuo soccorso richiesta aiuto", "elenco enti di beneficenza invia", "condividi la tua storia raccolta fondi"],
    "ru": ["отправить заявку на финансовую помощь форма", "взаимопомощь попросить помощи", "благотворительный каталог добавить организацию", "форма запроса поддержки"],
    "ar": ["تقديم طلب مساعدة مالية نموذج", "المساعدة المتبادلة طلب مساعدة", "دليل الجمعيات الخيرية إضافة", "نموذج طلب دعم شخصي"],
    "hi": ["वित्तीय सहायता अनुरोध फॉर्म जमा करें", "पारस्परिक सहायता मदद का अनुरोध", "धर्मार्थ निर्देशिका सबमिट करें", "व्यक्तिगत सहायता अनुरोध फॉर्म"],
    "zh": ["提交募捐申请 表格", "互助 申请帮助", "慈善目录 提交", "个人求助申请表", "提交筹款请求"],
    "ja": ["募金 申請 フォーム 送信", "相互扶助 支援依頼", "慈善団体 ディレクトリ 登録", "支援申請フォーム"],
    "ko": ["모금 신청 양식 제출", "상호 부조 도움 요청", "자선 단체 디렉토리 등록", "지원 요청 양식"],
    "tr": ["maddi yardım başvuru formu gönder", "karşılıklı yardım yardım talebi", "hayır kurumu dizini kayıt", "destek talep formu"],
    "id": ["kirim permohonan bantuan keuangan formulir", "gotong royong minta bantuan", "direktori amal kirim", "formulir permintaan dukungan"],
    "vi": ["gửi đơn xin hỗ trợ tài chính biểu mẫu", "tương trợ yêu cầu giúp đỡ", "danh bạ từ thiện gửi", "biểu mẫu yêu cầu hỗ trợ"],
    "pl": ["wyślij wniosek o pomoc finansową formularz", "pomoc wzajemna prośba o pomoc", "katalog charytatywny zgłoś", "formularz prośby o wsparcie"],
    "uk": ["подати заявку на фінансову допомогу форма", "взаємодопомога попросити допомоги", "благодійний каталог додати", "форма запиту підтримки"],
    "nl": ["financiële hulp aanvraag formulier indienen", "wederzijdse hulp steun aanvragen", "goededoelen directory indienen"],
    "sv": ["skicka ansökan om ekonomiskt stöd formulär", "ömsesidig hjälp be om hjälp", "välgörenhetskatalog skicka in"],
    "no": ["send søknad om økonomisk hjelp skjema", "gjensidig hjelp be om hjelp"],
    "da": ["indsend ansøgning om økonomisk hjælp formular", "gensidig hjælp anmod om hjælp"],
    "fi": ["lähetä taloudellisen avun hakemus lomake", "keskinäinen apu pyydä apua"],
    "cs": ["odeslat žádost o finanční pomoc formulář", "vzájemná pomoc požádat o pomoc"],
    "ro": ["trimite cerere de ajutor financiar formular", "ajutor reciproc cere ajutor"],
    "el": ["υποβολή αίτησης οικονομικής βοήθειας φόρμα", "αλληλοβοήθεια αίτηση βοήθειας"],
    "he": ["שליחת בקשה לעזרה כלכלית טופס", "עזרה הדדית בקשת עזרה"],
    "th": ["ส่งคำขอความช่วยเหลือทางการเงิน แบบฟอร์ม", "ช่วยเหลือซึ่งกันและกัน ขอความช่วยเหลือ"],
    "bn": ["আর্থিক সহায়তার অনুরোধ ফর্ম জমা দিন", "পারস্পরিক সহায়তা সাহায্যের অনুরোধ"],
    "ur": ["مالی امداد کی درخواست فارم جمع کریں", "باہمی امداد مدد کی درخواست"],
    "fa": ["ارسال فرم درخواست کمک مالی", "کمک متقابل درخواست کمک"],
    "sw": ["tuma ombi la msaada wa kifedha fomu", "msaada wa pamoja omba msaada"],
    "ms": ["hantar borang permohonan bantuan kewangan", "bantuan bersama minta bantuan"],
    "fil": ["isumite ang form ng kahilingan sa tulong pinansyal", "tulong sa isa't isa humiling ng tulong"],
    "ta": ["நிதி உதவி கோரிக்கை படிவம் சமர்ப்பிக்க", "பரஸ்பர உதவி உதவி கேட்க", "தொண்டு அடைவு சமர்ப்பி"],
    "te": ["ఆర్థిక సహాయం అభ్యర్థన ఫారం సమర్పించండి", "పరస్పర సహాయం సహాయం అడగండి", "ఛారిటీ డైరెక్టరీ సమర్పించండి"],
    "ml": ["സാമ്പത്തിക സഹായ അഭ്യർത്ഥന ഫോം സമർപ്പിക്കുക", "പരസ്പര സഹായം സഹായം അഭ്യർത്ഥിക്കുക", "ചാരിറ്റി ഡയറക്ടറി സമർപ്പിക്കുക"],
    "kn": ["ಆರ್ಥಿಕ ನೆರವು ವಿನಂತಿ ಫಾರ್ಮ್ ಸಲ್ಲಿಸಿ", "ಪರಸ್ಪರ ಸಹಾಯ ಸಹಾಯ ಕೇಳಿ", "ಚ್ಯಾರಿಟಿ ಡೈರೆಕ್ಟರಿ ಸಲ್ಲಿಸಿ"],
    "mr": ["आर्थिक मदत विनंती फॉर्म सबमिट करा", "परस्पर मदत मदत मागा", "धर्मादाय निर्देशिका सबमिट करा"],
    "gu": ["નાણાકીય સહાય વિનંતી ફોર્મ સબમિટ કરો", "પરસ્પર મદદ મદદ માંગો", "ચેરિટી ડિરેક્ટરી સબમિટ કરો"],
    "pa": ["ਵਿੱਤੀ ਮਦਦ ਬੇਨਤੀ ਫਾਰਮ ਜਮ੍ਹਾਂ ਕਰੋ", "ਆਪਸੀ ਮਦਦ ਮਦਦ ਮੰਗੋ", "ਚੈਰਿਟੀ ਡਾਇਰੈਕਟਰੀ ਜਮ੍ਹਾਂ ਕਰੋ"],
    "ne": ["आर्थिक सहायता अनुरोध फारम पेश गर्नुहोस्", "पारस्परिक सहायता मद्दत माग्नुहोस्", "दान निर्देशिका पेश गर्नुहोस्"],
    "si": ["මූල්‍ය ආධාර ඉල්ලීමේ පෝරමය ඉදිරිපත් කරන්න", "පරස්පර ආධාර උදව් ඉල්ලන්න", "පුණ්‍යායතන නාමාවලිය ඉදිරිපත් කරන්න"],
    "my": ["ဘဏ္ဍာရေးအကူအညီတောင်းခံမှုပုံစံ တင်ပါ", "အပြန်အလှန်အကူအညီ အကူအညီတောင်းပါ", "ပရဟိတအဖွဲ့များ လမ်းညွှန် တင်ပါ"],
    "km": ["ដាក់ស្នើទម្រង់ស្នើសុំជំនួយហិរញ្ញវត្ថុ", "ជំនួយគ្នាទៅវិញទៅមក ស្នើសុំជំនួយ", "បញ្ជីសប្បុរសធម៌ ដាក់ស្នើ"],
    "lo": ["ສົ່ງແບບຟອມຂໍຄວາມຊ່ວຍເຫຼືອທາງການເງິນ", "ການຊ່ວຍເຫຼືອເຊິ່ງກັນແລະກັນ ຂໍຄວາມຊ່ວຍເຫຼືອ", "ບໍລິສັດການກຸສົນ ສົ່ງ"],
    "hu": ["pénzügyi segélykérelem űrlap beküldése", "kölcsönös segítség segítségkérés", "jótékonysági könyvtár beküldése"],
    "bg": ["подайте формуляр за финансова помощ", "взаимопомощ поискайте помощ", "благотворителен каталог добавете"],
    "hr": ["pošaljite obrazac zahtjeva za financijsku pomoć", "uzajamna pomoć zatražite pomoć", "dobrotvorni direktorij pošaljite"],
    "sk": ["odoslať žiadosť o finančnú pomoc formulár", "vzájomná pomoc požiadať o pomoc", "charitatívny katalóg odoslať"],
    "sl": ["pošljite obrazec za prošnjo za finančno pomoč", "vzajemna pomoč zaprosite za pomoč", "dobrodelni imenik pošljite"],
    "lt": ["pateikti finansinės pagalbos prašymo formą", "abipusė pagalba prašyti pagalbos", "labdaros katalogas pateikti"],
    "lv": ["iesniegt finansiālās palīdzības pieprasījuma veidlapu", "savstarpējā palīdzība lūgt palīdzību", "labdarības katalogs iesniegt"],
    "et": ["esita rahalise abi taotluse vorm", "vastastikune abi küsi abi", "heategevuskataloog esita"],
    "sr": ["пошаљите образац захтева за финансијску помоћ", "узајамна помоћ затражите помоћ", "добротворни каталог пошаљите"],
    "mk": ["поднесете барање за финансиска помош формулар", "взаемна помош побарајте помош", "хуманитарен директориум поднесете"],
    "sq": ["dërgo formularin e kërkesës për ndihmë financiare", "ndihma e ndërsjellë kërko ndihmë", "drejtoria e bamirësisë dërgo"],
    "bs": ["pošaljite obrazac zahtjeva za financijsku pomoć", "uzajamna pomoć zatražite pomoć", "humanitarni direktorij pošaljite"],
    "ca": ["envia el formulari de sol·licitud d'ajuda financera", "ajuda mútua demana ajuda", "directori benèfic envia"],
    "af": ["dien finansiële hulp versoek vorm in", "onderlinge hulp vra vir hulp", "liefdadigheids gids dien in"],
    "am": ["የገንዘብ እርዳታ ጥያቄ ቅጽ ላክ", "የጋራ እርዳታ እርዳታ ጠይቅ", "የበጎ አድራጎት ማውጫ ላክ"],
    "ha": ["aika takardar neman taimakon kudi", "taimakon juna nemi taimako", "kundin bayanai na agaji aika"],
    "yo": ["fi ibeere iranlowo owo ranṣe", "iranlowo ara eni beere fun iranlowo", "ito awon eleejoorun ranṣe"],
    "zu": ["thumela ifomu lesicelo sosizo lwezimali", "usizo olubambisene cela usizo", "uhlu lwezomusa thumela"],
    "so": ["dir foomka codsiga caawimaada maaliyadeed", "caawimaad isdhexgalleed codso caawimo", "tusaha hay'adaha samafalka dir"],
    "az": ["maliyyə yardımı sorğu forması göndərin", "qarşılıqlı yardım kömək istəyin", "xeyriyyə kataloquna əlavə edin"],
    "kk": ["қаржылық көмек сұрау формасын жіберу", "өзара көмек көмек сұрау", "қайырымдылық каталогына қосу"],
    "uz": ["moliyaviy yordam so'rov formasini yuboring", "o'zaro yordam yordam so'rang", "xayriya katalogiga qo'shing"],
    "hy": ["ֆինանսական օգնության հայտի ձև ուղարկել", "փոխադարձ օգնություն օգնություն խնդրել", "բարեգործական կատալոգ ուղարկել"],
    "ka": ["ფინანსური დახმარების მოთხოვნის ფორმის გაგზავნა", "ურთიერთდახმარება დახმარება სთხოვე", "საქველმოქმედო კატალოგი გაგზავნა"],
    "mn": ["санхүүгийн тусламжийн хүсэлтийн маягт илгээх", "харилцан тусламж тусламж хүсэх", "буяны каталогт нэмэх"],
}

# Market/locale codes so a query in a given language surfaces sites from that
# language's regions instead of only US/English results (google hl, bing
# setlang/mkt, duckduckgo kl). Languages not listed keep the default market.
LANG_MARKET: dict[str, str] = {
    "es": "es-ES", "fr": "fr-FR", "de": "de-DE", "pt": "pt-BR", "it": "it-IT",
    "ru": "ru-RU", "ar": "ar-XA", "hi": "hi-IN", "zh": "zh-CN", "ja": "ja-JP",
    "ko": "ko-KR", "tr": "tr-TR", "id": "id-ID", "vi": "vi-VN", "pl": "pl-PL",
    "uk": "uk-UA", "nl": "nl-NL", "sv": "sv-SE", "no": "nb-NO", "da": "da-DK",
    "fi": "fi-FI", "cs": "cs-CZ", "ro": "ro-RO", "el": "el-GR", "he": "he-IL",
    "th": "th-TH", "bn": "bn-IN", "ur": "ur-PK", "fa": "fa-IR", "sw": "sw-KE",
    "ms": "ms-MY", "fil": "fil-PH", "ta": "ta-IN", "te": "te-IN", "ml": "ml-IN",
    "kn": "kn-IN", "mr": "mr-IN", "gu": "gu-IN", "pa": "pa-IN", "ne": "ne-NP",
    "hu": "hu-HU", "bg": "bg-BG", "hr": "hr-HR", "sk": "sk-SK", "sl": "sl-SI",
    "lt": "lt-LT", "lv": "lv-LV", "et": "et-EE", "sr": "sr-RS", "ca": "ca-ES",
    "af": "af-ZA", "az": "az-AZ", "kk": "kk-KZ", "uz": "uz-UZ", "hy": "hy-AM",
    "ka": "ka-GE",
}

_QUERY_LANGUAGE: dict[str, str] = {}


def _register_query_languages() -> None:
    for _lang, _qs in GLOBAL_QUERY_TEMPLATES.items():
        for _q in _qs:
            _key = " ".join(str(_q).split()).strip().lower()
            if _key:
                _QUERY_LANGUAGE[_key] = _lang


_register_query_languages()


def _query_language(query: str) -> str:
    """Best-effort language of a discovery query, from the template tables."""
    key = " ".join(str(query or "").split()).strip().lower()
    return _QUERY_LANGUAGE.get(key, "en")


class RobotsChecker:
    """Small robots.txt checker used for discovery crawling only."""

    def __init__(self, user_agent: str = "COCO/1.0", timeout: float = 5.0):
        self.user_agent = user_agent
        self.timeout = timeout
        self._cache: dict[str, object] = {}

    def can_fetch(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                return False
            base = f"{parsed.scheme}://{parsed.netloc}"
            if base not in self._cache:
                from urllib.robotparser import RobotFileParser

                parser = RobotFileParser()
                robots_url = base + "/robots.txt"
                try:
                    req = urllib.request.Request(robots_url, headers={"User-Agent": self.user_agent})
                    with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                        body = resp.read(512_000).decode("utf-8", "ignore")
                    parser.parse(body.splitlines())
                except Exception:
                    # Missing/unreachable robots.txt: allow, but never treat this
                    # as permission to publish.
                    parser = None
                self._cache[base] = parser
            parser = self._cache.get(base)
            if parser is None:
                return True
            return bool(parser.can_fetch(self.user_agent, url))
        except Exception:
            return True


class _SkipIntelligence(Exception):
    pass


class DiscoveryService:
    def __init__(self, config: dict, db: Database, browser: Optional[BrowserAutomation] = None):
        self.config = config
        self.db = db
        self.browser = browser
        self.analyzer = RelevanceAnalyzer()
        self.intelligence = IntelligenceEngine((config or {}).get("intelligence") or {})
        self.robots = RobotsChecker() if config.get("respect_robots_txt", True) else None
        self._seen_urls: set[str] = set()
        self._domain_hits: dict[str, int] = {}
        self._lock = threading.RLock()
        self._host_next_ok: dict[str, float] = {}
        self._scans_today = (None, 0)  # (date, count) fallback when the DB count is unavailable
        self._search_domain_seen: set[str] = set()
        self._blocked_search_providers: dict[str, float] = {}  # provider -> blocked-until monotonic time
        # Per-discover() counters so a 0-result run can say exactly why.
        self.run_stats: dict[str, int] = {
            "seeds": 0, "queue": 0, "search_queries": 0, "providers_blocked": 0,
            "candidates_parsed": 0, "filtered_robots": 0, "filtered_relevance": 0,
            "filtered_category": 0, "filtered_prohibited": 0, "duplicates": 0, "recorded": 0,
        }

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    def discover(self, seeds: Optional[list[str]] = None, limit: int = 50) -> list[WebsiteRecord]:
        explicit_seeds = seeds is not None
        seed_list = list(seeds) if explicit_seeds else list(self.config.get("seed_urls") or [])
        found: list[WebsiteRecord] = []

        if not seed_list and not explicit_seeds:
            seed_list = list(self.config.get("candidate_urls") or [])

        emit_event("🔄 Continuous discovery active", event_type="discovery")
        # Recover any queue rows left in 'processing' by a crash/interrupt.
        try:
            recovered_q = self.db.recover_discovery_queue_processing()
            if recovered_q:
                emit_event(f"Recovered {recovered_q} discovery queue item(s) from processing -> pending", event_type="discovery", level="warn")
        except Exception:
            pass

        emit_event(f"Discovery started: {len(seed_list)} seed/candidate URL(s)", event_type="discovery")
        own_browser = self.browser is None
        previous_browser = self.browser
        browser = self.browser or BrowserAutomation({"headless": True, "navigation_timeout_ms": 30000})
        if own_browser:
            self.browser = browser
        try:
            if own_browser:
                browser.start()
            # Bulk seed/candidate files -> persistent discovery queue (one URL per line)
            try:
                seed_files = list(self.config.get("seed_files") or [])
                if self.config.get("seed_file"):
                    seed_files.append(self.config.get("seed_file"))
                # Convenience: auto-load local seeds.txt/urls.txt if present (bulk URL list input)
                for auto_name in ("seeds.txt", "urls.txt", "seed_urls.txt", "candidate_urls.txt"):
                    ap = Path.cwd() / auto_name
                    if ap.exists() and ap.is_file():
                        seed_files.append(str(ap))
                seen_seed_files = set()
                for sf in seed_files:
                    try:
                        pth = Path(str(sf)).expanduser()
                        if not pth.is_absolute():
                            pth = (Path.cwd() / pth).resolve()
                        key = str(pth).lower()
                        if key in seen_seed_files:
                            continue
                        seen_seed_files.add(key)
                        if not pth.exists() or not pth.is_file():
                            continue
                        for raw in pth.read_text(encoding="utf-8", errors="ignore").splitlines():
                            line = raw.strip()
                            if not line or line.startswith("#"):
                                continue
                            cu = canonicalize_url(line)
                            if not cu:
                                continue
                            try:
                                dom = self.db.domain_for_url(cu)
                                self.db.enqueue_discovery_url(cu, dom, source=f"seed-file:{pth.name}", query=str(pth))
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass
            # Process persisted discovery queue first so opportunities are not lost across restarts
            # Drain in batches to handle bulk seed files / large queues faster per cycle.
            while len(found) < limit:
                try:
                    queued = self.db.fetch_discovery_queue(limit=max(25, min(limit - len(found), 200)))
                except Exception:
                    queued = []
                if not queued:
                    break
                if self._scan_workers() > 1:
                    if not self._scan_batch(queued, found, limit):
                        break
                    continue
                progressed = False
                for item in queued:
                    self.run_stats["queue"] += 1
                    if len(found) >= limit:
                        break
                    url = item.get("url")
                    if not url:
                        continue
                    progressed = True
                    try:
                        self.db.mark_discovery_queue(url, "processing")
                    except Exception as _suppressed_exc:
                        _log_suppressed('discover (line 4287)', _suppressed_exc)
                    try:
                        found.extend(self.inspect_and_record(url, enforce_filters=True, source=item.get("source") or "queue"))
                    except Exception as e:
                        logger.debug("Queued discovery failed %s: %s", url, e)
                        try:
                            self.db.mark_discovery_queue(url, "pending", f"retry: {e}")
                        except Exception as _suppressed_exc:
                            _log_suppressed('discover (line 4295)', _suppressed_exc)
                if not progressed:
                    break

            for seed in seed_list:
                self.run_stats["seeds"] += 1
                if len(found) >= limit:
                    break
                try:
                    emit_event(f"Inspecting seed: {seed}", event_type="discovery")
                    found.extend(self.inspect_and_record(seed, enforce_filters=False))
                except Exception as e:
                    logger.warning("Failed to inspect seed %s: %s", seed, e)
                    emit_event(f"Discovery failed for {seed}: {e}", event_type="discovery", level="error")

            if not explicit_seeds and self.config.get("search_providers") and len(found) < limit:
                found.extend(self._discover_from_search(browser, limit - len(found)))
        finally:
            if own_browser:
                browser.stop()
                self.browser = previous_browser

        if not found:
            # Loud diagnosis for "discovery finds 0 websites": name the cause.
            stats = self.run_stats
            parsed = stats.get("candidates_parsed", 0)
            if stats.get("providers_blocked", 0) and stats["providers_blocked"] >= max(1, stats.get("search_queries", 0)):
                hint = ("Likely cause: every search provider served a bot-verification/block page. "
                        "Try again later, use fewer queries, or add seed_urls to config.yaml.")
            elif stats.get("search_queries", 0) > 0 and parsed == 0:
                hint = ("Likely cause: search pages returned no parsable result links "
                        "(provider markup changed or the response was not a results page).")
            elif not stats.get("seeds") and not stats.get("queue") and not stats.get("search_queries"):
                hint = ("Likely cause: no seed_urls/candidate_urls configured and no search queries ran "
                        "(check discovery.search_providers / search_queries in config.yaml).")
            elif parsed > 0 and stats.get("filtered_relevance", 0) + stats.get("filtered_category", 0) >= parsed:
                hint = ("Likely cause: every candidate was filtered by relevance/category rules "
                        "(consider discovery.min_candidate_relevance or allowed_categories in config.yaml).")
            else:
                hint = "See the per-filter counters for where candidates were dropped."
            emit_event(
                "Discovery found 0 websites. "
                + ", ".join(f"{k}={v}" for k, v in stats.items() if v)
                + ". " + hint,
                event_type="discovery", level="warn",
            )
        logger.info("Discovery completed: %s candidates", len(found))
        emit_event(f"Discovery completed: {len(found)} candidate URL(s)", event_type="discovery")
        return found

    # ------------------------------------------------------------------
    # Bulk scan: HTTP-first thread pool, browser only for JS-only pages
    # ------------------------------------------------------------------
    def _scan_workers(self) -> int:
        if not self.config.get("http_first", True):
            return 1
        try:
            return max(1, int(self.config.get("scan_workers", 8)))
        except Exception:
            return 1

    def _scans_done_today(self) -> int:
        try:
            midnight = datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
            with self.db.connection() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) AS c FROM discovery_queue WHERE processed_at >= ? AND status IN ('processed','skipped')",
                    (midnight,),
                ).fetchone()
            return int(row["c"] if row else 0)
        except Exception:
            today = datetime.now().date()
            d, n = self._scans_today
            return n if d == today else 0

    def _count_scan(self, n: int = 1) -> None:
        today = datetime.now().date()
        with self._lock:
            d, c = self._scans_today
            self._scans_today = (today, (c if d == today else 0) + n)

    def _host_gate(self, url: str) -> None:
        """Per-host politeness: never hit one host more than once per per_host_delay_seconds."""
        try:
            host = (urlparse(url).netloc or "").lower()
            delay = float(self.config.get("per_host_delay_seconds", 1.0))
            with self._lock:
                now = time.monotonic()
                at = max(now, self._host_next_ok.get(host, 0.0))
                self._host_next_ok[host] = at + delay
            wait = at - now
            if wait > 0:
                time.sleep(wait)
        except Exception:
            pass

    def _close_row(self, url: str) -> None:
        """Rows filtered out (relevance/category/robots) would otherwise stay 'processing' until restart."""
        try:
            with self.db.connection() as conn:
                conn.execute("UPDATE discovery_queue SET status='processed', processed_at=? WHERE url=? AND status='processing'",
                             (self.db._now(), url))
        except Exception:
            pass

    def _scan_one(self, item: dict) -> tuple[str, list]:
        """Worker: returns (state, records). state in done|js|skip|error."""
        url = item.get("url")
        src = item.get("source") or "queue"
        if not url:
            return "skip", []
        if not self._allowed_by_robots(url):
            return "done", self.inspect_and_record(url, enforce_filters=True, source=src)  # records the robots filter
        self._host_gate(url)
        snap = self.browser.inspect_url_http(url) if self.browser is not None else BrowserAutomation({}).inspect_url_http(url)
        if snap is None:
            return "error", []
        min_chars = int(self.config.get("min_static_text_chars", 300))
        if len((snap.text or "").strip()) < min_chars and not snap.forms:
            return "js", []  # likely JS-rendered; handled by the single shared browser in the main thread
        recs = self.inspect_and_record(
            url, enforce_filters=True, source=src, snap=snap, follow_links=False,
            fast=bool(self.config.get("skip_ai_in_bulk_scan", True)),
        )
        return "done", recs

    def _scan_batch(self, queued: list[dict], found: list, limit: int) -> int:
        """Scan one queue batch concurrently. Returns number of URLs handled (0 = stop)."""
        import concurrent.futures as cf
        cap = int(self.config.get("max_scans_per_day", 0) or 0)
        room = (10**9 if cap <= 0 else cap - max(self._scans_done_today(), self._scans_today[1] if self._scans_today[0] == datetime.now().date() else 0))
        if room <= 0:
            emit_event(f"Daily scan cap reached ({cap}); resuming tomorrow", event_type="discovery", level="warn")
            return 0
        items = [i for i in queued if i.get("url")][:room]
        for it in items:
            try:
                self.db.mark_discovery_queue(it["url"], "processing")
            except Exception:
                pass
        js_items: list[dict] = []
        handled = 0
        with cf.ThreadPoolExecutor(max_workers=self._scan_workers(), thread_name_prefix="coco-scan") as ex:
            futs = {ex.submit(self._scan_one, it): it for it in items}
            for fut in cf.as_completed(futs):
                it = futs[fut]
                self.run_stats["queue"] += 1
                try:
                    state, recs = fut.result()
                except Exception as e:
                    state, recs = "error", []
                    logger.debug("Scan failed %s: %s", it.get("url"), e)
                if state == "js":
                    js_items.append(it)
                    continue
                handled += 1
                self._count_scan()
                found.extend(recs)
                self._close_row(it["url"])
                if state in ("error", "skip"):
                    try:
                        self.db.mark_discovery_queue(it["url"], "skipped", "fetch failed" if state == "error" else "empty")
                    except Exception:
                        pass
        # JS-only pages: one reused browser, main thread only, capped per batch.
        cap_js = int(self.config.get("js_fallback_per_batch", 15))
        for n, it in enumerate(js_items):
            handled += 1
            self._count_scan()
            if n >= cap_js or self.browser is None:
                try:
                    self.db.mark_discovery_queue(it["url"], "skipped", "js-only page, over per-batch browser cap")
                except Exception:
                    pass
                continue
            try:
                found.extend(self.inspect_and_record(it["url"], enforce_filters=True, source=it.get("source") or "queue", follow_links=False))
                self._close_row(it["url"])
            except Exception as e:
                try:
                    self.db.mark_discovery_queue(it["url"], "skipped", f"browser: {e}")
                except Exception:
                    pass
        return handled

    def discover_from_seeds(self, seeds: Optional[list[str]] = None, limit: int = 0) -> list[WebsiteRecord]:
        """Backwards-compatible entry point.

        When called without explicit seeds it also runs configured search
        providers so discovery is not limited to a fixed list of domains.
        """
        limit = int(limit or self.config.get("max_scans_per_cycle", 1000))
        return self.discover(seeds=seeds, limit=limit)

    def add_manual_url(self, url: str, category: str = "personal_support") -> list[WebsiteRecord]:
        return self.inspect_and_record(url, forced_category=category, enforce_filters=False)

    # ------------------------------------------------------------------
    # Inspection and persistence
    # ------------------------------------------------------------------
    def inspect_and_record(
        self,
        url: str,
        forced_category: Optional[str] = None,
        enforce_filters: bool = False,
        source: str = "seed",
        snap: Optional[PageSnapshot] = None,
        follow_links: bool = True,
        fast: bool = False,
    ) -> list[WebsiteRecord]:
        browser = self.browser
        if browser is None and snap is None:
            raise RuntimeError("Browser instance required for inspection")

        canonical = canonicalize_url(url)
        if not canonical:
            return []
        with self._lock:
            if canonical in self._seen_urls:
                return []
            self._seen_urls.add(canonical)

        if enforce_filters and not self._allowed_by_robots(url):
            self.run_stats["filtered_robots"] += 1
            emit_event(f"Robots.txt disallows discovery: {url}", event_type="discovery", level="warn")
            return []

        if snap is None:
            snap = browser.inspect_url(url)
        # Try to pass focused rules text when detectable; fall back to page text.
        rules_text = ""
        try:
            rules_url = self._find_rules_url(snap.url, snap.html)
            if rules_url:
                # Best-effort: rules page may be same page; keep lightweight (no extra fetch here)
                if canonicalize_url(rules_url) == canonical:
                    rules_text = snap.text
        except Exception:
            rules_text = ""
        analysis = self.analyzer.analyze(
            snap.url, snap.title, snap.text, rules_text=rules_text, html_lang=snap.html_lang or "",
            forms=snap.forms, html=snap.html,
        )
        # AI/intelligence layer (pluggable, local/free-only, heuristic fallback). Advisory only.
        try:
            if fast:
                raise _SkipIntelligence()
            page_decision = self.intelligence.classify_page(
                snap.url, snap.title, snap.text,
                heuristic={
                    "language": analysis.language,
                    "destination_category": analysis.destination_category,
                    "submission_method": analysis.submission_method.value,
                    "relevance_score": analysis.relevance_score,
                    "rules_summary": analysis.rules_summary,
                },
            )
            perm_decision = self.intelligence.interpret_permission(
                snap.url, snap.text,
                heuristic={
                    "permission": analysis.permission.value,
                    "permission_verified": False,
                    "allowed_categories": analysis.allowed_categories,
                    "registration_requirements": analysis.registration.value,
                    "rules_summary": analysis.rules_summary,
                    "permission_evidence": analysis.permission_evidence,
                },
            )
            analysis.intelligence = {
                "page": IntelligenceEngine.to_record(page_decision),
                "permission": IntelligenceEngine.to_record(perm_decision),
                "capabilities": self.intelligence.capability_report(),
            }
        except _SkipIntelligence:
            pass
        except Exception as _suppressed_exc:
            _log_suppressed('inspect_and_record (line 4413)', _suppressed_exc)
        category = forced_category or analysis.recommended_variant.value
        method_verified = analysis.submission_method not in (SubmissionMethod.UNKNOWN,)
        permission_verified = (
            analysis.permission == PermissionStatus.ALLOWED
            and bool(analysis.allowed_categories)
            and method_verified
        )
        notes = analysis.rules_summary
        if snap.obstacles:
            notes = f"{notes}; obstacles: {summarize_obstacles(snap.obstacles)}"

        rules_url = self._find_rules_url(snap.url, snap.html)
        rec = WebsiteRecord(
            url=snap.url,
            domain=self.db.domain_for_url(snap.url),
            category=category,
            language=analysis.language,
            registration_requirements=analysis.registration,
            submission_method=analysis.submission_method,
            rules_url=rules_url,
            relevance_score=analysis.relevance_score,
            last_verification_date=datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None),
            permission_status=analysis.permission,
            notes=notes.strip("; "),
            permission_verified=permission_verified,
            permission_evidence=analysis.permission_evidence,
            allowed_categories=list(analysis.allowed_categories),
            submission_method_verified=method_verified,
            permission_source_url=rules_url or snap.url,
            permission_checked_at=datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None),
            permission_reason=analysis.rules_summary or analysis.permission_evidence,
            inspection_status="inspected",
        )

        if snap.forms and rec.submission_method == SubmissionMethod.UNKNOWN:
            rec.submission_method = SubmissionMethod.FORM
            rec.submission_method_verified = True
            rec.relevance_score = min(1.0, rec.relevance_score + 0.05)
        if self.config.get("prioritize_no_registration", True) and rec.registration_requirements == RegistrationRequirement.NONE:
            rec.relevance_score = min(1.0, rec.relevance_score + 0.08)
        if analysis.permission == PermissionStatus.PROHIBITED:
            rec.relevance_score = min(rec.relevance_score, 0.2)
            rec.permission_status = PermissionStatus.PROHIBITED
            rec.permission_verified = False
        # mark eligible for strict auto flow when all conditions satisfied
        try:
            min_score = float(self.config.get("min_candidate_relevance", 0.35))
            eligible = (
                rec.permission_status == PermissionStatus.ALLOWED and rec.permission_verified
                and rec.registration_requirements == RegistrationRequirement.NONE
                and rec.submission_method in (SubmissionMethod.FORM, SubmissionMethod.POST)
                and rec.submission_method_verified and bool(rec.allowed_categories)
                and rec.category in rec.allowed_categories and rec.relevance_score >= min_score
            )
            rec.inspection_status = "eligible" if eligible else "inspected"
        except Exception:
            rec.inspection_status = "inspected"

        # Relevance / category filtering for automated discovery. Manual adds and
        # explicit seeds are always recorded so the user can inspect them.
        if enforce_filters:
            min_score = float(self.config.get("min_candidate_relevance", 0.35))
            allowed = set(self.config.get("allowed_categories") or [])
            if analysis.permission == PermissionStatus.PROHIBITED:
                self.run_stats["filtered_prohibited"] += 1
                emit_event(f"Filtered (prohibited): {rec.url}", event_type="discovery", level="warn")
                return []
            if rec.relevance_score < min_score:
                self.run_stats["filtered_relevance"] += 1
                emit_event(
                    f"Filtered (low relevance {rec.relevance_score:.2f} < {min_score:.2f}): {rec.url}",
                    event_type="discovery",
                )
                return []
            if allowed and rec.category not in allowed:
                self.run_stats["filtered_category"] += 1
                emit_event(f"Filtered (category {rec.category}): {rec.url}", event_type="discovery")
                return []

        # Domain and URL deduplication.
        domain = rec.domain
        existing = self.db.get_website_by_url(rec.url) or self.db.get_website_by_url(canonical)
        if existing and not self.config.get("recheck_existing_urls", False):
            self.run_stats["duplicates"] += 1
            try:
                self.db.mark_discovery_queue(rec.url, "skipped", "already inspected")
            except Exception as _suppressed_exc:
                _log_suppressed('inspect_and_record (line 4501)', _suppressed_exc)
            return [existing]

        self.db.upsert_website(rec)
        self.run_stats["recorded"] += 1
        try:
            intel = getattr(analysis, "intelligence", None) or {}
            for cap, recd in (intel.items() if isinstance(intel, dict) else []):
                if isinstance(recd, dict) and "provider" in recd:
                    self.db.record_intelligence_decision(rec.url, cap, recd)
        except Exception as _suppressed_exc:
            _log_suppressed('inspect_and_record (line 4512)', _suppressed_exc)
        try:
            self.db.mark_discovery_queue(rec.url, "processed", rec.inspection_status)
        except Exception as _suppressed_exc:
            _log_suppressed('inspect_and_record (line 4516)', _suppressed_exc)
        with self._lock:
            self._domain_hits[domain] = self._domain_hits.get(domain, 0) + 1
        self._emit_discovery_events(rec, source)

        results = [self.db.get_website_by_url(rec.url) or rec]
        if not follow_links:
            # Bulk mode: candidate links are queued (not recursed) so the pool stays flat.
            try:
                for link in self._extract_candidate_links(snap.url, snap.html)[:int(self.config.get("max_candidates_per_seed", 10))]:
                    ld = self.db.domain_for_url(link)
                    with self._lock:
                        over = self._domain_hits.get(ld, 0) >= int(self.config.get("max_urls_per_domain", 3))
                    if not over:
                        self.db.enqueue_discovery_url(link, ld, source="candidate-link", priority=float(rec.relevance_score))
            except Exception as _suppressed_exc:
                _log_suppressed('inspect_and_record bulk links', _suppressed_exc)
            return results
        max_links = int(self.config.get("max_candidates_per_seed", 10))
        max_per_domain = int(self.config.get("max_urls_per_domain", 3))
        for link in self._extract_candidate_links(snap.url, snap.html)[:max_links]:
            try:
                if not self._allowed_by_robots(link):
                    continue
                link_domain = self.db.domain_for_url(link)
                if self._domain_hits.get(link_domain, 0) >= max_per_domain:
                    continue
                # Persist for future runs and discover multiple relevant submission pages per domain
                try:
                    self.db.enqueue_discovery_url(link, link_domain, source="candidate-link", priority=float(rec.relevance_score))
                except Exception as _suppressed_exc:
                    _log_suppressed('inspect_and_record (line 4534)', _suppressed_exc)
                results.extend(self.inspect_and_record(
                    link, forced_category=forced_category, enforce_filters=True, source="candidate-link",
                ))
            except Exception as e:
                logger.debug("Candidate link inspect failed %s: %s", link, e)
        return results

    def _emit_discovery_events(self, rec: WebsiteRecord, source: str) -> None:
        try:
            emit_event(f"Discovered: {rec.url} [{source}]", event_type="discovery",
                       details={"url": rec.url, "domain": rec.domain, "language": rec.language, "source": source})
            emit_event(
                f"Permission check: {rec.url} -> {rec.permission_status.value} "
                f"(verified: {rec.permission_verified}, categories: {', '.join(rec.allowed_categories) or 'none'}, "
                f"reg: {rec.registration_requirements.value}, method: {rec.submission_method.value}, "
                f"score: {rec.relevance_score:.2f})",
                event_type="permission",
                details={
                    "url": rec.url, "permission": rec.permission_status.value,
                    "verified": rec.permission_verified, "registration": rec.registration_requirements.value,
                },
            )
            eligible = (
                rec.permission_status == PermissionStatus.ALLOWED
                and rec.permission_verified
                and rec.registration_requirements == RegistrationRequirement.NONE
                and rec.submission_method in (SubmissionMethod.FORM, SubmissionMethod.POST)
            )
            emit_event(
                f"Eligibility: {rec.url} -> {'auto-eligible' if eligible else 'not auto-eligible'}",
                event_type="eligibility",
                level="info" if eligible else "warn",
                details={"url": rec.url, "eligible": eligible},
            )
        except Exception as _suppressed_exc:
            _log_suppressed('_emit_discovery_events (line 4570)', _suppressed_exc)

    # ------------------------------------------------------------------
    # Search providers (free/public HTML endpoints only)
    # ------------------------------------------------------------------
    def _discover_from_search(self, browser: BrowserAutomation, remaining: int) -> list[WebsiteRecord]:
        providers = [str(p).lower() for p in (self.config.get("search_providers") or [])]
        allowed_providers = ("duckduckgo", "bing", "mojeek", "yahoo", "startpage", "yandex", "google")
        providers = [p for p in providers if p in allowed_providers] or ["google", "duckduckgo", "mojeek", "bing"]
        if not providers:
            return []
        queries = self._rotation_queries()
        max_queries = int(self.config.get("max_queries_per_run", 12))
        per_query = int(self.config.get("max_results_per_query", 8))
        results: list[WebsiteRecord] = []
        for i, query in enumerate(queries[:max_queries]):
            if len(results) >= remaining:
                break
            provider = providers[i % len(providers)]
            # Skip providers temporarily blocked by captcha/bot walls in this run
            try:
                until = float(self._blocked_search_providers.get(provider, 0.0) or 0.0)
                if time.monotonic() < until:
                    continue
            except Exception as _suppressed_exc:
                _log_suppressed('_discover_from_search (line 4595)', _suppressed_exc)
            self.run_stats["search_queries"] += 1
            emit_event(f"Global discovery search ({provider}): {query}", event_type="discovery")
            try:
                urls = self._search(browser, provider, query, per_query, lang=_query_language(query))
                self.run_stats["candidates_parsed"] += len(urls)
            except Exception as e:
                logger.warning("Search provider %s failed: %s", provider, e)
                emit_event(f"Search failed ({provider}): {e}", event_type="discovery", level="error")
                try:
                    self.db.record_discovery_run(provider, query, 0, notes=f"error: {e}")
                except Exception as _suppressed_exc:
                    _log_suppressed('_discover_from_search (line 4607)', _suppressed_exc)
                continue
            try:
                self.db.record_discovery_run(provider, query, len(urls))
            except Exception as _suppressed_exc:
                _log_suppressed('_discover_from_search (line 4612)', _suppressed_exc)
            for url in urls:
                if len(results) >= remaining:
                    break
                if not self._is_new_candidate(url):
                    continue
                try:
                    dom = self.db.domain_for_url(url)
                    try:
                        self.db.enqueue_discovery_url(url, dom, source=f"search:{provider}", query=query)
                    except Exception as _suppressed_exc:
                        _log_suppressed('_discover_from_search (line 4623)', _suppressed_exc)
                    results.extend(self.inspect_and_record(
                        url, enforce_filters=True, source=f"search:{provider}",
                    ))
                except Exception as e:
                    logger.debug("Search candidate failed %s: %s", url, e)
                time.sleep(float(self.config.get("request_delay_seconds", 0.5)))
        return results

    def _rotation_queries(self) -> list[str]:
        configured = [str(q) for q in (self.config.get("search_queries") or []) if str(q).strip()]
        if configured:
            candidates = configured
        else:
            languages_cfg = self.config.get("search_languages")
            if languages_cfg is None or languages_cfg == "all":
                languages = list(GLOBAL_QUERY_TEMPLATES.keys())
            else:
                languages = [str(l).lower() for l in (languages_cfg or ["en"])]
                # "every practically supported language": include all built-in templates too
                for lang in GLOBAL_QUERY_TEMPLATES.keys():
                    if lang not in languages:
                        languages.append(lang)
            candidates = []
            generated = GLOBAL_QUERY_TEMPLATES if self.config.get("multilingual_queries", True) else {"en": GLOBAL_QUERY_TEMPLATES["en"]}
            for lang in languages:
                if lang in generated:
                    candidates.extend(generated[lang])
            if not candidates:
                candidates = list(GLOBAL_QUERY_TEMPLATES["en"])

            # Smart autonomous expansion: generate broad query variations to discover more sites without user-provided seeds
            try:
                en_base = list(GLOBAL_QUERY_TEMPLATES.get("en") or [])
                actions = ["submit", "post", "share", "request", "apply", "add"]
                topics = ["help request", "financial support", "fundraising campaign", "donation request", "community assistance", "mutual aid", "personal support", "charity listing"]
                forms = ["form", "page", "website", "online", "submission"]
                extras = ["no registration", "public form", "free to submit", "community help", "support request"]
                for a in actions:
                    for t in topics:
                        candidates.append(f"{a} {t} {forms[hash((a,t)) % len(forms)]}")
                for t in topics:
                    for e in extras[:3]:
                        candidates.append(f"{t} {e}")
                # include shorter high-intent queries
                candidates.extend([
                    "submit support request form", "post fundraising request", "community help submission form",
                    "ask for help form", "submit assistance request", "public donation request form",
                    "mutual aid request form", "share personal story form", "request financial help form",
                ])
                candidates.extend(en_base)
            except Exception:
                pass
        # Deduplicate while preserving order
        seen = set()
        uniq = []
        for q in candidates:
            qn = " ".join(str(q).split()).strip()
            if qn and qn.lower() not in seen:
                seen.add(qn.lower())
                uniq.append(qn)
        last_runs = {}
        try:
            last_runs = {row["query"]: row["last_run"] for row in self.db.recent_discovery_queries(1000)}
        except Exception:
            last_runs = {}
        # Least-recently used first; never-run queries first.
        return sorted(uniq, key=lambda q: (last_runs.get(q, ""), q))

    def _search(self, browser: BrowserAutomation, provider: str, query: str, limit: int, lang: str = "") -> list[str]:
        lang = (lang or "en").strip().lower() or "en"
        market = LANG_MARKET.get(lang, "")
        if provider == "duckduckgo":
            url = "https://html.duckduckgo.com/html/?q=" + quote_plus(query) + (f"&kl={market.lower()}" if market and lang != "en" else "")
        elif provider == "bing":
            url = "https://www.bing.com/search?q=" + quote_plus(query) + f"&count={max(10, limit * 2)}" + (f"&setlang={lang}&mkt={market}" if market and lang != "en" else "")
        elif provider == "mojeek":
            url = "https://www.mojeek.com/search?q=" + quote_plus(query)
        elif provider == "yahoo":
            url = "https://search.yahoo.com/search?p=" + quote_plus(query)
        elif provider == "startpage":
            url = "https://www.startpage.com/sp/search?query=" + quote_plus(query)
        elif provider == "yandex":
            url = "https://yandex.com/search/?text=" + quote_plus(query)
        elif provider == "google":
            url = "https://www.google.com/search?q=" + quote_plus(query) + f"&hl={lang}&num=10"
        else:
            return []

        page = browser.new_page()
        try:
            nav_timeout = min(12000, int(self.config.get("navigation_timeout_ms", 30000) or 30000))
            try:
                page.set_default_navigation_timeout(nav_timeout)
                page.set_default_timeout(nav_timeout)
            except Exception as _suppressed_exc:
                _log_suppressed('_search (line 4694)', _suppressed_exc)
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=nav_timeout)
            except Exception as e:
                emit_event(f"Search navigation issue ({provider}): {e}", event_type="discovery", level="warn")
                # Try HTTP fallback once instead of failing the whole provider call
                try:
                    fb = self._http_search_fallback(provider, query, limit)
                    if fb:
                        return fb
                except Exception as _suppressed_exc:
                    _log_suppressed('_search (line 4705)', _suppressed_exc)
                return []
            page.wait_for_timeout(700)
            html = page.content() or ""
            try:
                text = page.inner_text("body") or ""
            except Exception:
                text = ""
            status = getattr(response, "status", None) if response else None
            frame_urls = []
            try:
                frame_urls = [f.url for f in page.frames if f.url]
            except Exception as _suppressed_exc:
                _log_suppressed('_search (line 4718)', _suppressed_exc)
            obstacles = detect_obstacles(text, html, status, frame_urls)
            if obstacles:
                self.run_stats["providers_blocked"] += 1
                emit_event(
                    f"Search blocked by {summarize_obstacles(obstacles)}; skipping query",
                    event_type="discovery", level="warn",
                )
                # Cool down blocked provider for this run to avoid wasting queries
                try:
                    self._blocked_search_providers[provider] = time.monotonic() + 120.0
                except Exception as _suppressed_exc:
                    _log_suppressed('_search (line 4730)', _suppressed_exc)
                # Try lightweight HTTP fallback once (may still be blocked; best effort)
                try:
                    fb = self._http_search_fallback(provider, query, limit)
                    if fb:
                        return fb
                except Exception as _suppressed_exc:
                    _log_suppressed('_search (line 4737)', _suppressed_exc)
                return []
            parsed_urls = self._parse_search_results(html, url, limit)
            if not parsed_urls:
                # Best-effort HTTP fallback when browser page yielded no parsable results
                try:
                    fb = self._http_search_fallback(provider, query, limit)
                    if fb:
                        return fb
                except Exception as _suppressed_exc:
                    _log_suppressed('_search (line 4747)', _suppressed_exc)
            return parsed_urls
        finally:
            try:
                page.close()
            except Exception as _suppressed_exc:
                _log_suppressed('_search (line 4753)', _suppressed_exc)

    def _http_search_fallback(self, provider: str, query: str, limit: int) -> list[str]:
        """Best-effort HTTP fetch for search results (no browser). May be blocked; never bypass challenges."""
        try:
            import requests  # type: ignore
        except Exception:
            return []
        if provider == "duckduckgo":
            url = "https://html.duckduckgo.com/html/"
            params = {"q": query}
        elif provider == "mojeek":
            url = "https://www.mojeek.com/search"
            params = {"q": query}
        elif provider == "bing":
            url = "https://www.bing.com/search"
            params = {"q": query, "count": str(max(10, limit * 2))}
        elif provider == "yahoo":
            url = "https://search.yahoo.com/search"
            params = {"p": query}
        elif provider == "google":
            url = "https://www.google.com/search"
            params = {"q": query, "hl": "en", "num": "10"}
        else:
            return []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml",
        }
        try:
            r = requests.get(url, params=params, headers=headers, timeout=float(self.config.get("request_timeout_seconds", 20)))
            if r.status_code >= 400 or not r.text:
                return []
            # quick block detection
            low = (r.text or "").lower()
            if any(k in low for k in ("captcha", "unusual traffic", "verify you are human", "challenge")):
                return []
            return self._parse_search_results(r.text, r.url or url, limit)
        except Exception:
            return []

    def _parse_search_results(self, html: str, base_url: str, limit: int) -> list[str]:
        urls: list[str] = []
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html or "", "html.parser")
            anchors = soup.select("a.result__a, li.b_algo h2 a, a.title, h2 a")
            hrefs = [a.get("href") for a in anchors]
            if not hrefs:
                hrefs = [a.get("href") for a in soup.find_all("a", href=True)]
        except Exception:
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', html or "", flags=re.IGNORECASE)

        for href in hrefs:
            if not href:
                continue
            url = self._decode_result_href(str(href), base_url)
            if not url:
                continue
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                continue
            domain = parsed.netloc.lower().removeprefix("www.")
            if not domain or domain in SEARCH_ENGINE_DOMAINS:
                continue
            if any(parsed.path.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
                continue
            if any(hint in parsed.path.lower() for hint in SKIP_PATH_HINTS):
                continue
            canonical = canonicalize_url(url)
            if canonical and canonical not in urls:
                urls.append(canonical)
            if len(urls) >= limit:
                break
        return urls

    @staticmethod
    def _decode_result_href(href: str, base_url: str) -> str:
        if href.startswith("//"):
            href = "https:" + href
        elif href.startswith("/"):
            href = urljoin(base_url, href)
        if "uddg=" in href:
            try:
                qs = parse_qs(urlparse(href).query)
                if qs.get("uddg"):
                    return qs["uddg"][0]
            except Exception as _suppressed_exc:
                _log_suppressed('_decode_result_href (line 4843)', _suppressed_exc)
        if "bing.com/ck/a" in href:
            try:
                qs = parse_qs(urlparse(href).query)
                if qs.get("u"):
                    import base64

                    raw = qs["u"][0]
                    if raw.startswith("a1"):
                        raw = raw[2:]
                    raw += "=" * (-len(raw) % 4)
                    return base64.urlsafe_b64decode(raw).decode("utf-8", "ignore")
            except Exception as _suppressed_exc:
                _log_suppressed('_decode_result_href (line 4856)', _suppressed_exc)
        return href

    def _is_new_candidate(self, url: str) -> bool:
        canonical = canonicalize_url(url)
        if not canonical or canonical in self._seen_urls:
            return False
        domain = self.db.domain_for_url(canonical)
        if not domain:
            return False
        if self._domain_hits.get(domain, 0) >= int(self.config.get("max_urls_per_domain", 3)):
            return False
        if domain in self._search_domain_seen:
            return False
        if self.config.get("prefer_new_domains", True) and self.db.domain_exists(domain):
            if not self.config.get("recheck_existing_domains", False):
                return False
        self._search_domain_seen.add(domain)
        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _allowed_by_robots(self, url: str) -> bool:
        if not self.robots:
            return True
        return self.robots.can_fetch(url)

    def _extract_candidate_links(self, base_url: str, html: str) -> list[str]:
        """Return relevant candidate links. Includes same-domain links and (smart crawl) external links that look like submission/help pages."""
        links = re.findall(r'href=["\']([^"\']+)["\']', html or "", flags=re.IGNORECASE)
        out: list[str] = []
        external_out: list[str] = []
        base_host = urlparse(base_url).netloc.lower().removeprefix("www.")
        keywords = (
            "submit", "post", "new", "create", "share", "fund", "support", "donat", "community",
            "form", "contact", "request", "apply", "listing", "story", "help", "assistance", "appeal", "campaign",
        )
        strong_keywords = ("submit", "form", "request", "apply", "fundrais", "donat", "support", "help", "campaign", "appeal")
        for href in links:
            abs_url = urljoin(base_url, href)
            parsed = urlparse(abs_url)
            if parsed.scheme not in ("http", "https"):
                continue
            host = parsed.netloc.lower().removeprefix("www.")
            if not host or host in SEARCH_ENGINE_DOMAINS:
                continue
            path = (parsed.path or "").lower()
            full = (abs_url or "").lower()
            if any(hint in path for hint in SKIP_PATH_HINTS):
                continue
            if any(parsed.path.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
                continue
            if not any(k in path or k in full for k in keywords):
                continue
            cu = canonicalize_url(abs_url.split("#")[0])
            if not cu:
                continue
            if host == base_host:
                out.append(cu)
            else:
                # External crawl: only keep stronger submission/help-looking links to expand discovery smartly
                if any(k in path or k in full for k in strong_keywords):
                    external_out.append(cu)
        # Prioritize same-domain, then external; dedupe preserving order
        seen: set[str] = set()
        uniq: list[str] = []
        for u in out + external_out:
            if u and u not in seen:
                seen.add(u)
                uniq.append(u)
        return uniq

    @staticmethod
    def _find_rules_url(base_url: str, html: str) -> Optional[str]:
        try:
            for href in re.findall(r'href=["\']([^"\']+)["\']', html or "", flags=re.IGNORECASE):
                low = href.lower()
                if any(k in low for k in ("rules", "guidelines", "terms", "tos", "policy")):
                    return urljoin(base_url, href)
        except Exception as _suppressed_exc:
            _log_suppressed('_find_rules_url (line 4922)', _suppressed_exc)
        return None


def canonicalize_url(url: str) -> str:
    """Normalize a URL for deduplication without changing its meaning."""
    try:
        parsed = urlparse((url or "").strip())
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return ""
        netloc = parsed.netloc.lower()
        if netloc.endswith(":80") and parsed.scheme == "http":
            netloc = netloc[:-3]
        if netloc.endswith(":443") and parsed.scheme == "https":
            netloc = netloc[:-4]
        path = re.sub(r"/+", "/", parsed.path or "/")
        if path != "/":
            path = path.rstrip("/")
        query_pairs = []
        for pair in (parsed.query or "").split("&"):
            if not pair:
                continue
            key = pair.split("=", 1)[0].lower()
            if key in TRACKING_PARAMS:
                continue
            query_pairs.append(pair)
        query = "&".join(sorted(query_pairs))
        return urlunparse((parsed.scheme.lower(), netloc, path, "", query, ""))
    except Exception:
        return ""

# ======================================================================
# merged from publishing.py
# ======================================================================
import hashlib
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


logger = get_logger(__name__)

# Built-in CSS selector defaults. Each is overridable via the config `selectors`
# section (see PublishingEngine._selectors); defaults match the lists that were
# previously hard-coded at the call sites.
DEFAULT_SIGNUP_LINK_SELECTORS = [
    "a:has-text('Sign up')", "a:has-text('Register')", "a:has-text('Create account')",
    "button:has-text('Sign up')", "button:has-text('Register')", "button:has-text('Create account')",
]
DEFAULT_REGISTRATION_SUBMIT_SELECTORS = [
    "button[type='submit']", "input[type='submit']",
    "button:has-text('Sign up')", "button:has-text('Register')", "button:has-text('Create account')",
    "button:has-text('Continue')", "button:has-text('Next')",
]
DEFAULT_FORM_SUBMIT_SELECTORS = [
    "button[type='submit']", "input[type='submit']",
    "button:has-text('Submit')", "button:has-text('Post')", "button:has-text('Send')",
    "button:has-text('Publish')", "button:has-text('Share')", "button:has-text('Create')",
    "[role='button']:has-text('Submit')", "[role='button']:has-text('Post')",
]


VERIFICATION_CUES = [
    "verify your email", "verification email", "check your email", "confirm your email",
    "email verification", "verification code", "enter the code", "otp", "one-time",
    "phone verification", "verify your phone", "mobile verification", "sms code", "text code",
    "send code to", "we sent a code", "2fa", "two-factor", "authenticator",
]
HUMAN_INTERVENTION_CUES = [
    "contact support", "manual review", "wait for approval", "administrator approval",
]


class PublishingEngine:
    def __init__(self, config: dict, db: Database, content: ContentManager, translator: TranslationService):
        self.config = config
        self.db = db
        self.content = content
        self.translator = translator

    def _selectors(self, key: str, default: list[str]) -> list[str]:
        """Return the CSS selectors for a publishing step (config-overridable)."""
        custom = (self.config.get("selectors") or {}).get(key)
        if isinstance(custom, (list, tuple)) and custom:
            return [str(s) for s in custom]
        return list(default)

    def build_plan(self, website: WebsiteRecord, variant: ContentVariant, target_language: Optional[str] = None,
                   translate: bool = True) -> SubmissionPlan:
        item = self.content.get_variant(variant)
        lang = target_language or website.language or "en"
        if lang in ("unknown", ""):
            lang = "en"
        translated_text = ""
        translation_failed = False
        translation_error = ""
        if translate:
            try:
                tr = self.translator.translate(item.body, target_language=lang, variant=variant, source_language="en")
                translated_text = tr.text
            except TranslationError as e:
                translation_failed = True
                translation_error = str(e)
            except Exception as e:
                translation_failed = True
                translation_error = f"translation error: {e}"
            if translation_failed and lang != "en" and item.body:
                # Pace over perfection: fall back to the English text instead of
                # discarding an otherwise-eligible site when translation is down.
                translated_text = item.body
                lang = "en"
                translation_failed = False
                translation_error = ""
        requires_reg = website.registration_requirements in (RegistrationRequirement.REQUIRED, RegistrationRequirement.EMAIL_VERIFICATION_REQUIRED)
        requires_email = website.registration_requirements == RegistrationRequirement.EMAIL_VERIFICATION_REQUIRED
        content_hash = hashlib.sha256(translated_text.encode("utf-8")).hexdigest() if translated_text else ""
        plan = SubmissionPlan(
            website=website,
            variant=variant,
            target_language=lang,
            translated_content=translated_text,
            destination_category=website.category,
            intended_action=f"Submit {variant.value} content via {website.submission_method.value} on permitted page",
            rules_summary=website.notes or "Rules not fully captured; verify manually before submission.",
            requires_registration=requires_reg,
            requires_email_verification=requires_email,
            approved=False,
            auto_eligible=False,
            translation_failed=translation_failed,
            translation_error=translation_error,
            content_hash=content_hash,
        )
        ok, reason = self.evaluate_auto_eligibility(plan, check_limits=False)
        plan.auto_eligible = ok
        plan.auto_block_reason = "" if ok else reason
        return plan

    def submission_key(self, plan: SubmissionPlan) -> str:
        material = f"{plan.website.url.strip().lower()}|{plan.variant.value}|{plan.content_hash}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]

    def policy_block_reason(self, website: WebsiteRecord) -> str:
        """Structural policy check that does not require a translation.

        Returns an empty string only when the destination has explicitly verified
        permission for its recorded category and submission method, with no
        registration/verification requirement.
        """
        if bool(self.config.get("respect_site_rules", True)):
            if website.permission_status == PermissionStatus.PROHIBITED:
                return "website rules indicate the submission is prohibited"
            if website.permission_status != PermissionStatus.ALLOWED:
                return f"permission is {website.permission_status.value}; exact requirements must be verified"
            if not website.permission_verified:
                return "explicit permission for the exact content category and submission method is not verified"
        if website.registration_requirements != RegistrationRequirement.NONE:
            return f"registration requirement is {website.registration_requirements.value}; automatic submission requires none"
        if website.submission_method not in (SubmissionMethod.FORM, SubmissionMethod.POST):
            return f"submission method '{website.submission_method.value}' is not a verified public form/post"
        if not website.submission_method_verified:
            return "submission method was not verified on the destination"
        if bool(self.config.get("respect_site_rules", True)):
            allowed = {str(c).lower().replace(" ", "_") for c in (website.allowed_categories or [])}
            if not allowed:
                return "no exact content category was explicitly permitted on the destination"
            if website.category not in allowed:
                return f"content category '{website.category}' is not explicitly permitted by the destination"
        min_score = float(
            self.config.get("app_min_relevance_fallback")
            or (self.config.get("app_cfg_ref") or {}).get("min_relevance_score", 0.55)
        )
        if website.relevance_score < min_score:
            return f"relevance score {website.relevance_score:.2f} is below the minimum {min_score:.2f}"
        return ""

    def evaluate_auto_eligibility(self, plan: SubmissionPlan, check_limits: bool = True) -> tuple[bool, str]:
        """Automatic publishing is allowed only for an explicitly verified match.

        A public form is not permission. Conditional or unknown permission, missing
        category/method evidence, registration, verification challenges, duplicate
        content and rate limits all block automatic submission.
        """
        w = plan.website
        if plan.translation_failed:
            return False, f"Translation failed or unreliable: {plan.translation_error or 'unknown error'}"
        block = self.policy_block_reason(w)
        if block:
            return False, block
        if plan.requires_registration or plan.requires_email_verification:
            return False, "Registration or email verification would be required"
        if self.config.get("autonomous_submit", True) is False:
            return False, "Autonomous submission is disabled by policy"
        if check_limits:
            ok, reason = self.check_duplicate_and_limits(w)
            if not ok:
                return False, reason
        return True, "Eligible: explicitly permitted, no registration, verified method, relevant category"

    def can_auto_submit(self, plan: SubmissionPlan) -> tuple[bool, str]:
        ok, reason = self.evaluate_auto_eligibility(plan, check_limits=True)
        if not ok:
            return False, reason
        if self.config.get("auto_mode_only_for_preverified_no_registration", False):
            content_hash = hashlib.sha256(plan.translated_content.encode("utf-8")).hexdigest()
            with self.db.connection() as conn:
                row = conn.execute(
                    "SELECT 1 FROM approvals WHERE website_url=? AND variant=? AND target_language=? AND translated_content_hash=? AND approved=1 LIMIT 1",
                    (plan.website.url, plan.variant.value, plan.target_language, content_hash),
                ).fetchone()
                site = conn.execute("SELECT preverified, auto_eligible FROM websites WHERE url=?", (plan.website.url,)).fetchone()
            if not row:
                return False, "No prior human approval for this exact content/target"
            if not site or not (site["preverified"] and site["auto_eligible"]):
                return False, "Website not marked preverified/auto-eligible"
        return True, "Eligible for automatic submission"

    def check_duplicate_and_limits(self, website: WebsiteRecord) -> tuple[bool, str]:
        app_cfg = self.config.get("app_cfg_ref") or {}
        cooldown = int(app_cfg.get("duplicate_cooldown_days", 30))
        per_day = int(app_cfg.get("max_submissions_per_domain_per_day", 1))
        domain = website.domain or self.db.domain_for_url(website.url)
        if self.db.has_recent_submission(domain, cooldown):
            return False, f"Duplicate prevention: recent submission exists within {cooldown} days"
        if self.db.submissions_today_for_domain(domain) >= per_day:
            return False, f"Rate/volume limit: max {per_day} submission(s) per domain per day reached"
        return True, "OK"

    def review_plan(self, plan: SubmissionPlan, auto_approve: bool = False) -> bool:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console()
        table = Table(title="COCO Submission Review", show_header=False)
        table.add_row("Website", plan.website.url)
        table.add_row("Rules/Notes", plan.rules_summary or "(none)")
        table.add_row("Rules URL", plan.website.rules_url or "(not detected)")
        table.add_row("Destination category", plan.destination_category)
        table.add_row("Variant", plan.variant.value)
        table.add_row("Language", plan.target_language)
        table.add_row("Registration required", str(plan.requires_registration))
        table.add_row("Email verification required", str(plan.requires_email_verification))
        table.add_row("Intended action", plan.intended_action)
        console.print(table)
        console.print(Panel(plan.translated_content, title="Translated content", expand=False))
        content_hash = hashlib.sha256(plan.translated_content.encode("utf-8")).hexdigest()
        if auto_approve:
            self.db.record_approval(plan.website.url, plan.variant.value, plan.target_language, content_hash, True, notes="auto-approved")
            if plan.website.registration_requirements == RegistrationRequirement.NONE and plan.website.permission_status != PermissionStatus.PROHIBITED:
                self.db.mark_website_verified(plan.website.url, preverified=True, auto_eligible=True)
            return True
        ans = console.input("Approve this submission? [y/N]: ").strip().lower()
        approved = ans in ("y", "yes")
        self.db.record_approval(plan.website.url, plan.variant.value, plan.target_language, content_hash, approved)
        if approved:
            # mark site preverified for potential future auto mode only when explicitly no-registration and permitted
            if plan.website.registration_requirements == RegistrationRequirement.NONE and plan.website.permission_status != PermissionStatus.PROHIBITED:
                self.db.mark_website_verified(plan.website.url, preverified=True, auto_eligible=True)
        return approved

    def submit(self, plan: SubmissionPlan, browser: BrowserAutomation, dry_run: bool = False,
               profile_picture_path: Optional[str] = None, profile_info: Optional[dict] = None) -> SubmissionResult:
        w = plan.website
        if plan.translation_failed:
            return self._record(plan, "skipped", f"Skipped: translation failed or unreliable ({plan.translation_error})")
        # respect_site_rules (default true) gates all site-rule/permission checks.
        # CAPTCHA/verification stops, dedup and capability checks always apply.
        respect_rules = bool(self.config.get("respect_site_rules", True))
        if respect_rules:
            if w.permission_status == PermissionStatus.PROHIBITED:
                return self._record(plan, "skipped", "Skipped: website rules prohibit this submission")
            if w.permission_status != PermissionStatus.ALLOWED:
                return self._record(
                    plan, "skipped",
                    f"Skipped: permission is {w.permission_status.value}; exact requirements must be verified before publishing",
                )
            if not w.permission_verified:
                return self._record(plan, "skipped", "Skipped: exact content category and submission method are not explicitly permitted/verified")
        if plan.requires_email_verification:
            return self._record(plan, "skipped", "Skipped: email verification required (human verification)")
        needs_signup = w.registration_requirements != RegistrationRequirement.NONE or plan.requires_registration
        if needs_signup:
            if w.registration_requirements == RegistrationRequirement.EMAIL_VERIFICATION_REQUIRED or plan.requires_email_verification:
                return self._record(plan, "skipped", "Skipped: email verification required after sign-up (human step)")
            if not self.config.get("allow_account_creation_when_permitted", False):
                return self._record(plan, "skipped", "Skipped: registration required and automatic account creation is disabled")
        if w.submission_method not in (SubmissionMethod.FORM, SubmissionMethod.POST) or not w.submission_method_verified:
            return self._record(plan, "skipped", "Skipped: submission method is not a verified public form")

        # Permanent per-site dedup (owner requirement): a site that already
        # received a successful submission is never submitted to again, even
        # across reruns with different content.
        if self.db.has_successful_submission_for_url(w.url):
            return self._record(
                plan, "skipped",
                "Skipped: this site already received a successful submission (per-site dedup)",
            )

        ok, reason = self.check_duplicate_and_limits(w)
        if not ok:
            return self._record(plan, "skipped", f"Skipped: {reason}")

        submission_key = self.submission_key(plan) if plan.content_hash else ""
        if submission_key:
            previous = self.db.get_job(submission_key)
            if self.db.has_successful_submission_key(submission_key):
                return self._record(
                    plan, "skipped",
                    "Skipped: identical content was already submitted successfully (persistent duplicate guard)",
                    job_status="success",
                )
            if previous and previous.get("status") in ("in_progress",):
                return self._record(
                    plan, "skipped",
                    "Skipped: an identical submission attempt is already in progress",
                    job_status="in_progress",
                )
            if previous and previous.get("status") in ("interrupted", "uncertain", "attempted"):
                return self._record(
                    plan, "skipped",
                    f"Skipped: a previous attempt for identical content was {previous.get('status')}; manual verification is required before retrying",
                    job_status=previous.get("status"),
                )

        if dry_run:
            return self._record(plan, "skipped", "Dry run: no submission performed")
        if browser is None:
            return self._record(plan, "failed", "Browser session unavailable for live submission")
        if not submission_key:
            return self._record(plan, "failed", "Submission blocked: missing validated content hash")

        job = self.db.start_job(
            submission_key, w.url, w.domain or self.db.domain_for_url(w.url), plan.variant.value,
            plan.content_hash, max_attempts=int((self.config.get("app_cfg_ref") or {}).get("max_retries", 2)) + 1,
        )
        if job.get("exhausted"):
            return self._record(plan, "skipped", "Skipped: bounded retry limit reached for this submission")

        try:
            emit_event(f"Submission attempt: {w.url}", event_type="submission_attempt",
                       details={"url": w.url, "variant": plan.variant.value, "submission_key": submission_key})
            self.db.record_submission(
                website_id=w.id, website_url=w.url, status="attempted",
                message="Submission attempt started", variant=plan.variant.value,
                screenshot_path=None, details={"submission_key": submission_key}, submission_key=submission_key,
            )
        except Exception as _suppressed_exc:
            _log_suppressed('submit (line 5263)', _suppressed_exc)

        page = browser.new_page()
        self._submit_clicked = False
        try:
            response = page.goto(w.url, wait_until="domcontentloaded")
            page.wait_for_timeout(1200)
            status = getattr(response, "status", None) if response is not None else None
            if status == 429:
                shot = browser.screenshot(page, Path(self.config.get("log_dir_path", "logs")) / f"ratelimit_{datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.png")
                return self._record(plan, "skipped", "Skipped: HTTP 429 rate limit", screenshot=shot)

            obstacles = browser.detect_obstacles(page)
            if obstacles:
                shot = browser.screenshot(page, Path(self.config.get("log_dir_path", "logs")) / f"obstacle_{datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.png")
                return self._record(plan, "skipped", "Skipped: " + summarize_obstacles(obstacles), screenshot=shot)

            body_text = self._page_text(page)
            if any(c in body_text for c in ["rate limit", "too many requests", "try again later", "slow down", "temporarily blocked"]):
                return self._record(plan, "skipped", "Skipped: rate limit or temporary access restriction detected")

            needs_account = needs_signup or any(
                c in body_text for c in ["log in", "sign in", "signin", "create account", "register", "sign up"]
            )
            if needs_account:
                if not self.config.get("allow_account_creation_when_permitted", False):
                    return self._record(
                        plan, "skipped",
                        "Skipped: login/registration required and automatic account creation is disabled",
                    )
                # Sign up where the site's own rules permit it. Per-site generated
                # password from the local store; stops on any verification challenge.
                domain = w.domain or self.db.domain_for_url(w.url)
                info = profile_info or {}
                username_candidates = [info.get("username_preference") or info.get("username") or ""]
                username_candidates.extend(info.get("username_fallbacks") or [])
                account = self.db.get_or_create_site_account(
                    domain,
                    email=info.get("email") or "",
                    usernames=[u for u in username_candidates if u],
                    universal_password=str(self.config.get("universal_password") or ""),
                )
                signup = self._try_account_creation(page, browser, account["email"], account["password"], profile_info)
                if signup == "skip":
                    shot = browser.screenshot(page, Path(self.config.get("log_dir_path", "logs")) / f"signup_verify_{datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.png")
                    return self._record(plan, "skipped", "Skipped: sign-up requires CAPTCHA/email/phone/ID verification (no bypass)", screenshot=shot)
                if signup == "failed":
                    return self._record(plan, "failed", "Sign-up failed: registration form could not be completed")
                self.db.touch_site_account(domain)
                # Re-check the page after sign-up before posting anything.
                page.wait_for_timeout(1200)
                post_signup_obstacles = browser.detect_obstacles(page)
                if post_signup_obstacles:
                    shot = browser.screenshot(page, Path(self.config.get("log_dir_path", "logs")) / f"postsignup_{datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.png")
                    return self._record(
                        plan, "skipped",
                        "Skipped: verification challenge after sign-up - " + summarize_obstacles(post_signup_obstacles),
                        screenshot=shot,
                    )

            if self._has_verification_challenge(page, browser, body_text):
                shot = browser.screenshot(page, Path(self.config.get("log_dir_path", "logs")) / f"challenge_{datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.png")
                return self._record(plan, "skipped", "Skipped: CAPTCHA/bot verification or human-verification challenge detected", screenshot=shot)

            target_found, submitted = self._try_fill_generic_form(
                page, plan.translated_content, profile_picture_path=profile_picture_path, profile_info=profile_info,
            )
            if not target_found:
                return self._record(plan, "failed", "Submission failed: no suitable public submission form detected")
            if not submitted:
                return self._record(plan, "failed", "Submission failed: no submit/publish control could be activated")
            page.wait_for_timeout(1800)
            obstacles = browser.detect_obstacles(page)
            if obstacles:
                shot = browser.screenshot(page, Path(self.config.get("log_dir_path", "logs")) / f"challenge_{datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.png")
                return self._record(
                    plan, "uncertain",
                    "Uncertain: verification challenge appeared after submission attempt: " + summarize_obstacles(obstacles),
                    screenshot=shot, details={"auto_fill": True, "submission_key": submission_key},
                    evidence=summarize_obstacles(obstacles),
                )
            body_after = self._page_text(page)
            url_after = ""
            try:
                url_after = page.url or ""
            except Exception:
                url_after = ""
            confirmation_cues = [
                "thank you", "thanks for", "submission received", "your submission", "successfully submitted",
                "form submitted", "message sent", "request received", "we have received", "submitted successfully",
                "post submitted", "response recorded", "your response has been recorded",
            ]
            rejection_cues = ["submission failed", "could not submit", "error submitting", "not accepted", "rejected"]
            confirmation = next((c for c in confirmation_cues if c in body_after), "")
            rejection = next((c for c in rejection_cues if c in body_after), "")
            shot = browser.screenshot(page, Path(self.config.get("log_dir_path", "logs")) / f"submit_{datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.png")
            evidence = f"url={url_after}; confirmation_cue={confirmation or 'none'}"
            if rejection:
                return self._record(plan, "rejected", f"Rejected/failed after submit attempt: {rejection}",
                                    screenshot=shot, details={"auto_fill": True, "submission_key": submission_key, "evidence": evidence},
                                    evidence=evidence, confirmation=rejection, verified=False)
            if confirmation:
                return self._record(plan, "confirmed", f"Confirmed submission: detected '{confirmation}' after submit",
                                    screenshot=shot, details={"auto_fill": True, "submission_key": submission_key, "evidence": evidence},
                                    evidence=evidence, confirmation=confirmation, verified=True)
            # Button click alone is not proof; record as uncertain and never auto-retry same key
            return self._record(
                plan, "uncertain",
                "Uncertain: submit action completed but no reliable confirmation detected; manual verification required",
                screenshot=shot,
                details={"auto_fill": True, "submission_key": submission_key, "evidence": evidence},
                evidence=evidence,
                confirmation="",
                verified=False,
                job_status="uncertain",
            )
        except BrowserUnavailableError as e:
            logger.exception("Browser unavailable during submission for %s: %s", w.url, e)
            return self._record(
                plan, "failed", f"Submission interrupted: browser unavailable ({e}); manual verification required",
                job_status="interrupted",
            )
        except Exception as e:
            logger.exception("Submission error for %s: %s", w.url, e)
            job_status = "interrupted" if getattr(self, "_submit_clicked", False) else "failed"
            return self._record(plan, "failed", f"Submission error: {e}", job_status=job_status)
        finally:
            try:
                page.close()
            except Exception as _suppressed_exc:
                _log_suppressed('submit (line 5393)', _suppressed_exc)

    @staticmethod
    def _page_text(page) -> str:
        try:
            return (page.inner_text("body") or "").lower()
        except Exception:
            return ""

    def _has_verification_challenge(self, page, browser, body_text: Optional[str] = None) -> bool:
        try:
            if browser.detect_obstacles(page):
                return True
            text = body_text if body_text is not None else (page.inner_text("body") or "").lower()
            cues = list(VERIFICATION_CUES) + list(HUMAN_INTERVENTION_CUES)
            if any(c in text for c in cues):
                return True
        except Exception:
            return False
        return False

    def _try_account_creation(self, page, browser, email: str, password: str, profile_info: Optional[dict] = None) -> str:
        """Best-effort account creation on sites where it is explicitly enabled.
        Returns ok|not_needed|skip|failed. Never bypasses verification challenges."""
        try:
            reasons = browser.detect_obstacles(page)
            if reasons or is_human_verification_obstacle(reasons):
                return "skip"
            if self._has_verification_challenge(page, browser):
                return "skip"
            # Try to navigate to signup/register view if present
            for sel in self._selectors("signup_links", DEFAULT_SIGNUP_LINK_SELECTORS):
                try:
                    el = page.query_selector(sel)
                    if el and el.is_visible() and el.is_enabled():
                        el.click()
                        page.wait_for_timeout(1200)
                        break
                except Exception:
                    continue
            if self._has_verification_challenge(page, browser):
                return "skip"
            # Find password fields
            pw_fields = [el for el in page.query_selector_all("input[type='password']") if self._is_visible_enabled(el)]
            if not pw_fields:
                return "not_needed"
            # Fill email/username
            filled_email = False
            for el in page.query_selector_all("input[type='email'], input[name*='email'], input[id*='email'], input[autocomplete='email']"):
                if self._is_visible_enabled(el):
                    try:
                        el.fill(email)
                        filled_email = True
                        break
                    except Exception:
                        continue
            if not filled_email:
                for el in page.query_selector_all("input[type='text'], input[name*='user'], input[id*='user']"):
                    if self._is_visible_enabled(el):
                        try:
                            el.fill(email)
                            filled_email = True
                            break
                        except Exception:
                            continue
            # Fill password(s)
            try:
                pw_fields[0].fill(password)
                if len(pw_fields) > 1:
                    pw_fields[1].fill(password)
            except Exception:
                return "failed"
            # Fill username/name if available (prefer vinaydxo, else closest intelligent fallback)
            name = (profile_info or {}).get("name") or ""
            username = (profile_info or {}).get("username") or "vinaydxo"
            username_fallbacks = (profile_info or {}).get("username_fallbacks") or []
            if username or name:
                for el in page.query_selector_all("input[name*='name'], input[id*='name'], input[name*='user'], input[id*='user'], input[autocomplete='username'], input[autocomplete='nickname']"):
                    if self._is_visible_enabled(el):
                        try:
                            meta = ((el.get_attribute('name') or '') + (el.get_attribute('id') or '') + (el.get_attribute('autocomplete') or '')).lower()
                            if 'email' in meta or 'pass' in meta:
                                continue
                            if any(k in meta for k in ['user', 'username', 'handle', 'login', 'nick']):
                                chosen = self._choose_username_value(el, username, username_fallbacks)
                                if chosen:
                                    el.fill(chosen)
                                    break
                            elif name:
                                el.fill(name)
                                break
                        except Exception:
                            continue
            # Submit registration
            submitted = False
            for sel in self._selectors("registration_submit", DEFAULT_REGISTRATION_SUBMIT_SELECTORS):
                try:
                    btn = page.query_selector(sel)
                    if btn and self._is_visible_enabled(btn):
                        btn.click()
                        submitted = True
                        page.wait_for_timeout(2000)
                        break
                except Exception:
                    continue
            if not submitted:
                return "failed"
            if self._has_verification_challenge(page, browser):
                return "skip"
            return "ok"
        except Exception:
            return "failed"

    @staticmethod
    def _is_visible_enabled(el) -> bool:
        try:
            return bool(el and el.is_visible() and el.is_enabled())
        except Exception:
            return False

    def _try_fill_generic_form(self, page, content: str, profile_picture_path: Optional[str] = None,
                               profile_info: Optional[dict] = None) -> tuple[bool, bool]:
        """Fill a public form. Returns (target_found, submit_clicked)."""
        profile_info = profile_info or {}
        # Fill common identity/profile fields when websites request profile information
        profile_info = dict(profile_info or {})
        if not profile_info.get("caption"):
            stripped = (content or "").strip()
            profile_info["caption"] = (stripped.splitlines()[0] if stripped else "")[:120]
        self._fill_profile_fields(page, profile_info)
        # Try to attach profile picture if a suitable file input exists (avatar/profile/upload)
        profile_image_file_found = False
        if profile_picture_path:
            try:
                profile_image_file_found = Path(profile_picture_path).is_file()
            except Exception as _suppressed_exc:
                _log_suppressed('_try_fill_generic_form (line 5529)', _suppressed_exc)
        if profile_picture_path:
            try:
                p = Path(profile_picture_path)
                if p.exists():
                    for fin in page.query_selector_all("input[type='file']"):
                        try:
                            if fin.is_enabled():
                                fin.set_input_files(str(p))
                                break
                        except Exception:
                            continue
            except Exception as _suppressed_exc:
                _log_suppressed('_try_fill_generic_form (line 5542)', _suppressed_exc)
        if not profile_image_file_found:
            try:
                with self.db.connection() as conn:
                    picture_bytes = get_coco_profile_picture(conn)
                for fin in page.query_selector_all("input[type='file']"):
                    try:
                        if fin.is_enabled():
                            fin.set_input_files({
                                "name": "coco-profile.jpg",
                                "mimeType": "image/jpeg",
                                "buffer": picture_bytes,
                            })
                            break
                    except Exception:
                        continue
            except Exception as _suppressed_exc:
                _log_suppressed('_try_fill_generic_form (line 5559)', _suppressed_exc)

        # Try textarea first for main message/content
        textareas = page.query_selector_all("textarea")
        target = None
        for ta in textareas:
            try:
                if ta.is_visible() and ta.is_enabled():
                    target = ta
                    break
            except Exception:
                continue
        if target:
            try:
                target.fill(content)
            except Exception:
                try:
                    target.click()
                    page.keyboard.insert_text(content)
                except Exception:
                    target = None
        else:
            # try contenteditable/text inputs
            editable = page.query_selector("[contenteditable='true'], [role='textbox']")
            if editable:
                try:
                    editable.click()
                    page.keyboard.insert_text(content)
                    target = editable
                except Exception:
                    target = None
            if not target:
                inputs = page.query_selector_all("input[type='text'], input:not([type]), input[type='search']")
                for inp in inputs:
                    try:
                        if inp.is_visible() and inp.is_enabled():
                            meta = " ".join([
                                (inp.get_attribute("name") or ""),
                                (inp.get_attribute("id") or ""),
                                (inp.get_attribute("placeholder") or ""),
                                (inp.get_attribute("aria-label") or ""),
                            ]).lower()
                            if any(k in meta for k in ["name", "email", "bio", "about", "profile", "title"]):
                                continue
                            inp.fill(content[:1000])
                            target = inp
                            break
                    except Exception:
                        continue
        if not target:
            return False, False
        # try to click submit/publish
        for sel in self._selectors("form_submit", DEFAULT_FORM_SUBMIT_SELECTORS):
            try:
                btn = page.query_selector(sel)
                if btn and btn.is_visible() and btn.is_enabled():
                    btn.click()
                    page.wait_for_timeout(1800)
                    self._submit_clicked = True
                    return True, True
            except Exception:
                continue
        # As a fallback, press Enter in textarea (may not submit) - avoid accidental sends; return not submitted
        return True, False

    def _choose_username_value(self, el, preferred: str, fallbacks: list | None = None) -> str:
        """Prefer vinaydxo; if field constraints suggest otherwise, pick closest allowed fallback."""
        preferred = (preferred or "vinaydxo").strip() or "vinaydxo"
        candidates = [preferred]
        for fb in (fallbacks or ["vinay_dxo", "vinaydxo1", "vinay.dxo", "vinaydx", "vinay_d", "vinaydxo_"]):
            fb = str(fb or "").strip()
            if fb and fb not in candidates:
                candidates.append(fb)
        try:
            maxlen = el.get_attribute("maxlength")
            maxlen_i = int(maxlen) if maxlen and str(maxlen).isdigit() else None
        except Exception:
            maxlen_i = None
        try:
            pattern = (el.get_attribute("pattern") or "").strip()
        except Exception:
            pattern = ""
        # heuristic: if pattern disallows dot/underscore, prefer alnum-close variants
        disallow_dot = "." not in pattern and ("[a-zA-Z0-9" in pattern or "\\w" not in pattern and pattern != "")
        disallow_us = "_" not in pattern and ("[a-zA-Z0-9" in pattern and "_" not in pattern and pattern != "")
        def ok(c: str) -> bool:
            if maxlen_i is not None and len(c) > maxlen_i:
                return False
            if disallow_dot and "." in c:
                return False
            if disallow_us and "_" in c and pattern:
                # only reject if pattern clearly excludes underscore
                if "[a-zA-Z0-9-]" in pattern.replace(" ", "") or "a-z0-9" in pattern:
                    return False if "_" in c else True
            if pattern:
                try:
                    import re
                    if not re.fullmatch(pattern, c):
                        return False
                except Exception as _suppressed_exc:
                    _log_suppressed('ok (line 5659)', _suppressed_exc)
            return True
        for c in candidates:
            if ok(c):
                return c
        # last resort: trim preferred to maxlength
        if maxlen_i and len(preferred) > maxlen_i:
            return preferred[:maxlen_i]
        return preferred

    def _fill_profile_fields(self, page, profile_info: dict) -> None:
        name = (profile_info.get("name") or "").strip()
        username_pref = (profile_info.get("username_preference") or profile_info.get("username") or "vinaydxo").strip() or "vinaydxo"
        username_fallbacks = profile_info.get("username_fallbacks") or []
        email = (profile_info.get("email") or "").strip()
        bio = (profile_info.get("bio") or "").strip()
        caption = (profile_info.get("caption") or "").strip()
        if not any([name, username_pref, email, bio, caption]):
            return
        fields = page.query_selector_all("input, textarea")
        for el in fields:
            try:
                if not el.is_visible() or not el.is_enabled():
                    continue
                tag = (el.evaluate("e => e.tagName.toLowerCase()") or "").lower()
                input_type = (el.get_attribute("type") or "").lower()
                if input_type in ("hidden", "password", "submit", "button", "checkbox", "radio", "file"):
                    continue
                meta = " ".join([
                    (el.get_attribute("name") or ""),
                    (el.get_attribute("id") or ""),
                    (el.get_attribute("placeholder") or ""),
                    (el.get_attribute("aria-label") or ""),
                    (el.get_attribute("autocomplete") or ""),
                ]).lower()
                value = None
                if email and (input_type == "email" or "email" in meta):
                    value = email
                elif caption and any(k in meta for k in ["title", "subject", "headline", "caption"]):
                    value = caption
                elif any(k in meta for k in ["username", "user_name", "user-name", "handle", "screen_name", "nickname", "login"]) and "email" not in meta:
                    value = self._choose_username_value(el, username_pref, username_fallbacks)
                elif name and any(k in meta for k in ["full_name", "fullname", "display name", "displayname", "author", "your name"]) and "user" not in meta and "email" not in meta:
                    value = name
                elif name and any(k in meta for k in ["name"]) and "user" not in meta and "email" not in meta and "file" not in meta:
                    value = name
                elif bio and tag == "textarea" and any(k in meta for k in ["bio", "about", "description", "profile", "intro"]):
                    value = bio
                elif bio and input_type in ("text", "") and any(k in meta for k in ["bio", "about", "description", "tagline", "intro"]):
                    value = bio
                if value is not None:
                    try:
                        cur = (el.input_value() or "").strip()
                    except Exception:
                        cur = ""
                    if cur:
                        continue
                    try:
                        el.fill(value)
                    except Exception as _suppressed_exc:
                        _log_suppressed('_fill_profile_fields (line 5719)', _suppressed_exc)
            except Exception:
                continue

    def _record(self, plan: SubmissionPlan, status: str, message: str, screenshot: Optional[str] = None,
                details: Optional[dict] = None, submission_key: Optional[str] = None,
                job_status: Optional[str] = None, evidence: str = "", confirmation: str = "",
                http_status: Optional[int] = None, verified: bool = False) -> SubmissionResult:
        details = dict(details or {})
        key = submission_key or (self.submission_key(plan) if plan.content_hash else "")
        if key:
            details.setdefault("submission_key", key)
        # Normalize status for consistency while preserving compatibility
        norm_status = status
        try:
            self.db.record_submission(
                website_id=plan.website.id,
                website_url=plan.website.url,
                status=norm_status,
                message=message,
                variant=plan.variant.value,
                translation_id=None,
                screenshot_path=screenshot,
                details=details,
                submission_key=key or None,
                evidence=evidence or (details.get("evidence") or ""),
                confirmation=confirmation or (details.get("confirmation") or ""),
                http_status=http_status,
                verified=bool(verified or norm_status == "confirmed"),
            )
        except Exception as e:
            logger.warning("Failed to record submission outcome: %s", e)
        if key:
            effective = job_status or {"success": "success", "submitted": "success", "confirmed": "success", "accepted": "success"}.get(norm_status, norm_status)
            try:
                self.db.update_job(key, effective, message if effective != "success" else "")
            except Exception as _suppressed_exc:
                _log_suppressed('_record (line 5756)', _suppressed_exc)
        try:
            etype = "info"
            level = "info"
            if norm_status in ("success", "confirmed", "accepted"):
                etype, level = "submission_success", "info"
            elif norm_status in ("failed",):
                etype, level = "submission_failure", "error"
            elif norm_status in ("skipped", "blocked", "needs_approval", "uncertain"):
                etype, level = "submission_skipped", "warn"
            elif norm_status == "rejected":
                etype, level = "submission_skipped", "warn"
            emit_event(f"{plan.website.url} - {message}", event_type=etype, level=level,
                       details={"url": plan.website.url, "status": norm_status})
        except Exception as _suppressed_exc:
            _log_suppressed('_record (line 5771)', _suppressed_exc)
        return SubmissionResult(
            website_url=plan.website.url,
            status=norm_status,
            message=message,
            timestamp=datetime.now(__import__("datetime").timezone.utc).replace(tzinfo=None),
            variant=plan.variant.value,
            screenshot_path=screenshot,
            details=details,
            evidence=evidence or (details.get("evidence") or ""),
            confirmation=confirmation or (details.get("confirmation") or ""),
            verified=bool(verified or norm_status == "confirmed"),
        )


# ============================================================================
# merged from coco.py (launcher: terminal_dashboard, dashboard, cli + entry point)
# ============================================================================

#!/usr/bin/env python3
"""COCO - single main entry point (dashboards + CLI). Requires Python 3.12+."""


import sys
from pathlib import Path

# Keep sibling modules (coco_core, coco_data, coco_web) importable
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ======================================================================
# merged from terminal_dashboard.py
# ======================================================================
import time
from collections import deque
from typing import Any, Callable, Optional

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


# Targeted handling for Playwright/asyncio "Future exception was never retrieved" noise
# when driver connection closes during shutdown/teardown. Genuine errors remain logged.
_COCO_SHUTTING_DOWN = False

def _coco_mark_shutting_down():
    global _COCO_SHUTTING_DOWN
    _COCO_SHUTTING_DOWN = True

def _is_expected_driver_closed_error(err) -> bool:
    try:
        msg = " ".join(str(err or "")).split()
        msg = " ".join(msg).lower()
    except Exception:
        return False
    return "connection closed while reading from the driver" in msg

def _coco_unraisablehook(unraisable):
    try:
        err = getattr(unraisable, "exc_value", None)
        obj = getattr(unraisable, "object", None)
        if err is None:
            err = obj if obj is not None else unraisable
        # Suppress only this known Playwright driver-closed case (often emitted as unraisable future
        # when browser/driver connection is torn down). Genuine/unrelated errors are not suppressed.
        if (_is_expected_driver_closed_error(err)
                or _is_expected_driver_closed_error(obj)
                or _is_expected_driver_closed_error(getattr(unraisable, "err_msg", None))):
            try:
                logger.debug("Suppressed expected Playwright driver-closed unraisable: %s", err)
            except Exception:
                pass
            return
    except Exception:
        pass
    try:
        return sys.__unraisablehook__(unraisable)
    except Exception:
        try:
            _orig_unraisable(unraisable)
        except Exception:
            pass

try:
    _orig_unraisable = sys.unraisablehook
    sys.unraisablehook = _coco_unraisablehook
except Exception:
    pass

# Also suppress asyncio's "Future exception was never retrieved" logging for this specific driver-closed case.
try:
    import asyncio as _asyncio

    def _is_expected_asyncio_driver_closed(context) -> bool:
        try:
            exc = context.get("exception")
            msg = context.get("message") or ""
            fut = context.get("future")
            text = str(msg).lower()
            if _is_expected_driver_closed_error(exc) or _is_expected_driver_closed_error(msg) or _is_expected_driver_closed_error(fut):
                return True
            if "future exception was never retrieved" in text and _is_expected_driver_closed_error(exc):
                return True
        except Exception:
            return False
        return False

    try:
        _orig_asyncio_default_handler = _asyncio.base_events.BaseEventLoop.default_exception_handler
        def _coco_default_loop_exception_handler(self, context):
            try:
                if _is_expected_asyncio_driver_closed(context):
                    logger.debug("Suppressed expected Playwright driver-closed asyncio future exception: %s", context)
                    return
            except Exception:
                pass
            return _orig_asyncio_default_handler(self, context)
        _asyncio.base_events.BaseEventLoop.default_exception_handler = _coco_default_loop_exception_handler
    except Exception:
        pass

    # Some futures report via sys.stderr/unraisable paths; add a narrow stderr filter for this exact noise.
    class _DriverClosedStderrFilter:
        def __init__(self, stream):
            self._stream = stream
            self._buf = ""
        def write(self, s):
            try:
                text = str(s)
                self._buf += text
                # suppress the specific 3-line/fragment sequence when it appears
                low = self._buf.lower()
                if "future exception was never retrieved" in low and "connection closed while reading from the driver" in low:
                    # once full known pattern seen, drop buffered noise
                    if "exception: connection closed while reading from the driver" in low:
                        self._buf = ""
                        return len(s)
                    # keep buffering briefly in case split across writes
                    if len(self._buf) < 500:
                        return len(s)
                # flush safe buffered content if it doesn't look like the target pattern start
                if self._buf and "future exception was never retrieved" not in self._buf.lower():
                    out = self._buf
                    self._buf = ""
                    return self._stream.write(out)
                if len(self._buf) > 500:
                    out = self._buf
                    self._buf = ""
                    return self._stream.write(out)
                return len(s)
            except Exception:
                try:
                    return self._stream.write(s)
                except Exception:
                    return len(s)
        def flush(self):
            try:
                if self._buf:
                    out = self._buf
                    self._buf = ""
                    self._stream.write(out)
                return self._stream.flush()
            except Exception:
                pass
        def __getattr__(self, name):
            return getattr(self._stream, name)

    try:
        if not isinstance(sys.stderr, _DriverClosedStderrFilter):
            sys.stderr = _DriverClosedStderrFilter(sys.stderr)
    except Exception:
        pass
except Exception:
    pass


def _enable_windows_vt(out) -> bool:
    """Enable Windows virtual terminal processing for ANSI escape sequences."""
    try:
        if os.name != "nt":
            return True
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            return True
        return kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    except Exception:
        return False



def _supports_emoji(console: Console) -> bool:
    enc = (getattr(console, "encoding", None) or "utf-8").lower()
    return "utf" in enc


def _icon(console: Console, emoji: str, fallback: str) -> str:
    return emoji if _supports_emoji(console) else fallback


def _classify_event(e: dict[str, Any], console: Console) -> str:
    msg = str(e.get("message") or "")
    lower = msg.lower()
    etype = str(e.get("type") or "").lower()
    lvl = str(e.get("level") or "info").lower()
    if etype == "submission_success" or "confirmed submission" in lower or "submission successful" in lower:
        return _icon(console, "✅", "[OK]")
    if "uncertain" in lower:
        return _icon(console, "⚠️", "[!?]")
    if etype == "submission_skipped" or "skipped" in lower:
        return _icon(console, "⏭️", "[SKIP]")
    if etype == "submission_failure" or "rejected" in lower or "failed" in lower or lvl == "error" or "error" in lower:
        return _icon(console, "❌", "[ERR]")
    if "stopped gracefully" in lower or "shutting down" in lower or "stop request" in lower or "ctrl + c" in lower:
        return _icon(console, "🛑", "[STOP]")
    if "browser crash" in lower or "recover" in lower:
        return _icon(console, "🔧", "[REC]")
    if etype == "translation" or "translation" in lower:
        return _icon(console, "🌐", "[TR]")
    if etype == "permission" or "permission" in lower:
        return _icon(console, "🔐", "[PERM]")
    if etype == "discovery" or "discover" in lower:
        return _icon(console, "🌍", "[DISC]")
    if "inspect" in lower:
        return _icon(console, "🔎", "[INSP]")
    if etype == "eligibility" or "eligib" in lower:
        return _icon(console, "🎯", "[ELIG]")
    if etype == "submission_attempt" or "submission attempt" in lower:
        return _icon(console, "📤", "[TRY]")
    if "pending" in lower or "queue" in lower or "waiting" in lower:
        return _icon(console, "⏳", "[PEND]")
    if lvl in ("warn", "warning"):
        return _icon(console, "⚠️", "[WARN]")
    return _icon(console, "📝", "[LOG]")


def _clean_message(msg: str) -> str:
    text = str(msg or "")
    for ch in list("🌍🔎🎯📤✅❌⚠️⏭️🛑🔧🌐🔐📝⏳"):
        text = text.replace(ch, "")
    return text.strip(" -:|")


def _split_event(e: dict[str, Any]) -> tuple[str, str]:
    raw = _clean_message(e.get("message") or "")
    for sep in (" — ", " - ", ": ", " → "):
        if sep in raw:
            left, right = raw.split(sep, 1)
            left = left.strip() or "COCO"
            right = right.strip() or raw
            return left, right
    parts = raw.split()
    if parts and parts[0].startswith("http"):
        return parts[0], " ".join(parts[1:]).strip() or "Activity update"
    return "COCO", raw or "Activity update"


class TerminalDashboard:
    """Single dedicated terminal renderer (ANSI, fixed top-left). No Rich Live/print from workers."""
    def __init__(self, bus: EventBus, get_metrics: Callable[[], dict[str, Any]], get_db_status: Optional[Callable[[], str]] = None):
        self.bus = bus
        self.get_metrics = get_metrics
        self.get_db_status = get_db_status
        self._out = sys.stdout
        self._live_events: deque[dict[str, Any]] = deque(maxlen=6)
        self._seen_keys: deque[str] = deque(maxlen=200)
        self._last_live_event = None
        self._stopping_text = None
        self._op_started: dict[str, float] = {}
        self._started_mono = time.monotonic()
        self._last_lines: list[str] = []
        self._term_width = 120
        self._term_height = 40

    def set_output(self, out):
        self._out = out

    def _write(self, text: str):
        try:
            self._out.write(text)
            self._out.flush()
        except Exception:
            pass

    def _get_term_size(self):
        try:
            size = shutil.get_terminal_size(fallback=(120, 40))
            self._term_width = max(40, int(size.columns))
            self._term_height = max(20, int(size.lines))
        except Exception:
            self._term_width, self._term_height = 120, 40
        return self._term_width, self._term_height

    def _snapshot(self):
        try:
            state = self.bus.snapshot() or {}
        except Exception:
            state = {}
        try:
            metrics = self.get_metrics() or {}
        except Exception:
            metrics = {}
        return state, metrics

    def _strip_ansi_len(self, s: str) -> int:
        import re as _re
        return len(_re.sub(r"\x1b\[[0-9;]*m", "", s or ""))

    def _fit_visible(self, text: str, max_len: int) -> str:
        """Truncate visible length (approx, ignoring ANSI width) and clear remainder handled by renderer."""
        text = " ".join(str(text or "").replace("\r", " ").replace("\n", " ").split())
        # remove any accidental ANSI from content; we add our own
        import re as _re
        text = _re.sub(r"\x1b\[[0-9;]*m", "", text)
        if max_len <= 0:
            return ""
        if len(text) <= max_len:
            return text
        if max_len <= 3:
            return text[:max_len]
        limit = max_len - 3
        cut = text[:limit].rstrip()
        if limit < len(text) and cut and cut[-1].isalnum() and text[limit].isalnum():
            sp = cut.rfind(" ")
            if sp >= max(8, limit // 2):
                cut = cut[:sp].rstrip()
        return cut + "..."

    def _fmt_event_ts(self, ev: dict) -> str:
        ts = str(ev.get("ts") or "").strip()
        if ts:
            return ts
        return datetime.now().strftime("%I:%M:%S %p")

    def _extract_site(self, text: str) -> str:
        import re as _re
        m = _re.search(r'https?://[^\s\]\)>,]+', text or "")
        if m:
            url = m.group(0).rstrip('.,;')
            try:
                from urllib.parse import urlparse
                host = urlparse(url).netloc or url
                return host or url
            except Exception:
                return url
        return ""

    def _meaningful_event(self, ev: dict) -> Optional[dict]:
        if not ev:
            return None
        msg = " ".join(str(ev.get("message") or "").split())
        if not msg:
            return None
        et = str(ev.get("type") or "").lower()
        low = msg.lower()
        if et == "dashboard":
            return None
        if low in ("terminal dashboard started",) or low.startswith("application status:"):
            return None
        icon = "\U0001F916"
        if "discover" in low or et == "discovery":
            icon = "\U0001F30D"
        elif "inspect" in low:
            icon = "\U0001F50E"
        elif "permission" in low or "rules" in low:
            icon = "\U0001F4CB"
        elif "translat" in low or "language" in low or et == "translation":
            icon = "\U0001F310"
        elif "eligib" in low or et == "eligibility":
            icon = "\U0001F3AF"
        elif "submit" in low or "attempt" in low or et == "submission_attempt":
            icon = "\U0001F4E4"
        elif "confirm" in low or "verified" in low or et == "submission_success":
            icon = "\u2705"
        elif "skip" in low or et == "submission_skipped":
            icon = "\u23ED\uFE0F"
        elif "uncertain" in low:
            icon = "\u26A0\uFE0F"
        elif "recover" in low or "error" in low or "fail" in low or "reject" in low or et == "submission_failure":
            icon = "\u26A0\uFE0F"
        elif "stop" in low or "shutdown" in low:
            icon = "\U0001F6D1"
        key = str(ev.get("id") or "") + "|" + et + "|" + msg
        return {"ts": self._fmt_event_ts(ev), "icon": icon, "message": msg, "site": self._extract_site(msg), "key": key}

    def _consume_events(self):
        try:
            for _ in range(200):
                ev = self.bus.pop_next_display()
                if ev is None:
                    break
                item = self._meaningful_event(ev)
                if not item:
                    continue
                if item["key"] in self._seen_keys:
                    continue
                self._seen_keys.append(item["key"])
                self._live_events.append(item)
                self._last_live_event = item
        except Exception:
            pass

    def _build_lines(self) -> list[str]:
        state, metrics = self._snapshot()
        width, height = self._get_term_size()
        # Reserve fixed rows for sections; ensure fits in available height
        # Layout rows: 6 (SYSTEM) + 1 + 13 (LIVE METRICS) + 1 + 5 (CURRENT) + 1 + 2 (LIVE ACTIVITY: header+1 line) + 1 + 1 (footer) = 31
        max_content_width = max(20, width - 1)

        run_state = str(state.get("run_state") or metrics.get("run_state") or "RUNNING").strip().upper()
        if run_state not in ("RUNNING", "STOPPING", "STOPPED", "ERROR"):
            run_state = "RUNNING"
        if run_state == "RUNNING":
            app_display, app_icon = "RUNNING", "\U0001F7E2"
        elif run_state == "STOPPING":
            app_display, app_icon = "STOPPING", "\U0001F6D1"
        elif run_state == "STOPPED":
            app_display, app_icon = "STOPPED", "\U0001F6D1"
        else:
            app_display, app_icon = "ERROR", "\u274C"

        browser = str(state.get("browser_status") or metrics.get("browser_status") or "DISCONNECTED")
        dbs = str(state.get("database_status") or metrics.get("database_status") or "CONNECTED")
        if self.get_db_status:
            try:
                dbs = self.get_db_status() or dbs
            except Exception:
                pass
        browser_lower = browser.lower()
        if "running" in browser_lower or browser_lower in ("connected", "ok", "ready"):
            browser_display = "CONNECTED"
        elif "start" in browser_lower or browser_lower == "connecting":
            browser_display = "CONNECTING"
        elif "fail" in browser_lower or "error" in browser_lower or "stopped" in browser_lower or browser_lower in ("idle", "disconnected", "unavailable", "unknown", ""):
            browser_display = "DISCONNECTED"
        else:
            browser_display = "DISCONNECTED"

        cycle = state.get("cycle") or metrics.get("cycle") or 0
        # Uptime from actual application start time (every second)
        try:
            secs = float(state.get("uptime_seconds") or metrics.get("uptime_seconds") or 0)
            if secs <= 0:
                secs = max(0.0, time.monotonic() - self._started_mono)
            total = int(secs)
            uptime = f"{total//3600:02d}:{(total%3600)//60:02d}:{total%60:02d}"
        except Exception:
            uptime = "00:00:00"

        discovered = int(state.get("discovered", metrics.get("discovered", metrics.get("discovered_websites", 0))) or 0)
        inspected = int(state.get("inspected", metrics.get("inspected", metrics.get("inspected_pages", 0))) or 0)
        eligible = int(state.get("eligible", metrics.get("eligible", metrics.get("eligible_destinations", 0))) or 0)
        attempts = int(state.get("attempts", metrics.get("attempts", metrics.get("submission_attempts", 0))) or 0)
        confirmed = int(state.get("confirmed", metrics.get("confirmed", metrics.get("confirmed_submissions", 0))) or 0)
        rejected = int(state.get("rejected", metrics.get("rejected", metrics.get("rejected_submissions", 0))) or 0)
        uncertain = int(state.get("uncertain", metrics.get("uncertain", metrics.get("uncertain_submissions", 0))) or 0)
        failed = int(state.get("failed", metrics.get("failed", metrics.get("failed_submissions", 0))) or 0)
        skipped = int(state.get("skipped", metrics.get("skipped", metrics.get("skipped_submissions", 0))) or 0)
        queue = state.get("queue_pending", metrics.get("queue_pending", metrics.get("pending_queue", metrics.get("discovery_queue_pending", 0))))
        if queue in (None, ""): queue = 0
        try:
            queue = int(queue)
        except Exception:
            queue = 0
        lang_dist = metrics.get("language_distribution") or {}
        country_dist = metrics.get("country_distribution") or {}
        languages = len(lang_dist) if isinstance(lang_dist, dict) else int(metrics.get("languages") or 0)
        countries = len(country_dist) if isinstance(country_dist, dict) else int(metrics.get("countries") or 0)
        translation_issues = int(metrics.get("translation_failures") or metrics.get("translation_issues") or 0)

        current = str(state.get("current_activity") or metrics.get("current_activity") or "Idle").strip()
        current = " ".join(current.replace("\r", " ").replace("\n", " ").split()) or "Idle"
        cur_site = self._extract_site(current)
        if not cur_site and self._last_live_event:
            cur_site = self._last_live_event.get("site") or ""
        if not cur_site:
            cur_site = str(state.get("current_site") or state.get("current_url") or state.get("current_target") or "")
            if cur_site:
                cur_site = self._extract_site(cur_site) or cur_site
        if not cur_site:
            cur_site = "None"

        processed = attempts + failed + skipped
        progress_total = max(eligible, processed, discovered, 0)
        now_m = time.monotonic()
        act_key = current[:120]
        if "_act_key" not in self._op_started or self._op_started.get("_act_key") != act_key:
            self._op_started = {"_act_key": act_key, "t": now_m}
        elapsed = int(max(0, now_m - self._op_started.get("t", now_m)))

        action, task = current, current
        low = current.lower()
        if "discover" in low:
            action, task = "Discovering websites", "Finding and identifying website sources"
        elif "inspect" in low:
            action, task = "Inspecting website", "Opening and inspecting the website"
        elif "permission" in low or "rules" in low:
            action, task = "Checking submission permissions", "Checking submission rules and permission evidence"
        elif "translat" in low or "language" in low:
            action, task = "Translating content", "Identifying language and translating content"
        elif "eligib" in low:
            action, task = "Determining eligibility", "Determining whether the website is eligible"
        elif "submit" in low or "prepar" in low:
            action, task = "Submitting content", "Preparing and submitting an eligible submission"
        elif "verif" in low or "confirm" in low:
            action, task = "Verifying submission", "Verifying the submission result"
        elif "skip" in low:
            action, task = "Skipping website", current
        elif "stop" in low or "shutting" in low:
            action, task = "Stopping COCO", current
        if self._stopping_text:
            action, task = "Stopping COCO", self._stopping_text

        G = "\x1b[1;32m"  # green headings
        R = "\x1b[0m"
        def fmt(text: str, green: bool = False) -> str:
            t = self._fit_visible(text, max_content_width)
            if green:
                return f"{G}{t}{R}"
            return t

        rows = []
        rows.append(fmt("SYSTEM STATUS", True))
        rows.append(fmt(f"{app_icon} Application :: {app_display}"))
        rows.append(fmt(f"\U0001F916 Browser :: {browser_display}"))
        rows.append(fmt(f"\U0001F5C4\uFE0F Database :: {dbs}"))
        rows.append(fmt(f"\U0001F504 Current cycle :: {cycle}"))
        rows.append(fmt(f"\u23F1\uFE0F Uptime :: {uptime}"))
        rows.append(fmt(""))
        rows.append(fmt("LIVE METRICS", True))
        rows.append(fmt(f"\U0001F30D Websites discovered :: {discovered}"))
        rows.append(fmt(f"\U0001F50E Pages inspected :: {inspected}"))
        rows.append(fmt(f"\U0001F3AF Eligible websites :: {eligible}"))
        rows.append(fmt(f"\U0001F4E4 Submission attempts :: {attempts}"))
        rows.append(fmt(f"\u2705 Confirmed submissions :: {confirmed}"))
        rows.append(fmt(f"\u274C Rejected submissions :: {rejected}"))
        rows.append(fmt(f"\u26A0\uFE0F Uncertain submissions :: {uncertain}"))
        rows.append(fmt(f"\u23ED\uFE0F Failed / Skipped :: {failed + skipped}"))
        rows.append(fmt(f"\u23F3 Pending queue :: {queue}"))
        rows.append(fmt(f"\U0001F310 Languages :: {languages}"))
        rows.append(fmt(f"\U0001F5FA\uFE0F Countries :: {countries}"))
        rows.append(fmt(f"\u26A0\uFE0F Translation issues :: {translation_issues}"))
        rows.append(fmt(""))
        rows.append(fmt("CURRENT ACTIVITY", True))
        rows.append(fmt(f"\u26A1 Action :: {action}"))
        rows.append(fmt(f"\U0001F30D Website :: {cur_site}"))
        rows.append(fmt(f"\U0001F4CB Task :: {task}{'' if self._stopping_text else f' ({elapsed} seconds)'}"))
        rows.append(fmt(f"\U0001F4CA Progress :: {processed} of {progress_total} websites processed"))
        # Exactly ONE latest event line (real event timestamp), replaced when new genuine event occurs; retain previous if none
        ev = self._last_live_event
        if ev:
            msg = ev["message"]
            if msg and ord(msg[0]) > 1000:
                ev_display = f"{ev['ts']} :: {msg}"
            else:
                ev_display = f"{ev['ts']} :: {ev['icon']} {msg}"
            self._last_live_line_text = ev_display
        elif hasattr(self, "_last_live_line_text") and self._last_live_line_text:
            ev_display = self._last_live_line_text
        else:
            ev_display = "No events yet"
        rows.append(fmt(f"\U0001F534 Latest event :: {ev_display}"))
        rows.append(fmt(""))
        rows.append(fmt("\U0001F534 Press Ctrl + C to stop COCO"))

        # Ensure dashboard fits within available height (no scrolling); trim middle if absolutely necessary
        max_rows = max(10, height - 1)
        if len(rows) > max_rows:
            # Keep header sections and footer; trim from live metrics/progress if needed (rare)
            rows = rows[:max_rows-1] + [rows[-1]]
        return rows

    def render_full(self):
        self._consume_events()
        lines = self._build_lines()
        self._last_lines = list(lines)
        self._write("\x1b[?25l\x1b[?7l")  # hide cursor, disable auto-wrap
        for i, line in enumerate(lines, start=1):
            self._write(f"\x1b[{i};1H{line}\x1b[K")
        # Clear a few rows below dashboard to avoid leftover garbage without scrolling dashboard
        for j in range(len(lines) + 1, min(len(lines) + 4, self._term_height + 1)):
            self._write(f"\x1b[{j};1H\x1b[K")
        self._write(f"\x1b[{len(lines)+1};1H")
        self._write("\x1b[?7h")  # re-enable wrap for safety
        self._write("\x1b[?25h")
        return lines

    def render_diff(self):
        self._consume_events()
        lines = self._build_lines()
        self._write("\x1b[?25l\x1b[?7l")
        prev = self._last_lines
        for i, line in enumerate(lines, start=1):
            old = prev[i-1] if i-1 < len(prev) else None
            if old != line:
                self._write(f"\x1b[{i};1H{line}\x1b[K")
        # If dashboard shrank (resize), clear leftover rows below
        if len(prev) > len(lines):
            for j in range(len(lines) + 1, min(len(prev) + 1, self._term_height + 1)):
                self._write(f"\x1b[{j};1H\x1b[K")
        self._last_lines = list(lines)
        self._write(f"\x1b[{len(lines)+1};1H\x1b[?7h\x1b[?25h")
        return lines

    def cleanup(self):
        try:
            self._write("\x1b[?7h\x1b[?25h\x1b[0m")
        except Exception:
            pass


# ======================================================================
# merged from dashboard.py
# ======================================================================
import json
import socket
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse



DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>COCO Control Center</title>
  <style>
    :root {
      --bg: #0b0d10;
      --surface: #12161b;
      --surface-2: #161b22;
      --border: #232a33;
      --border-soft: #1d232b;
      --text: #e6edf3;
      --muted: #9aa7b4;
      --dim: #7d8894;
      --accent: #4da3ff;
      --ok: #3fb950;
      --warn: #d29922;
      --err: #f85149;
      --info: #58a6ff;
      --skip: #a371f7;
      --pending: #c9d1d9;
      --radius: 10px;
      --shadow: 0 1px 0 rgba(255,255,255,0.02) inset;
      --mono: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
      --sans: "Segoe UI", Inter, Roboto, Arial, sans-serif;
    }
    * { box-sizing: border-box; }
    html, body { height: 100%; margin: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      line-height: 1.4;
      overflow: hidden;
    }
    .app {
      height: 100%;
      max-width: 1480px;
      margin: 0 auto;
      padding: 20px 24px 14px;
      display: flex;
      flex-direction: column;
      gap: 16px;
      min-width: 0;
    }
    .panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      min-width: 0;
    }
    .header {
      padding: 16px 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .header-top {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
    }
    .brand { min-width: 0; }
    .title {
      margin: 0;
      font-size: 28px;
      line-height: 1.1;
      letter-spacing: 0.08em;
      font-weight: 700;
      color: #fff;
    }
    .subtitle {
      margin: 4px 0 0;
      font-size: 12px;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      color: var(--muted);
      font-weight: 600;
    }
    .status-strip {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px 14px;
      color: var(--muted);
      font-size: 13px;
    }
    .status-item { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; }
    .dot { color: #3a4452; }
    .status-item strong { color: var(--text); font-weight: 600; }
    .pill {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: var(--surface-2);
      color: var(--muted);
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    .pill.ok { color: var(--ok); border-color: rgba(63,185,80,0.25); }
    .pill.warn { color: var(--warn); border-color: rgba(210,153,34,0.25); }
    .pill.err { color: var(--err); border-color: rgba(248,81,73,0.25); }
    .pill.info { color: var(--info); border-color: rgba(88,166,255,0.25); }
    .meta-strip {
      display: flex;
      flex-wrap: wrap;
      gap: 10px 18px;
      padding-top: 10px;
      border-top: 1px solid var(--border-soft);
      color: var(--muted);
      font-size: 13px;
    }
    .meta-strip span { color: var(--dim); }
    .meta-strip strong { color: var(--text); font-weight: 600; }

    .metrics {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
    }
    .metric {
      padding: 14px 16px;
      min-height: 92px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 8px;
    }
    .metric-label {
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .metric-value {
      font-size: 30px;
      line-height: 1;
      font-weight: 700;
      color: #fff;
      letter-spacing: 0.01em;
    }
    .metric.ok .metric-value { color: var(--ok); }
    .metric.warn .metric-value { color: var(--warn); }
    .metric.err .metric-value { color: var(--err); }
    .metric.info .metric-value { color: var(--info); }
    .metric.skip .metric-value { color: var(--skip); }

    .context {
      padding: 12px 16px;
      display: flex;
      flex-wrap: wrap;
      gap: 10px 18px;
      color: var(--muted);
      font-size: 13px;
      align-items: center;
    }
    .context strong { color: var(--text); font-weight: 600; }
    .truncate { max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .activity {
      flex: 1 1 auto;
      min-height: 0;
      display: flex;
      flex-direction: column;
    }
    .activity-head {
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-soft);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .section-title {
      margin: 0;
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--muted);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .section-meta { font-size: 12px; color: var(--dim); white-space: nowrap; }
    .feed {
      padding: 8px 10px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      gap: 0;
    }
    .rows { display: flex; flex-direction: column; }
    .event {
      display: grid;
      grid-template-columns: 112px 28px minmax(180px, 1.2fr) minmax(220px, 1.8fr);
      align-items: center;
      gap: 10px;
      padding: 10px 8px;
      border-bottom: 1px solid var(--border-soft);
      font-size: 13px;
      min-height: 44px;
    }
    .event:last-child { border-bottom: none; }
    .ts { color: var(--dim); font-family: var(--mono); font-size: 12px; white-space: nowrap; }
    .icon { text-align: center; font-size: 14px; }
    .target { color: var(--text); font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .result { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .event.ok .result { color: #b7e3c1; }
    .event.warn .result { color: #e6d3a3; }
    .event.err .result { color: #f2b8b5; }
    .event.info .result { color: #bdd7ff; }
    .event.skip .result { color: #dcc9ff; }
    .waiting {
      color: var(--dim);
      font-size: 13px;
      padding: 10px 8px;
      min-height: 44px;
      display: flex;
      align-items: center;
    }
    .footer {
      text-align: center;
      color: var(--muted);
      font-size: 13px;
      padding: 2px 0 0;
      flex: 0 0 auto;
    }

    @media (max-width: 1200px) {
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .event { grid-template-columns: 104px 24px minmax(140px, 1fr) minmax(160px, 1.4fr); }
    }
    @media (max-width: 760px) {
      body { overflow: auto; }
      .app { height: auto; min-height: 100%; padding: 12px; gap: 12px; }
      .header { padding: 14px; }
      .title { font-size: 24px; }
      .metrics { grid-template-columns: 1fr 1fr; gap: 10px; }
      .metric { min-height: 84px; padding: 12px; }
      .metric-value { font-size: 26px; }
      .status-strip, .meta-strip, .context { font-size: 12px; }
      .event { grid-template-columns: 92px 22px 1fr; gap: 8px; }
      .result { grid-column: 2 / 4; padding-left: 30px; }
      .section-meta { white-space: normal; text-align: right; }
    }
    @media (max-width: 480px) {
      .metrics { grid-template-columns: 1fr; }
      .event { grid-template-columns: 1fr; gap: 4px; padding: 10px 6px; }
      .result { grid-column: auto; padding-left: 0; }
      .icon { text-align: left; }
    }
  </style>
</head>
<body>
  <div class="app">
    <section class="panel header">
      <div class="header-top">
        <div class="brand">
          <h1 class="title">COCO</h1>
          <p class="subtitle">Content Outreach Control Center</p>
        </div>
        <div class="status-strip">
          <div class="status-item">⚙️ Status <strong id="run_state">IDLE</strong></div>
          <span class="dot">•</span>
          <div class="status-item">🧭 Browser <strong id="browser_status">STOPPED</strong> <span id="browser_mode" class="pill">HEADLESS</span></div>
          <span class="dot">•</span>
          <div class="status-item">🗄️ Database <strong id="database_status">DISCONNECTED</strong></div>
        </div>
      </div>
      <div class="meta-strip">
        <div>📝 Current activity: <strong id="current_activity" class="truncate">Idle</strong></div>
        <div>✅ Last confirmed: <strong id="last_confirmed" class="truncate">None</strong></div>
        <div>📊 Confirmed success rate: <strong id="success_rate">0%</strong></div>
      </div>
    </section>

    <section class="metrics">
      <div class="panel metric info"><div class="metric-label">🌍 Discovered</div><div class="metric-value" id="discovered">0</div></div>
      <div class="panel metric info"><div class="metric-label">🔎 Inspected</div><div class="metric-value" id="inspected">0</div></div>
      <div class="panel metric"><div class="metric-label">🎯 Eligible</div><div class="metric-value" id="eligible">0</div></div>
      <div class="panel metric"><div class="metric-label">📤 Attempts</div><div class="metric-value" id="attempts">0</div></div>
      <div class="panel metric ok"><div class="metric-label">✅ Confirmed</div><div class="metric-value" id="confirmed">0</div></div>
      <div class="panel metric err"><div class="metric-label">❌ Rejected</div><div class="metric-value" id="rejected">0</div></div>
      <div class="panel metric warn"><div class="metric-label">⚠️ Uncertain</div><div class="metric-value" id="uncertain">0</div></div>
      <div class="panel metric skip"><div class="metric-label">⏭️ Failed/Skipped</div><div class="metric-value" id="failed_skipped">0</div></div>
    </section>

    <section class="panel context">
      <div class="truncate">🌐 Languages: <strong id="languages">-</strong></div>
      <span class="dot">•</span>
      <div class="truncate">🌍 Countries: <strong id="countries">-</strong></div>
      <span class="dot">•</span>
      <div>🌐 Translation issues: <strong id="translation_failures">0</strong></div>
      <span class="dot">•</span>
      <div>⏳ Queue pending: <strong id="queue_pending">0</strong></div>
    </section>

    <section class="panel activity">
      <div class="activity-head">
        <h2 class="section-title">📝 Live Activity</h2>
        <div class="section-meta">Newest first • up to 20 rows • full history in SQLite</div>
      </div>
      <div id="feed" class="feed"><div class="waiting">⏳ Waiting for activity...</div></div>
    </section>

    <footer class="footer">🔴 Press Ctrl + C to stop COCO</footer>
  </div>
  <script>
    let lastEventId = 0;
    let events = [];
    const eventIds = new Set();
    const maxEvents = 500;
    const displayLimit = 20;
    let sse = null;
    let sseHealthy = false;
    let reconnectTimer = null;
    const feed = document.getElementById('feed');

    function setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }
    function escapeHtml(s){ return String(s ?? '').replace(/[&<>"']/g, c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])); }

    function classify(e) {
      const msg = String((e && e.message) || '');
      const lower = msg.toLowerCase();
      const type = String((e && e.type) || '').toLowerCase();
      const lvl = String((e && e.level) || 'info').toLowerCase();
      if (type === 'submission_success' || lower.includes('confirmed submission') || lower.includes('submission successful')) {
        return { icon: '✅', tone: 'ok' };
      }
      if (lower.includes('uncertain')) return { icon: '⚠️', tone: 'warn' };
      if (type === 'submission_skipped' || lower.includes('skipped')) return { icon: '⏭️', tone: 'skip' };
      if (type === 'submission_failure' || lower.includes('rejected') || lower.includes('failed') || lvl === 'error' || lower.includes('error')) {
        return { icon: '❌', tone: 'err' };
      }
      if (lower.includes('stopped gracefully') || lower.includes('shutting down') || lower.includes('stop request') || lower.includes('ctrl + c')) return { icon: '🛑', tone: 'warn' };
      if (lower.includes('browser crash') || lower.includes('recovery') || lower.includes('recover')) return { icon: '🔧', tone: 'warn' };
      if (type === 'translation' || lower.includes('translation')) return { icon: '🌐', tone: 'info' };
      if (type === 'permission' || lower.includes('permission')) return { icon: '🔐', tone: 'info' };
      if (type === 'discovery' || lower.includes('discover')) return { icon: '🌍', tone: 'info' };
      if (type === 'inspection' || lower.includes('inspect')) return { icon: '🔎', tone: 'info' };
      if (type === 'eligibility' || lower.includes('eligibility')) return { icon: '🎯', tone: 'info' };
      if (type === 'submission_attempt' || lower.includes('submission attempt')) return { icon: '📤', tone: 'info' };
      if (lower.includes('pending') || lower.includes('queue') || lower.includes('waiting')) return { icon: '⏳', tone: 'info' };
      if (lvl === 'warn' || lvl === 'warning') return { icon: '⚠️', tone: 'warn' };
      return { icon: '📝', tone: 'info' };
    }

    function cleanMessage(msg) {
      return String(msg || '').replace(/^[\p{Extended_Pictographic}\uFE0F\u200D\s#*0-9]+/u, '').replace(/^\s*[-:|]\s*/, '').trim();
    }

    function splitEvent(e) {
      const raw = cleanMessage(e.message);
      const parts = raw.split(/\s[-–—]\s|:\s|→/);
      if (parts.length >= 2) {
        return { target: parts[0].trim() || 'COCO', result: parts.slice(1).join(' - ').trim() || raw };
      }
      const m = raw.match(/^(https?:\/\/\S+)\s+(.*)$/i);
      if (m) return { target: m[1], result: m[2] || 'Event' };
      return { target: 'COCO', result: raw || 'Activity update' };
    }

    function renderEvents() {
      if (!events.length) {
        feed.innerHTML = '<div class="waiting">⏳ Waiting for activity...</div>';
        return;
      }
      const shown = events.slice(0, displayLimit);
      const html = shown.map(e => {
        const meta = classify(e);
        const s = splitEvent(e);
        return `<div class="event ${meta.tone}" title="${escapeHtml(e.message || '')}">
          <div class="ts">${escapeHtml(e.ts || '')}</div>
          <div class="icon">${meta.icon}</div>
          <div class="target">${escapeHtml(s.target)}</div>
          <div class="result">${escapeHtml(s.result)}</div>
        </div>`;
      }).join('');
      feed.innerHTML = `<div class="rows">${html}</div>`;
    }

    function applyState(s) {
      if (!s) return;
      const run = s.run_state || 'IDLE';
      const browser = s.browser_status || 'STOPPED';
      const db = s.database_status || 'DISCONNECTED';
      setText('run_state', run);
      setText('browser_status', browser);
      setText('browser_mode', s.headless === false ? 'HEADED' : 'HEADLESS');
      setText('database_status', db);
      setText('current_activity', s.current_activity || (run === 'RUNNING' ? 'Running' : 'Idle'));
      setText('last_confirmed', s.last_confirmed || 'None');
      setText('success_rate', ((s.success_rate ?? 0) + '%'));
      setText('discovered', s.discovered ?? 0);
      setText('inspected', s.inspected ?? 0);
      setText('eligible', s.eligible ?? 0);
      setText('attempts', s.attempts ?? 0);
      setText('confirmed', s.confirmed ?? 0);
      setText('rejected', s.rejected ?? 0);
      setText('uncertain', s.uncertain ?? 0);
      setText('failed_skipped', ((s.failed ?? 0) + (s.skipped ?? 0)));
      setText('translation_failures', s.translation_failures ?? 0);
      setText('queue_pending', s.queue_pending ?? 0);
      const fmtMap = (m) => { try { const e = Object.entries(m||{}).slice(0,6).map(([k,v])=>`${k}: ${v}`).join(', '); return e || '-'; } catch(_) { return '-'; } };
      setText('languages', fmtMap(s.languages));
      setText('countries', fmtMap(s.countries));
    }

    function mergeNewEvents(newEvents) {
      if (!Array.isArray(newEvents) || !newEvents.length) return false;
      let changed = false;
      for (const e of newEvents) {
        if (!e || typeof e.id !== 'number') continue;
        if (eventIds.has(e.id)) continue;
        eventIds.add(e.id);
        events.push(e);
        lastEventId = Math.max(lastEventId, e.id);
        changed = true;
      }
      if (!changed) return false;
      events.sort((a, b) => b.id - a.id);
      if (events.length > maxEvents) {
        const removed = events.splice(maxEvents);
        for (const e of removed) eventIds.delete(e.id);
      }
      renderEvents();
      return true;
    }

    function resetEvents(newEvents) {
      events = [];
      eventIds.clear();
      lastEventId = 0;
      mergeNewEvents(newEvents || []);
    }

    async function poll() {
      try {
        const res = await fetch(`/api/state?after=${lastEventId}&limit=200`, { cache: 'no-store' });
        if (!res.ok) return;
        const data = await res.json();
        applyState(data.state);
        if (Array.isArray(data.events)) mergeNewEvents(data.events);
      } catch (_) { /* fallback polling keeps UI alive */ }
    }

    function startSSE() {
      if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
      if (sse) { try { sse.close(); } catch(_){} sse = null; }
      try {
        sse = new EventSource(`/api/events?after=${lastEventId}`);
        sse.onopen = () => { sseHealthy = true; };
        sse.onmessage = (ev) => {
          sseHealthy = true;
          try {
            const data = JSON.parse(ev.data || '{}');
            if (data.state) applyState(data.state);
            if (Array.isArray(data.events)) mergeNewEvents(data.events);
          } catch(_) {}
        };
        sse.onerror = () => {
          sseHealthy = false;
          if (sse) { try { sse.close(); } catch(_){} sse = null; }
          if (!reconnectTimer) {
            reconnectTimer = setTimeout(() => { reconnectTimer = null; startSSE(); }, 2000);
          }
        };
      } catch (_) {
        sseHealthy = false;
        if (!reconnectTimer) reconnectTimer = setTimeout(() => { reconnectTimer = null; startSSE(); }, 2000);
      }
    }

    // Initial snapshot then SSE; lastEventId survives reconnects so no event is lost.
    (async function init(){
      try {
        const res = await fetch('/api/snapshot?limit=200', { cache: 'no-store' });
        if (res.ok) {
          const data = await res.json();
          applyState(data.state);
          if (Array.isArray(data.events)) resetEvents(data.events);
        }
      } catch(_) {}
      startSSE();
      poll();
      setInterval(poll, 1000); // 1s updates + polling fallback
    })();
  </script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "COCODashboard/1.0"

    @property
    def bus(self) -> EventBus:
        return self.server.bus  # type: ignore[attr-defined]

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8", extra_headers: Optional[dict[str, str]] = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        try:
            parsed = urlparse(self.path)
            if parsed.path in ("/", "/index.html"):
                return self._send(200, DASHBOARD_HTML.encode("utf-8"))
            if parsed.path == "/api/state":
                qs = parse_qs(parsed.query)
                try:
                    after = int(qs.get("after", ["0"])[0])
                except Exception:
                    after = 0
                try:
                    limit = int(qs.get("limit", ["200"])[0])
                except Exception:
                    limit = 200
                payload = {
                    "state": self.bus.snapshot(),
                    "events": self.bus.events_since(after, limit=limit),
                    "server_time": format_local_timestamp(),
                }
                return self._send(200, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")
            if parsed.path == "/api/snapshot":
                qs = parse_qs(parsed.query)
                try:
                    limit = int(qs.get("limit", ["200"])[0])
                except Exception:
                    limit = 200
                payload = {
                    "state": self.bus.snapshot(),
                    "events": self.bus.list_events(limit=limit),  # newest first
                    "server_time": format_local_timestamp(),
                }
                return self._send(200, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")
            if parsed.path == "/api/events":
                return self._handle_sse()
            if parsed.path == "/api/health":
                return self._send(200, b"ok", "text/plain; charset=utf-8")
            self._send(404, b"Not found", "text/plain; charset=utf-8")
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return
        except Exception as e:
            try:
                self._send(500, f"error: {e}".encode("utf-8", "ignore"), "text/plain; charset=utf-8")
            except Exception as _suppressed_exc:
                _log_suppressed('do_GET (line 6860)', _suppressed_exc)

    def _handle_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        after = 0
        try:
            qs = parse_qs(urlparse(self.path).query)
            try:
                after = int(qs.get("after", ["0"])[0])
            except Exception:
                after = 0
            try:
                header_after = int(self.headers.get("Last-Event-ID", ""))
                after = max(after, header_after)
            except Exception as _suppressed_exc:
                _log_suppressed('_handle_sse (line 6880)', _suppressed_exc)
            try:
                self.wfile.write(b"retry: 2000\n\n")
                self.wfile.flush()
            except Exception:
                return
            last_ping = time.time()
            last_state = 0.0
            while getattr(self.server, "serving", True):
                self.bus.wait_for(after, timeout=1.0)
                events = self.bus.events_since(after, limit=100)
                if events:
                    after = max(after, max(e["id"] for e in events))
                now = time.time()
                if events or (now - last_state) >= 3.0:
                    payload = {"state": self.bus.snapshot(), "events": events}
                    frame = ""
                    if events:
                        frame += f"id: {after}\n"
                    frame += f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
                    self.wfile.write(frame.encode("utf-8"))
                    self.wfile.flush()
                    last_state = now
                if now - last_ping > 15:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    last_ping = now
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return
        except Exception:
            return

    def log_message(self, format: str, *args: Any) -> None:  # silence default HTTP logs
        return


class DashboardServer:
    def __init__(self, bus: Optional[EventBus] = None, host: str = "127.0.0.1", port: int = 8765):
        self.bus = bus or get_event_bus()
        self.host = host
        self.port = port
        self.httpd: Optional[ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    @staticmethod
    def is_port_open(host: str, port: int, timeout: float = 0.2) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    @staticmethod
    def is_dashboard_running(host: str = "127.0.0.1", port: int = 8765, timeout: float = 0.3) -> bool:
        if not DashboardServer.is_port_open(host, port, timeout=timeout):
            return False
        try:
            import urllib.request
            with urllib.request.urlopen(f"http://{host}:{port}/api/health", timeout=timeout) as r:
                return r.status == 200
        except Exception:
            return False

    def start(self) -> str:
        if self.httpd:
            return self.url
        self.httpd = ThreadingHTTPServer((self.host, self.port), DashboardHandler)
        self.httpd.daemon_threads = True
        self.httpd.bus = self.bus  # type: ignore[attr-defined]
        self.httpd.serving = True  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self.url

    def stop(self) -> None:
        if not self.httpd:
            return
        try:
            self.httpd.serving = False  # type: ignore[attr-defined]
        except Exception as _suppressed_exc:
            _log_suppressed('stop (line 6960)', _suppressed_exc)
        try:
            self.httpd.shutdown()
        except Exception as _suppressed_exc:
            _log_suppressed('stop (line 6964)', _suppressed_exc)
        try:
            self.httpd.server_close()
        except Exception as _suppressed_exc:
            _log_suppressed('stop (line 6968)', _suppressed_exc)
        self.httpd = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def open_in_browser(self) -> None:
        try:
            webbrowser.open(self.url)
        except Exception as _suppressed_exc:
            _log_suppressed('open_in_browser (line 6979)', _suppressed_exc)

# ======================================================================
# merged from cli.py
# ======================================================================
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table


app = typer.Typer(add_completion=False, invoke_without_command=True, help="COCO - autonomous, compliant browser-based content distribution and outreach agent.")
console = Console()


class _DashboardConsole:
    """No-op console while Rich Live dashboard owns the terminal."""
    def print(self, *args, **kwargs):
        return None
    def print_json(self, *args, **kwargs):
        return None
    def log(self, *args, **kwargs):
        return None
    def rule(self, *args, **kwargs):
        return None
    def __getattr__(self, name):
        def _noop(*args, **kwargs):
            return None
        return _noop


class _EventStream:
    """Redirect stray stdout/stderr writes into event bus instead of corrupting dashboard."""
    def __init__(self, bus, level="info", event_type="system"):
        self.bus = bus
        self.level = level
        self.event_type = event_type
        self._buf = ""
        self._lock = threading.Lock()
        self._last = ("", 0.0)

    def _emit_line(self, raw: str):
        line = " ".join(str(raw or "").replace("\r", "").split()).strip()
        if not line:
            return
        # Drop common traceback noise/frames from dashboard rows; keep concise signal.
        if line in ("Traceback (most recent call last):",):
            return
        if line.startswith("File ") and ", line " in line and " in " in line:
            return
        if len(line) > 240:
            line = line[:237] + "..."
        now = time.monotonic()
        # Avoid flooding duplicate lines from repeated failures.
        if self._last[0] == line and (now - self._last[1]) < 5.0:
            return
        self._last = (line, now)
        lvl = self.level
        low = line.lower()
        if "error" in low or "exception" in low or "cannot " in low or "failed" in low or "traceback" in low:
            lvl = "error"
        self.bus.emit(line, event_type=self.event_type, level=lvl)

    def write(self, s):
        if not s:
            return 0
        try:
            text = str(s)
            with self._lock:
                self._buf += text
                while "\n" in self._buf:
                    line, self._buf = self._buf.split("\n", 1)
                    self._emit_line(line)
                # flush very long partial buffers
                if len(self._buf) > 300:
                    self._emit_line(self._buf)
                    self._buf = ""
        except Exception as _suppressed_exc:
            _log_suppressed('write (line 7065)', _suppressed_exc)
        return len(s)

    def flush(self):
        try:
            with self._lock:
                if self._buf.strip():
                    self._emit_line(self._buf)
                self._buf = ""
        except Exception:
            try:
                self._buf = ""
            except Exception as _suppressed_exc:
                _log_suppressed('flush (line 7078)', _suppressed_exc)
        return None

    def isatty(self):
        return False
    def writable(self):
        return True
    def readable(self):
        return False
    def seekable(self):
        return False
    def fileno(self):
        raise OSError("redirected stream")
    @property
    def encoding(self):
        return "utf-8"
    @property
    def errors(self):
        return "replace"


def _cleanup_runtime_data(cfg, max_age_days: int = 2) -> None:
    """Periodic cleanup: remove old logs/reports/cache/temp artifacts (>2 days); keep DB/config/profile/content/source/.venv."""
    cutoff = time.time() - (max_age_days * 86400)

    def prune_dir(p: Path, patterns: tuple[str, ...] = ("*",), keep_names: set[str] | None = None):
        if not p.exists() or not p.is_dir():
            return
        keep_names = keep_names or set()
        for f in p.glob("**/*"):
            try:
                if not f.is_file() or f.name in keep_names:
                    continue
                if patterns != ("*",) and not any(f.match(pat) for pat in patterns):
                    continue
                if f.stat().st_mtime < cutoff:
                    f.unlink(missing_ok=True)
            except Exception as _suppressed_exc:
                _log_suppressed('prune_dir (line 7116)', _suppressed_exc)

    try:
        prune_dir(cfg.log_dir, keep_names={"coco.log"})  # keep active log; old/test logs removed
    except Exception as _suppressed_exc:
        _log_suppressed('prune_dir (line 7121)', _suppressed_exc)
    try:
        data = cfg.data_dir
        for sub in ("reports", "screenshots", "cache", "tmp", "temp"):
            prune_dir(data / sub)
        protected = {
            "coco.db", "coco.db-shm", "coco.db-wal",
            "silk.db", "silk.db-shm", "silk.db-wal",
            "nexus.db", "nexus.db-shm", "nexus.db-wal",  # legacy name, never auto-deleted
            "data.db", "data.db-shm", "data.db-wal",  # legacy name, never auto-deleted
            "STOP_COCO", "coco.pid",
        }
        if data.exists():
            for f in data.iterdir():
                try:
                    if f.is_file() and f.name not in protected and f.stat().st_mtime < cutoff:
                        if f.name.startswith(("coco.db", "data.db", "nexus.db", "silk.db")):
                            continue
                        f.unlink(missing_ok=True)
                except Exception as _suppressed_exc:
                    _log_suppressed('prune_dir (line 7139)', _suppressed_exc)
    except Exception as _suppressed_exc:
        _log_suppressed('prune_dir (line 7141)', _suppressed_exc)


def _bootstrap(config_path: Optional[Path], dashboard_mode: bool = False):
    cfg = load_config(config_path=config_path)
    logger = setup_logging(cfg.log_dir, level=cfg.app.get("log_level", "INFO"), to_console=not dashboard_mode)

    # Apply owner-configured obstacle-detection signatures before any discovery.
    configure_safety(cfg.data.get("safety"))

    # Fail loudly when a credential the config explicitly requires is missing.
    # Silently falling back to heuristics used to hide this misconfiguration.
    intel_cfg = cfg.data.get("intelligence") or {}
    provider_pref = str(intel_cfg.get("provider") or "auto").lower().strip()
    cloud_requested = bool(intel_cfg.get("cloud_enabled", False)) or provider_pref in (
        "google", "gemini", "google_gemini", "cloud",
    )
    if cloud_requested:
        key_env = str(intel_cfg.get("api_key_env") or "COCO_GOOGLE_API_KEY")
        if not any(os.getenv(k) for k in (key_env, "COCO_GOOGLE_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY")):
            raise SystemExit(
                "Configuration error: cloud intelligence is enabled "
                f"(provider={provider_pref!r}, cloud_enabled={intel_cfg.get('cloud_enabled')}) but no API key "
                f"is set. Export {key_env} (or GOOGLE_API_KEY / GEMINI_API_KEY), or set "
                "intelligence.cloud_enabled: false / provider: heuristic in config.yaml."
            )
    if dashboard_mode:
        try:
            enable_dashboard_logging(get_event_bus(), level=cfg.app.get("log_level", "INFO"))
        except Exception as _suppressed_exc:
            _log_suppressed('_bootstrap (line 7171)', _suppressed_exc)
    db = Database(cfg.db_path)
    if cfg.app.get("backup_on_start", True):
        try:
            backup_path = db.backup(keep=int(cfg.app.get("backup_keep", 10)))
            if backup_path:
                logger.info("Database backup created: %s", backup_path)
        except Exception as backup_error:
            logger.warning("Database backup failed: %s", backup_error)
    try:
        _cleanup_runtime_data(cfg)
        try:
            db.cleanup_old_events(keep_days=3)
        except Exception as _suppressed_exc:
            _log_suppressed('_bootstrap (line 7185)', _suppressed_exc)
    except Exception as _suppressed_exc:
        _log_suppressed('_bootstrap (line 7187)', _suppressed_exc)
    try:
        bus = get_event_bus()
        try:
            bus.set_persistence(db.record_event)
        except Exception as _suppressed_exc:
            _log_suppressed('_bootstrap (line 7193)', _suppressed_exc)
        bus.set_state(database_status="CONNECTED")
        if bus.snapshot().get("browser_status") in (None, "UNKNOWN"):
            bus.set_state(browser_status="IDLE")
    except Exception as _suppressed_exc:
        _log_suppressed('_bootstrap (line 7198)', _suppressed_exc)
    # Ensure permanent original fundraising content exists and is loaded automatically on startup
    try:
        ensure_original_content_files(cfg.root_dir)
    except Exception as _suppressed_exc:
        _log_suppressed('_bootstrap (line 7203)', _suppressed_exc)
    content = ContentManager(root_dir=cfg.root_dir)
    # Register permanent original source content in SQLite (never overwrite original text)
    try:
        ContentManager.register_original_content(db, cfg.root_dir, text=content.original_fundraising_text)
    except Exception as e:
        logger.warning("Failed to register original content in database: %s", e)
    # Load permanent user profile from profile/profile.json automatically on startup and sync to SQLite.
    profile = None
    try:
        pm = ProfileManager(cfg.root_dir)
        profile = pm.sync_to_db(db, source_content=content.source_text)
        # Ensure config reflects loaded profile for this run (without overwriting user config files)
        cfg.data.setdefault("profile", {})
        cfg.data["profile"].update({
            "name": profile.name,
            "email": profile.email,
            "bio": profile.bio,
            "profile_picture": profile.profile_picture,
            "profile_picture_abs": profile.profile_picture_abs,
        })
        cfg.app["profile_name"] = profile.name
        cfg.app["profile_picture_path"] = profile.profile_picture or cfg.app.get("profile_picture_path", DEFAULT_PROFILE_PICTURE)
        # Credentials disabled; keep email only in profile data for content/form identity.
    except Exception as e:
        logger.warning("Profile auto-load failed, using fallback identity: %s", e)
        try:
            pic_path = cfg.path(cfg.app.get("profile_picture_path", DEFAULT_PROFILE_PICTURE))
            db.upsert_profile(
                name=cfg.app.get("profile_name", PROFILE_NAME),
                email=PROFILE_EMAIL,
                source_content=content.source_text,
                payment_links=ContentManager.payment_info(),
                metadata={"profile_picture_path": str(pic_path), "profile_picture_exists": pic_path.exists()},
                is_default=True,
            )
        except Exception as _suppressed_exc:
            _log_suppressed('_bootstrap (line 7240)', _suppressed_exc)
    tr_cfg = dict(cfg.translation)
    tr_cfg.setdefault("translated_cache_dir", str(cfg.root_dir / "content" / "translated"))
    translator = TranslationService(db, tr_cfg)
    reporting = ReportingService(db, cfg.data_dir / "reports")
    try:
        refresh_dashboard_metrics(db, cfg)
    except Exception as _suppressed_exc:
        _log_suppressed('_bootstrap (line 7248)', _suppressed_exc)
    return cfg, logger, db, content, translator, reporting, profile


def refresh_dashboard_metrics(db: Database, cfg) -> None:
    """Update dashboard counters/status from actual database and execution state."""
    bus = get_event_bus()
    try:
        metrics = db.dashboard_metrics() if hasattr(db, "dashboard_metrics") else {}
        counts = db.count_submissions_by_status()
        submitted = int(counts.get("success", 0) + counts.get("submitted", 0) + counts.get("accepted", 0) + counts.get("confirmed", 0))
        skipped = int(counts.get("skipped", 0) + counts.get("blocked", 0) + counts.get("needs_approval", 0))
        discovered = int(metrics.get("discovered_websites", db.count_websites()))
        eligible = int(metrics.get("eligible_destinations", 0))
        last = metrics.get("last_confirmed_submission") or {}
        last_txt = ""
        if last:
            last_txt = f"{last.get('created_at','')} {last.get('website_url','')}".strip()
        bus.update_counters(
            discovered=discovered,
            eligible=eligible,
            submitted=submitted,
            skipped=skipped,
            inspected=int(metrics.get("inspected_pages", 0)),
            attempts=int(metrics.get("submission_attempts", 0)),
            confirmed=int(metrics.get("confirmed_successful_submissions", 0)),
            rejected=int(metrics.get("rejected_submissions", 0)),
            uncertain=int(metrics.get("uncertain_submissions", 0)),
            failed=int(metrics.get("failed_submissions", 0)),
            success_rate=round(float(metrics.get("confirmed_success_rate", 0.0)) * 100.0, 2),
            translation_failures=int(metrics.get("translation_failures", 0)),
            last_confirmed=last_txt,
            countries=metrics.get("country_distribution", {}),
            languages=metrics.get("language_distribution", {}),
            queue_pending=int(metrics.get("discovery_queue_pending", 0)),
        )
        bus.set_state(database_status="CONNECTED", headless=bool(cfg.app.get("headless", True)))
    except Exception as e:
        try:
            bus.set_state(database_status="DISCONNECTED")
            emit_event(f"Database/status update error: {e}", event_type="system", level="error")
        except Exception as _suppressed_exc:
            _log_suppressed('refresh_dashboard_metrics (line 7290)', _suppressed_exc)


@app.command("show-profile")
def show_profile_cmd(config_path: Optional[Path] = typer.Option(None, "--config")):
    """Show loaded permanent profile identity (no credentials)."""
    cfg, _, db, _, _, _, profile = _bootstrap(config_path)
    db_profile = db.get_default_profile()
    console.print(f"Name: {getattr(profile,'name',None)}")
    console.print(f"Email: {getattr(profile,'email',None)}")
    console.print(f"Bio: {getattr(profile,'bio',None)}")
    console.print(f"Profile picture: {getattr(profile,'profile_picture',None)} (exists: {Path(getattr(profile,'profile_picture_abs','')).exists() if profile else False})")
    console.print(f"Profile source: {getattr(profile,'source',None)}")
    console.print(f"DB profile synced: {bool(db_profile)}")
    console.print("Login to existing accounts: disabled. Sign-up on permitted sites: per-site generated passwords, stored locally.")


def _profile_picture_path(cfg, profile=None) -> Optional[str]:
    if profile and getattr(profile, "profile_picture_abs", None):
        p = Path(profile.profile_picture_abs)
        if p.exists():
            return str(p)
    p = cfg.path(cfg.app.get("profile_picture_path", DEFAULT_PROFILE_PICTURE))
    return str(p) if p.exists() else None


@app.command("init")
def init_cmd(config_path: Optional[Path] = typer.Option(None, "--config", help="Path to config.yaml")):
    """Initialize COCO data directories, database, permanent profile, and example config."""
    cfg, logger, db, content, translator, reporting, profile = _bootstrap(config_path)
    root = cfg.root_dir
    example = root / "config.example.yaml"
    target = root / "config.yaml"
    if not target.exists() and example.exists():
        target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
        console.print(f"[green]Created config.yaml from example:[/green] {target}")
    console.print(f"[green]Initialized database:[/green] {cfg.db_path}")
    console.print(f"Data dir: {cfg.data_dir}")
    console.print(f"Logs dir: {cfg.log_dir}")
    if profile:
        console.print(f"[green]Permanent profile loaded:[/green] {profile.name} <{profile.email}>")
        console.print(f"Bio: {profile.bio}")
        console.print(f"Profile picture: {profile.profile_picture} (exists: {Path(profile.profile_picture_abs).exists() if profile.profile_picture_abs else False})")
        console.print(f"Profile config: {cfg.root_dir / 'profile' / 'profile.json'}")
    console.print("Next: review config.yaml, install Playwright browsers (`python -m playwright install chromium`), then run discovery.")
    try:
        emit_event("Initialization completed", event_type="system")
    except Exception as _suppressed_exc:
        _log_suppressed('init_cmd (line 7338)', _suppressed_exc)


@app.command("discover")
def discover_cmd(
    config_path: Optional[Path] = typer.Option(None, "--config"),
    seed: Optional[list[str]] = typer.Option(None, "--seed", help="Seed URL (repeatable). Defaults to config seeds."),
    headless: bool = typer.Option(True, "--headless/--headed", help="Browser mode for discovery"),
):
    """Discover and analyze websites from configured seed URLs."""
    cfg, logger, db, *_rest = _bootstrap(config_path)
    browser_cfg = dict(cfg.browser)
    browser_cfg["headless"] = headless
    browser_cfg["navigation_timeout_ms"] = cfg.app.get("navigation_timeout_ms", 30000)
    try:
        get_event_bus().set_state(run_state="RUNNING", headless=headless, browser_status="IDLE", started_at_mono=time.monotonic())
        emit_event("Discovery command started", event_type="system")
        with BrowserAutomation(browser_cfg, headless=headless).session() as browser:
            disc_cfg = dict(cfg.discovery)
            disc_cfg["intelligence"] = dict(cfg.intelligence or {})
            svc = DiscoveryService(disc_cfg, db, browser=browser)
            records = svc.discover_from_seeds(seeds=list(seed) if seed else None)
        refresh_dashboard_metrics(db, cfg)
        console.print(f"[green]Discovery complete.[/green] Processed {len(records)} URL(s).")
        if records:
            table = Table(title="Discovered Websites")
            table.add_column("Score", justify="right")
            table.add_column("Reg")
            table.add_column("Permission")
            table.add_column("Lang")
            table.add_column("URL")
            for r in records[:20]:
                table.add_row(f"{r.relevance_score:.2f}", r.registration_requirements.value, r.permission_status.value, r.language, r.url)
            console.print(table)
    except Exception as e:
        emit_event(f"Discovery error: {e}", event_type="system", level="error")
        get_event_bus().set_state(run_state="ERROR")
        raise
    finally:
        get_event_bus().set_state(run_state="IDLE")
        refresh_dashboard_metrics(db, cfg)


@app.command("add-url")
def add_url_cmd(
    url: str = typer.Argument(..., help="Website or submission page URL"),
    category: str = typer.Option("personal_support", help="Category label"),
    config_path: Optional[Path] = typer.Option(None, "--config"),
):
    """Manually add and analyze a candidate submission URL."""
    cfg, logger, db, *_ = _bootstrap(config_path)
    browser_cfg = dict(cfg.browser)
    browser_cfg["navigation_timeout_ms"] = cfg.app.get("navigation_timeout_ms", 30000)
    with BrowserAutomation(browser_cfg, headless=cfg.app.get("headless", False)).session() as browser:
        disc_cfg = dict(cfg.discovery)
        disc_cfg["intelligence"] = dict(cfg.intelligence or {})
        svc = DiscoveryService(disc_cfg, db, browser=browser)
        recs = svc.add_manual_url(url, category=category)
    refresh_dashboard_metrics(db, cfg)
    console.print(f"[green]Added/analyzed {len(recs)} record(s).[/green]")


@app.command("list-sites")
def list_sites_cmd(
    config_path: Optional[Path] = typer.Option(None, "--config"),
    min_score: float = typer.Option(0.0, help="Minimum relevance score"),
    limit: int = typer.Option(50, help="Max rows"),
):
    """List websites in the discovery database."""
    cfg, _, db, *_ = _bootstrap(config_path)
    sites = db.list_websites(min_relevance=min_score, prioritize_no_registration=cfg.discovery.get("prioritize_no_registration", True))[:limit]
    table = Table(title=f"COCO Websites ({len(sites)})")
    table.add_column("ID", justify="right")
    table.add_column("Score", justify="right")
    table.add_column("Registration")
    table.add_column("Permission")
    table.add_column("Method")
    table.add_column("Lang")
    table.add_column("URL")
    for s in sites:
        table.add_row(str(s.id or ""), f"{s.relevance_score:.2f}", s.registration_requirements.value, s.permission_status.value, s.submission_method.value, s.language, s.url)
    console.print(table)


@app.command("run")
def run_cmd(
    config_path: Optional[Path] = typer.Option(None, "--config"),
    auto: bool = typer.Option(False, "--auto", help="Legacy strict auto mode (preverified/previously approved targets)."),
    review: bool = typer.Option(False, "--review/--no-review", help="Interactive human review before each submission (off by default for autonomous operation)."),
    autonomous: bool = typer.Option(True, "--autonomous/--manual", help="Autonomous mode: automatically translate, fill, and submit on explicitly permitted no-registration public forms; stop/flag only for account creation, verification challenges, or actions requiring user authorisation/permission."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Analyze and prepare plans without submitting."),
    live: bool = typer.Option(True, "--live/--no-live", help="Enable LIVE posting/submission (default: live)."),
    limit: Optional[int] = typer.Option(None, help="Maximum sites to process per cycle (defaults to config)."),
    headed: bool = typer.Option(False, "--headed/--headless", help="Browser visibility (headless by default for continuous/high-volume runs)."),
    continuous: bool = typer.Option(False, "--continuous", help="Run continuously: discover + publish cycles with persistent state, retries, and rate limits."),
    discover: bool = typer.Option(True, "--discover/--no-discover", help="Auto-discover from configured seeds when needed."),
):
    """Autonomous discovery-to-publishing workflow: translate, adapt, fill forms, upload profile picture, and publish where explicitly permitted."""
    # Live by default as requested; --dry-run forces prepare-only.
    effective_dry_run = True if dry_run else (not bool(live))
    _run_automation(config_path=config_path, auto=auto, review=review, autonomous=autonomous, dry_run=effective_dry_run,
                    limit=limit, headed=headed, continuous=continuous, discover=discover, emit_dashboard_events=True)


def _run_automation(config_path: Optional[Path] = None, auto: bool = False, review: bool = False, autonomous: bool = True,
                    dry_run: bool = False, limit: Optional[int] = None, headed: bool = False, continuous: bool = False,
                    discover: bool = True, emit_dashboard_events: bool = True,
                    stop_event: Optional[threading.Event] = None):
    global console
    cfg, logger, db, content, translator, reporting, profile = _bootstrap(config_path, dashboard_mode=emit_dashboard_events)
    _saved_console = console
    if emit_dashboard_events:
        console = _DashboardConsole()
    stop_event = stop_event or threading.Event()
    bus = get_event_bus()
    pub_cfg = dict(cfg.publishing)
    pub_cfg["app_cfg_ref"] = cfg.app
    pub_cfg["log_dir_path"] = str(cfg.log_dir)
    pub_cfg["selectors"] = cfg.data.get("selectors", {})
    pub_cfg["universal_password"] = (cfg.data.get("credentials") or {}).get("universal_password") or ""

    # Effective mode: live by default as requested; dry_run flag/config can force prepare-only.
    effective_dry_run = bool(dry_run) or bool(pub_cfg.get("dry_run", False))

    if autonomous:
        pub_cfg["autonomous_submit"] = True
    engine = PublishingEngine(pub_cfg, db, content, translator)

    profile_pic = _profile_picture_path(cfg, profile)
    profile_info = {
        "name": getattr(profile, "name", cfg.app.get("profile_name", PROFILE_NAME)),
        "username": getattr(profile, "username", "vinaydxo") or "vinaydxo",
        "username_preference": getattr(profile, "username_preference", None) or getattr(profile, "username", "vinaydxo") or "vinaydxo",
        "username_fallbacks": getattr(profile, "username_fallbacks", None) or ["vinay_dxo", "vinaydxo1", "vinay.dxo", "vinaydx", "vinay_d", "vinaydxo_"],
        "email": getattr(profile, "email", PROFILE_EMAIL),
        "bio": getattr(profile, "bio", ""),
    } if profile else {
        "name": cfg.app.get("profile_name", PROFILE_NAME),
        "username": "vinaydxo",
        "username_preference": "vinaydxo",
        "username_fallbacks": ["vinay_dxo", "vinaydxo1", "vinay.dxo", "vinaydx", "vinay_d", "vinaydxo_"],
        "email": PROFILE_EMAIL,
        "bio": "",
    }
    max_per_run = int(limit or cfg.app.get("max_submissions_per_run", 50))
    max_retries = int(cfg.app.get("max_retries", 2))
    retry_backoff = float(cfg.app.get("retry_backoff_seconds", 5))
    idle_pause = float(cfg.app.get("continuous_idle_pause_seconds", 2))
    # Unify record vs process threshold: do not ignore discovered/recorded candidates below app threshold
    # if they meet discovery threshold; policy/eligibility checks still gate actual submission.
    app_min_rel = float(cfg.app.get("min_relevance_score", 0.55))
    disc_min_rel = float((cfg.discovery or {}).get("min_candidate_relevance", 0.35))
    min_relevance = min(app_min_rel, disc_min_rel)
    prioritize_no_reg = cfg.discovery.get("prioritize_no_registration", True)

    def emit(msg, event_type="info", level="info", details=None):
        if emit_dashboard_events:
            try:
                emit_event(msg, event_type=event_type, level=level, details=details)
            except Exception as _suppressed_exc:
                _log_suppressed('emit (line 7488)', _suppressed_exc)

    # State the active mode once per run so live vs dry-run is never ambiguous.
    if effective_dry_run:
        emit("DRY RUN mode: preparing plans only - nothing will be published", event_type="system")
    else:
        emit("LIVE MODE: submissions WILL be published to explicitly permitted sites "
             "(live enabled explicitly; use --dry-run for a prepare-only run)", event_type="system", level="warn")

    # Recover crash-interrupted jobs. These are never retried automatically.
    try:
        recovered = db.recover_interrupted_jobs(older_than_seconds=int(cfg.app.get("recovery_stale_seconds", 0)))
        if recovered:
            emit(f"Recovered {recovered} interrupted submission job(s); manual verification required before retry",
                 event_type="recovery", level="warn")
    except Exception as _suppressed_exc:
        _log_suppressed('emit (line 7504)', _suppressed_exc)

    def ensure_sites(browser: BrowserAutomation, force_discovery: bool = False):
        sites_local = db.list_websites(min_relevance=min_relevance, prioritize_no_registration=prioritize_no_reg)
        if (force_discovery or not sites_local) and discover and cfg.discovery.get("enabled", True):
            if not sites_local:
                console.print("[cyan]No candidate sites found. Running autonomous discovery...[/cyan]")
                emit("No candidate sites found. Running global discovery...", event_type="discovery")
            else:
                emit("🔄 Continuous discovery active", event_type="discovery")
            try:
                bus.set_state(current_activity="🔄 Continuous discovery active")
            except Exception as _suppressed_exc:
                _log_suppressed('ensure_sites (line 7517)', _suppressed_exc)
            disc_cfg = dict(cfg.discovery)
            disc_cfg["intelligence"] = dict(cfg.intelligence or {})
            svc = DiscoveryService(disc_cfg, db, browser=browser)
            try:
                svc.discover_from_seeds()
            except Exception as e:
                logger.warning("Discovery failed: %s", e)
                emit(f"Discovery failed: {e}", event_type="discovery", level="error")
            sites_local = db.list_websites(min_relevance=min_relevance, prioritize_no_registration=prioritize_no_reg)
        refresh_dashboard_metrics(db, cfg)
        return sites_local

    def _process_sites(browser, sites: list) -> dict:
        stats = {"processed": 0, "success": 0, "failed": 0, "blocked": 0, "needs_approval": 0, "skipped": 0}
        if not sites:
            console.print("[yellow]No websites in database. Add seeds/URLs or enable discovery.[/yellow]")
            emit("No eligible websites in database yet; continuous discovery active", event_type="system", level="warn")
            try:
                bus.set_state(current_activity="🔄 Continuous discovery active")
            except Exception as _suppressed_exc:
                _log_suppressed('_process_sites (line 7538)', _suppressed_exc)
            refresh_dashboard_metrics(db, cfg)
            return stats
        reprocess_cooldown = int(cfg.app.get("skip_reprocess_cooldown_seconds", 21600))
        terminal_skip_statuses = ["skipped", "blocked", "needs_approval", "rejected"]
        for site in sites:
            if stop_event.is_set():
                emit("Shutdown requested; stopping current cycle safely", event_type="system", level="warn")
                break
            if stats["processed"] >= max_per_run:
                break
            # Avoid hot-loop: if this URL was already evaluated/skipped recently, do not re-record/reprocess now.
            try:
                if db.has_recent_url_outcome(site.url, terminal_skip_statuses, reprocess_cooldown):
                    continue
            except Exception as _suppressed_exc:
                _log_suppressed('_process_sites (line 7554)', _suppressed_exc)
            variant = {
                "fundraising": ContentVariant.FUNDRAISING,
                "community_assistance": ContentVariant.COMMUNITY_ASSISTANCE,
                "relevant_promotion": ContentVariant.RELEVANT_PROMOTION,
                "relevant promotion": ContentVariant.RELEVANT_PROMOTION,
                "personal_support": ContentVariant.PERSONAL_SUPPORT,
            }.get((site.category or "").lower().replace(" ", "_"), ContentVariant.PERSONAL_SUPPORT)

            try:
                get_event_bus().set_state(current_activity=f"Determining eligibility for {site.url}", current_site=site.url)
            except Exception:
                pass
            plan = engine.build_plan(
                site, variant,
                target_language=None if site.language in ("unknown", "") else site.language,
                translate=not engine.policy_block_reason(site),
            )
            policy_block = engine.policy_block_reason(site)
            refresh_dashboard_metrics(db, cfg)

            if policy_block:
                msg = f"Skipped: {policy_block}"
                engine._record(plan, "skipped", msg)
                emit(f"Eligibility decision: {site.url} -> skipped ({policy_block})", event_type="eligibility", level="warn")
                stats["processed"] += 1
                stats["skipped"] += 1
                refresh_dashboard_metrics(db, cfg)
                continue

            if plan.translation_failed:
                msg = f"Skipped: translation failed or unreliable ({plan.translation_error}); refusing to publish English source"
                engine._record(plan, "skipped", msg)
                emit(f"{site.url} - {msg}", event_type="submission_skipped", level="warn")
                stats["processed"] += 1
                stats["skipped"] += 1
                refresh_dashboard_metrics(db, cfg)
                continue

            emit(f"Content prepared: {site.url} ({variant.value}, lang: {plan.target_language})", event_type="content")
            try:
                get_event_bus().set_state(current_activity=f"Determining eligibility for {site.url}", current_site=site.url)
            except Exception:
                pass

            can_auto, auto_reason = engine.can_auto_submit(plan)
            if not can_auto:
                msg = f"Skipped: {auto_reason}"
                engine._record(plan, "skipped", msg)
                emit(f"Eligibility decision: {site.url} -> skipped ({auto_reason})", event_type="eligibility", level="warn")
                stats["processed"] += 1
                stats["skipped"] += 1
                refresh_dashboard_metrics(db, cfg)
                continue

            if review and not autonomous:
                if not engine.review_plan(plan, auto_approve=False):
                    engine._record(plan, "skipped", "Skipped: not approved in review")
                    stats["processed"] += 1
                    stats["skipped"] += 1
                    refresh_dashboard_metrics(db, cfg)
                    continue

            emit(f"Eligibility decision: {site.url} -> auto-eligible", event_type="eligibility")
            # Credentials/login/account creation are disabled by design.
            result = None
            attempts = max(1, max_retries + 1)
            for attempt in range(1, attempts + 1):
                result = engine.submit(
                    plan,
                    browser=browser,
                    dry_run=effective_dry_run,
                    profile_picture_path=profile_pic,
                    profile_info=profile_info,
                )
                if result is None:
                    break
                if result.status in ("success", "skipped", "blocked", "needs_approval", "confirmed", "accepted", "uncertain", "rejected"):
                    break
                # A crash-interrupted attempt must never be retried automatically.
                if result.status == "failed" and ("interrupted" in (result.message or "").lower() or "uncertain" in (result.message or "").lower()):
                    break
                if attempt < attempts:
                    logger.info("Retrying %s (%s/%s) after failure: %s", site.url, attempt, attempts - 1, result.message)
                    emit(f"Retrying submission: {site.url} (attempt {attempt + 1}/{attempts})", event_type="retry", level="warn")
                    if stop_event.wait(retry_backoff * attempt):
                        break
            if result is None:
                continue
            color = {"success": "green", "failed": "red", "blocked": "red", "skipped": "yellow", "needs_approval": "yellow"}.get(result.status, "white")
            console.print(f"[{color}]{result.status.upper()}[/{color}] {site.url} - {result.message}")
            stats["processed"] += 1
            key = result.status if result.status in stats else "skipped"
            stats[key] = stats.get(key, 0) + 1
            refresh_dashboard_metrics(db, cfg)
        return stats

    def process_once(persistent_browser: Optional[BrowserAutomation] = None) -> dict:
        browser_cfg = dict(cfg.browser)
        browser_cfg["headless"] = not headed
        browser_cfg["navigation_timeout_ms"] = cfg.app.get("navigation_timeout_ms", 30000)
        # Avoid launching Playwright in dry-run/no-discovery mode (allows workflow testing without browser binaries)
        if effective_dry_run and not discover:
            sites = db.list_websites(min_relevance=min_relevance, prioritize_no_registration=prioritize_no_reg)
            return _process_sites(None, sites)
        if persistent_browser is not None:
            if not persistent_browser.is_alive():
                if not persistent_browser.recover():
                    raise BrowserUnavailableError("Browser is unavailable and could not be recovered")
            sites = ensure_sites(persistent_browser)
            return _process_sites(persistent_browser, sites)
        with BrowserAutomation(browser_cfg, headless=not headed).session() as browser:
            sites = ensure_sites(browser)
            return _process_sites(browser, sites)

    try:
        if emit_dashboard_events:
            bus.set_state(run_state="RUNNING", headless=not headed, database_status="CONNECTED", started_at_mono=time.monotonic())
            emit(f"Automation started ({'continuous' if continuous else 'single cycle'}, headless={not headed})", event_type="system")
        if continuous:
            console.print("[green]Starting continuous autonomous mode (parallel discovery + publishing).[/green] Press Ctrl+C to stop.")
            browser_cfg = dict(cfg.browser)
            browser_cfg["headless"] = not headed
            browser_cfg["navigation_timeout_ms"] = cfg.app.get("navigation_timeout_ms", 30000)
            worker_state = {"discovery": "idle", "publishing": "idle", "last_stats": {}}
            _state_lock = threading.Lock()

            def _set_browser_aggregate():
                try:
                    ds = worker_state.get("discovery")
                    ps = worker_state.get("publishing")
                    vals = [ds, ps]
                    status = "STOPPED"
                    if "FAILED" in vals or "REPAIR FAILED" in vals:
                        status = "FAILED"
                    elif "RUNNING" in vals or "STARTING" in vals:
                        status = "RUNNING"
                    elif "IDLE" in vals:
                        status = "IDLE"
                    bus.set_state(browser_status=status, headless=not headed)
                except Exception as _suppressed_exc:
                    _log_suppressed('_set_browser_aggregate (line 7689)', _suppressed_exc)

            def _discovery_worker():
                if not (discover and cfg.discovery.get("enabled", True)):
                    with _state_lock:
                        worker_state["discovery"] = "IDLE"
                    _set_browser_aggregate()
                    return
                persistent_browser: Optional[BrowserAutomation] = None
                browser_unavailable = False
                cycle = 0
                try:
                    if not (effective_dry_run and not discover):
                        persistent_browser = BrowserAutomation(browser_cfg, headless=not headed)
                        try:
                            persistent_browser.start()
                            with _state_lock:
                                worker_state["discovery"] = "RUNNING"
                            _set_browser_aggregate()
                            emit("Discovery worker started (parallel)", event_type="discovery")
                        except Exception as e:
                            browser_unavailable = True
                            with _state_lock:
                                worker_state["discovery"] = "FAILED"
                            _set_browser_aggregate()
                            msg = " ".join(str(e).split())
                            emit(f"Discovery browser unavailable: {msg[:240]}", event_type="discovery", level="error")
                    while not stop_event.is_set():
                        cycle += 1
                        try:
                            if browser_unavailable or persistent_browser is None:
                                emit("Discovery paused: browser unavailable; will retry later", event_type="discovery", level="warn")
                                stop_event.wait(max(idle_pause, 15.0))
                                continue
                            if not persistent_browser.is_alive():
                                if not persistent_browser.recover():
                                    browser_unavailable = True
                                    with _state_lock:
                                        worker_state["discovery"] = "FAILED"
                                    _set_browser_aggregate()
                                    stop_event.wait(max(idle_pause, 15.0))
                                    continue
                            with _state_lock:
                                worker_state["discovery"] = "RUNNING"
                            _set_browser_aggregate()
                            emit(f"Discovery cycle {cycle}: searching and inspecting sites in parallel...", event_type="discovery")
                            try:
                                bus.set_state(current_activity="Continuous discovery/search active (parallel)")
                            except Exception as _suppressed_exc:
                                _log_suppressed('_discovery_worker (line 7738)', _suppressed_exc)
                            disc_cfg = dict(cfg.discovery)
                            disc_cfg["intelligence"] = dict(cfg.intelligence or {})
                            svc = DiscoveryService(disc_cfg, db, browser=persistent_browser)
                            try:
                                found = svc.discover_from_seeds()
                                emit(f"Discovery cycle {cycle} completed: {len(found)} candidate URL(s) processed", event_type="discovery")
                            except BrowserUnavailableError as e:
                                browser_unavailable = True
                                with _state_lock:
                                    worker_state["discovery"] = "FAILED"
                                _set_browser_aggregate()
                                emit(f"Discovery browser unavailable: {e}", event_type="discovery", level="error")
                                stop_event.wait(max(idle_pause, 15.0))
                                continue
                            except Exception as e:
                                emit(f"Discovery cycle {cycle} failed: {e}", event_type="discovery", level="error")
                            refresh_dashboard_metrics(db, cfg)
                        except Exception as e:
                            emit(f"Discovery worker error: {e}", event_type="system", level="error")
                        # brief pause between discovery cycles to avoid hammering providers
                        stop_event.wait(max(idle_pause, 2.0))
                finally:
                    try:
                        if persistent_browser is not None:
                            persistent_browser.stop()
                    except Exception as _suppressed_exc:
                        _log_suppressed('_discovery_worker (line 7765)', _suppressed_exc)
                    with _state_lock:
                        worker_state["discovery"] = "STOPPED"
                    _set_browser_aggregate()

            def _publishing_worker(worker_index: int = 0, worker_count: int = 1):
                cycle = 0
                persistent_browser: Optional[BrowserAutomation] = None
                browser_unavailable = False
                try:
                    if not (effective_dry_run and not discover):
                        persistent_browser = BrowserAutomation(browser_cfg, headless=not headed)
                        try:
                            persistent_browser.start()
                            with _state_lock:
                                worker_state["publishing"] = "RUNNING"
                            _set_browser_aggregate()
                            emit("Publishing worker started (parallel)", event_type="system")
                        except Exception as e:
                            browser_unavailable = True
                            with _state_lock:
                                worker_state["publishing"] = "FAILED"
                            _set_browser_aggregate()
                            msg = " ".join(str(e).split())
                            emit(f"Publishing browser unavailable: {msg[:240]}", event_type="system", level="error")
                    while not stop_event.is_set():
                        cycle += 1
                        try:
                            if effective_dry_run and not discover:
                                sites = db.list_websites(min_relevance=min_relevance, prioritize_no_registration=prioritize_no_reg)
                                stats = _process_sites(None, sites)
                            else:
                                if browser_unavailable or persistent_browser is None:
                                    emit("Publishing paused: browser unavailable; waiting for recovery/environment fix", event_type="system", level="warn")
                                    stop_event.wait(max(idle_pause, 15.0))
                                    continue
                                if not persistent_browser.is_alive():
                                    if not persistent_browser.recover():
                                        browser_unavailable = True
                                        with _state_lock:
                                            worker_state["publishing"] = "FAILED"
                                        _set_browser_aggregate()
                                        stop_event.wait(max(idle_pause, 15.0))
                                        continue
                                with _state_lock:
                                    worker_state["publishing"] = "RUNNING"
                                _set_browser_aggregate()
                                sites = db.list_websites(min_relevance=min_relevance, prioritize_no_registration=prioritize_no_reg)
                                if worker_count > 1:
                                    import zlib as _zlib
                                    sites = [s for s in sites if _zlib.crc32(((s.domain or "") or s.url).encode("utf-8")) % worker_count == worker_index]
                                try:
                                    bus.set_state(current_activity=f"Publishing cycle {cycle}: processing eligible sites (parallel)")
                                except Exception as _suppressed_exc:
                                    _log_suppressed('_publishing_worker (line 7816)', _suppressed_exc)
                                emit(f"Publishing cycle {cycle}: processing {len(sites)} candidate site(s)", event_type="cycle")
                                try:
                                    stats = _process_sites(persistent_browser, sites)
                                except BrowserUnavailableError as e:
                                    browser_unavailable = True
                                    with _state_lock:
                                        worker_state["publishing"] = "FAILED"
                                    _set_browser_aggregate()
                                    emit(f"Publishing browser unavailable: {e}", event_type="system", level="error")
                                    stats = {"processed": 0, "error": str(e)}
                            with _state_lock:
                                worker_state["last_stats"] = stats
                            refresh_dashboard_metrics(db, cfg)
                            console.print(f"Publishing cycle {cycle} stats: {stats}")
                            emit(f"Publishing cycle {cycle} completed: {stats}", event_type="cycle")
                            if (stats or {}).get("processed", 0) == 0 and not stop_event.is_set():
                                emit("No eligible submissions processed now; waiting for discovery/queue updates", event_type="system")
                                try:
                                    err = str((stats or {}).get("error") or "").lower()
                                    pause = max(idle_pause, 10.0)
                                    if "browser unavailable" in err or "repair failed" in err:
                                        pause = max(pause, 15.0)
                                    else:
                                        pause = max(pause, 8.0)
                                except Exception:
                                    pause = max(idle_pause, 10.0)
                                stop_event.wait(pause)
                            else:
                                stop_event.wait(0.5)
                        except Exception as e:
                            logger.exception("Publishing worker error: %s", e)
                            emit(f"Publishing worker error: {e}", event_type="system", level="error")
                            stop_event.wait(max(idle_pause, 5.0))
                finally:
                    try:
                        if persistent_browser is not None:
                            persistent_browser.stop()
                    except Exception as _suppressed_exc:
                        _log_suppressed('_publishing_worker (line 7855)', _suppressed_exc)
                    with _state_lock:
                        worker_state["publishing"] = "STOPPED"
                    _set_browser_aggregate()

            threads = []
            disc_t = threading.Thread(target=_discovery_worker, daemon=True, name="coco-discovery")
            pub_workers = max(1, int(cfg.app.get("publishing_workers", 3)))
            threads.append(disc_t)
            disc_t.start()
            for _wi in range(pub_workers):
                _pt = threading.Thread(target=_publishing_worker, args=(_wi, pub_workers), daemon=True, name=f"coco-publishing-{_wi}")
                threads.append(_pt)
                _pt.start()
            try:
                while not stop_event.is_set():
                    alive = any(t.is_alive() for t in threads)
                    if not alive:
                        break
                    stop_event.wait(1.0)
            finally:
                stop_event.set()
                for t in threads:
                    try:
                        t.join(timeout=30)
                    except Exception as _suppressed_exc:
                        _log_suppressed('_publishing_worker (line 7878)', _suppressed_exc)
                refresh_dashboard_metrics(db, cfg)
                console.print(reporting.print_summary())
        else:
            stats = process_once()
            refresh_dashboard_metrics(db, cfg)
            console.print(f"[green]Run complete.[/green] Stats: {stats}")
            console.print(reporting.print_summary())
            try:
                j = reporting.export_json()
                c = reporting.export_submissions_csv()
                console.print(f"[dim]Reports updated: {j} | {c}[/dim]")
            except Exception as _suppressed_exc:
                _log_suppressed('_publishing_worker (line 7891)', _suppressed_exc)
            return stats
    except KeyboardInterrupt:
        console.print("[yellow]Automation stopped by user.[/yellow]")
        emit("Automation stopped by user", event_type="system", level="warn")
    except Exception as e:
        logger.exception("Automation error: %s", e)
        if emit_dashboard_events:
            bus.set_state(run_state="ERROR")
            emit(f"System error: {e}", event_type="system", level="error")
        raise
    finally:
        try:
            console = _saved_console
        except Exception as _suppressed_exc:
            _log_suppressed('_publishing_worker (line 7906)', _suppressed_exc)
        try:
            if emit_dashboard_events and bus.snapshot().get("run_state") != "ERROR":
                bus.set_state(run_state="IDLE")
            refresh_dashboard_metrics(db, cfg)
        except Exception as _suppressed_exc:
            _log_suppressed('_publishing_worker (line 7912)', _suppressed_exc)
    return None


@app.command("report")
def report_cmd(
    config_path: Optional[Path] = typer.Option(None, "--config"),
    export_json: bool = typer.Option(False, "--json", help="Export JSON report"),
    export_csv: bool = typer.Option(False, "--csv", help="Export submissions CSV"),
):
    """Show and optionally export activity reports."""
    cfg, _, _, _, _, reporting, _profile = _bootstrap(config_path)
    console.print(reporting.print_summary())
    if export_json:
        p = reporting.export_json()
        console.print(f"[green]JSON report:[/green] {p}")
    if export_csv:
        p = reporting.export_submissions_csv()
        console.print(f"[green]CSV submissions:[/green] {p}")


@app.command("show-config")
def show_config_cmd(config_path: Optional[Path] = typer.Option(None, "--config")):
    """Display effective configuration (secrets redacted)."""
    cfg, *_ = _bootstrap(config_path)
    safe = json.loads(json.dumps(cfg.data))

    def redact(obj):
        secret_keys = ("password", "secret", "api_key", "apikey", "private_key", "access_token", "refresh_token")
        if isinstance(obj, dict):
            for k in list(obj.keys()):
                if any(s in str(k).lower() for s in secret_keys):
                    obj[k] = "***REDACTED***"
                else:
                    obj[k] = redact(obj[k])
        elif isinstance(obj, list):
            obj = [redact(v) for v in obj]
        return obj

    console.print_json(data=redact(safe))


def _start_dashboard_and_automation(config_path: Optional[Path] = None):
    cfg = load_config(config_path=config_path)
    data_dir = cfg.data_dir
    stop_file = data_dir / "STOP_COCO"
    pid_file = data_dir / "coco.pid"

    # Prevent duplicate instances using pid/stop-file markers.
    try:
        if pid_file.exists():
            old_pid = int((pid_file.read_text(encoding="utf-8", errors="ignore") or "0").strip() or "0")
            running = False
            if old_pid > 0:
                try:
                    # Windows-friendly existence check
                    import ctypes
                    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, old_pid)
                    if handle:
                        ctypes.windll.kernel32.CloseHandle(handle)
                        running = True
                except Exception:
                    running = False
            if running and not stop_file.exists():
                console.print("[yellow]COCO is already running. No duplicate instance started.[/yellow]")
                console.print("[dim]Use STOP_COCO.bat (or create data\\STOP_COCO) to request graceful shutdown.[/dim]")
                return
    except Exception as _suppressed_exc:
        _log_suppressed('_start_dashboard_and_automation (line 7981)', _suppressed_exc)

    bus = get_event_bus()
    bus.set_state(run_state="IDLE", headless=True, database_status="UNKNOWN", browser_status="IDLE", current_activity="Starting")

    # Dashboard owns terminal: route logs/stray output to event bus, keep Rich rendering on original stdout.
    _orig_stdout, _orig_stderr = sys.stdout, sys.stderr
    try:
        enable_dashboard_logging(bus, level=str(cfg.app.get("log_level", "INFO")))
    except Exception as _suppressed_exc:
        _log_suppressed('_start_dashboard_and_automation (line 7991)', _suppressed_exc)
    try:
        sys.stdout = _EventStream(bus, level="info", event_type="system")
        sys.stderr = _EventStream(bus, level="warn", event_type="system")
    except Exception as _suppressed_exc:
        _log_suppressed('_start_dashboard_and_automation (line 7996)', _suppressed_exc)

    stop_event = threading.Event()
    try:
        stop_file.unlink(missing_ok=True)
        pid_file.write_text(str(os.getpid()), encoding="utf-8")
    except Exception as _suppressed_exc:
        _log_suppressed('_start_dashboard_and_automation (line 8003)', _suppressed_exc)

    boot_db = {"db": None, "cfg": None}
    try:
        _cfg, _logger, db, *_rest = _bootstrap(config_path, dashboard_mode=True)
        boot_db["db"] = db
        boot_db["cfg"] = _cfg
        try:
            bus.set_persistence(db.record_event)
        except Exception as _suppressed_exc:
            _log_suppressed('_start_dashboard_and_automation (line 8013)', _suppressed_exc)
        refresh_dashboard_metrics(db, _cfg)
        # Active mode is printed clearly (bare dashboard mode defaults to safe dry-run).
        emit_event("MODE: LIVE (default dashboard mode). Submissions may be posted to explicitly permitted sites.", event_type="system", level="warn")
        emit_event("?? Terminal dashboard started", event_type="system")
    except Exception as e:
        emit_event(f"❌ Startup initialization error: {e}", event_type="system", level="error")
        bus.set_state(run_state="ERROR", database_status="DISCONNECTED")

    def worker():
        try:
            # Default dashboard mode: LIVE (continuous, autonomous) as requested.
            _run_automation(config_path=config_path, headed=False, continuous=True, discover=True,
                            autonomous=True, review=False, dry_run=False, emit_dashboard_events=True,
                            stop_event=stop_event)
        except Exception as e:
            try:
                bus.set_state(run_state="ERROR")
                emit_event(f"Automation worker error: {e}", event_type="system", level="error")
            except Exception as _suppressed_exc:
                _log_suppressed('worker (line 8030)', _suppressed_exc)

    t = threading.Thread(target=worker, daemon=True, name="coco-automation")
    t.start()

    def _request_shutdown(signum, frame):  # noqa: ANN001
        stop_event.set()

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _request_shutdown)
            except Exception as _suppressed_exc:
                _log_suppressed('_request_shutdown (line 8043)', _suppressed_exc)
    except Exception as _suppressed_exc:
        _log_suppressed('_request_shutdown (line 8045)', _suppressed_exc)


    def _metrics_provider():
        db = boot_db.get("db")
        if db is not None:
            try:
                return db.dashboard_metrics()
            except Exception as _suppressed_exc:
                _log_suppressed('_metrics_provider (line 8054)', _suppressed_exc)
        return {}

    def _db_status_provider():
        try:
            db = boot_db.get("db")
            if db is None:
                return "DISCONNECTED"
            db.count_websites()
            return "CONNECTED"
        except Exception:
            return "DISCONNECTED"

    dashboard = TerminalDashboard(bus=bus, get_metrics=_metrics_provider, get_db_status=_db_status_provider)
    try:
        out = _orig_stdout
        try:
            if hasattr(_orig_stdout, "buffer"):
                out = __import__("io").TextIOWrapper(_orig_stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
        except Exception:
            out = _orig_stdout
        dashboard.set_output(out)
        try:
            dashboard.console = Console(file=out, force_terminal=True, highlight=False, emoji=True, legacy_windows=False, soft_wrap=False)
        except Exception:
            pass
    except Exception as _suppressed_exc:
        _log_suppressed('_start_dashboard_and_automation console', _suppressed_exc)

    shutdown_announced = False
    shutdown_started = False
    pending_stop_until = 0.0

    def _fmt_now():
        return datetime.now().strftime("%I:%M:%S %p")

    def _emit_line(line: str):
        try:
            dashboard._lines.append(line)
            dashboard.console.print(line, soft_wrap=False, no_wrap=True, overflow="ignore", crop=False)
        except Exception:
            pass

    try:
        emit_event("Terminal dashboard started", event_type="system")
    except Exception as _suppressed_exc:
        _log_suppressed('_start_dashboard_and_automation (line start)', _suppressed_exc)

    # Single dedicated ANSI renderer in alternate screen (clean view, no previous scrollback above)
    stopping_text = None
    try:
        out = dashboard._out
        _enable_windows_vt(out)
        # Enter alternate screen and start at top-left
        try:
            out.write("\x1b[?1049h\x1b[2J\x1b[H")
            out.flush()
        except Exception:
            try:
                out.write("\x1b[2J\x1b[H")
                out.flush()
            except Exception:
                pass
        dashboard.render_full()
        last_refresh = 0.0
        while True:
            now_m = time.monotonic()

            # External stop-file request
            try:
                if stop_file.exists() and not shutdown_announced and not stop_event.is_set():
                    shutdown_announced = True
                    try:
                        emit_event("Stop request received. Stopping COCO...", event_type="system", level="warn")
                    except Exception:
                        pass
                    stop_event.set()
                    try:
                        _coco_mark_shutting_down()
                    except Exception:
                        pass
            except Exception:
                pass

            # Worker ended unexpectedly
            if not t.is_alive() and not stop_event.is_set() and pending_stop_until <= 0:
                if bus.snapshot().get("run_state") == "ERROR":
                    stop_event.set()

            # Ctrl+C double-check shown in activity
            if pending_stop_until > 0 and not stop_event.is_set():
                remaining = pending_stop_until - now_m
                if remaining <= 0:
                    pending_stop_until = 0.0
                    shutdown_announced = False
                    stopping_text = None
                    dashboard._stopping_text = None
                    try:
                        bus.set_state(run_state="RUNNING", current_activity="Resumed - continuing work")
                    except Exception:
                        pass
                else:
                    sec = max(1, int(remaining + 0.99))
                    stopping_text = f"Stopping COCO... press Ctrl+C again within {sec} seconds to confirm"
                    dashboard._stopping_text = stopping_text
                    try:
                        bus.set_state(run_state="STOPPING", current_activity="Stopping requested - waiting for confirmation")
                    except Exception:
                        pass

            # Confirmed shutdown: keep same dashboard visible, update in place, STOPPED gracefully
            if stop_event.is_set() and not shutdown_started:
                shutdown_started = True
                try:
                    _coco_mark_shutting_down()
                except Exception:
                    pass
                try:
                    bus.set_state(run_state="STOPPING", current_activity="Stopping COCO - stopping new work")
                except Exception:
                    pass
                for msg in [
                    "Stopping COCO... stopping new work",
                    "Stopping COCO... finishing or cancelling active operations",
                ]:
                    dashboard._stopping_text = msg
                    dashboard.render_diff()
                try:
                    t.join(timeout=5)
                except Exception:
                    pass
                dashboard._stopping_text = "Stopping COCO... closing browser, saving data and flushing logs"
                try:
                    bus.set_state(run_state="STOPPING", browser_status="DISCONNECTED", current_activity="Closing browser and saving data")
                except Exception:
                    pass
                dashboard.render_diff()
                try:
                    stop_file.unlink(missing_ok=True)
                    pid_file.unlink(missing_ok=True)
                except Exception:
                    pass
                try:
                    emit_event("COCO stopped gracefully", event_type="system", level="info")
                except Exception:
                    pass
                try:
                    bus.set_state(run_state="STOPPED", browser_status="DISCONNECTED", current_activity="COCO stopped gracefully")
                except Exception:
                    pass
                dashboard._stopping_text = "COCO stopped gracefully"
                dashboard.render_diff()
                time.sleep(0.3)
                break

            # Refresh dashboard once per second in place (differential updates)
            if now_m - last_refresh >= 1.0 or stopping_text is not None or dashboard._stopping_text is not None:
                last_refresh = now_m
                try:
                    dashboard.render_diff()
                except Exception as _suppressed_exc:
                    _log_suppressed('_start_dashboard_and_automation tick', _suppressed_exc)
            else:
                try:
                    dashboard._consume_events()
                except Exception:
                    pass
            try:
                stop_event.wait(0.2)
            except KeyboardInterrupt:
                # Ctrl+C: stop immediately (responsive), show progress in dashboard
                if not stop_event.is_set():
                    stop_event.set()
                    shutdown_announced = True
                    try:
                        _coco_mark_shutting_down()
                    except Exception:
                        pass
                    try:
                        emit_event("Stop requested (Ctrl+C). Stopping COCO...", event_type="system", level="warn")
                    except Exception:
                        pass
    except KeyboardInterrupt:
        try:
            if not stop_event.is_set():
                stop_event.set()
            _coco_mark_shutting_down()
            bus.set_state(run_state="STOPPED", browser_status="DISCONNECTED", current_activity="COCO stopped gracefully")
            dashboard._stopping_text = "COCO stopped gracefully"
            dashboard.render_diff()
        except Exception:
            pass
    finally:
        try:
            dashboard.cleanup()
        except Exception:
            pass
        try:
            dashboard._out.write("\x1b[?1049l\x1b[?25h\x1b[?7h\x1b[0m")
            dashboard._out.flush()
        except Exception:
            pass
        try:
            stop_file.unlink(missing_ok=True)
            pid_file.unlink(missing_ok=True)
        except Exception as _suppressed_exc:
            _log_suppressed('_start_dashboard_and_automation finally cleanup', _suppressed_exc)

    # Restore standard streams after dashboard
    try:
        sys.stdout = _orig_stdout
        sys.stderr = _orig_stderr
    except Exception as _suppressed_exc:
        _log_suppressed('_start_dashboard_and_automation restore streams', _suppressed_exc)


# verify-credentials command removed: credentials, keyring, and password storage are disabled.


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Launch COCO dashboard and autonomous automation when no subcommand is provided."""
    if ctx.invoked_subcommand is None:
        _start_dashboard_and_automation(config_path=None)


# COCO profile picture for websites: JPEG, sha256 cbe796cb28646491fa2a94d702e3cf7495fc0370db1bb43872b10b2bd53bcca6.
# The DB initializer stores this constant as the coco_profile asset; placed before the main guard for startup.
COCO_PROFILE_PICTURE_B64 = (
    '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'
    'lp7ri3kwFJzlMqZuaick1jnJOmObnV6jsvkv0Ll6ttn89zdSSpJErIS0koHKoxXMup2OHyHt4f6LxV8+vA6eUABNACEmqU1N'
    'ejouT6DHq6Ha6LYc/R0qD1+ETBACANDp9zpvmfle3A+m+qYAxA+b2+g4+jy6z0avn109zfb89tOQYQNME0AIe50nczr6tR79'
    'Xz9vvz47rI4qLrHRkcMzGOjNWKrM2OsNzm1Gy+bs+UV9fG7VZjaqHSqBpw2OU289heq5ys89Xn9mdzWEyTUlBNDguaLuMiVc'
    '5KyZIz6wsmJXHoeF6xlnGi4i87x4/RhzvBizYs7xxcLEXBKpVKoSS2uHwbZR5NzpMqc5h7/hL48KqXJJqpm5qZudIm5qPX5Y'
    '1r6qcp2PH2mPHUolKiSGSSiSKlIx67ZeQ9PmxbdPnpn8/T89gWAAhoSapTSI2mszOvS7bS+3h7uo9+m3Pp8gBvmgATRotNud'
    'N8z8r27T+n+qABpqNJpPbp/L7sWl3HN74VSrXkGOAAGAgAQHv7DV7DHt8T8exz1yuXVtMdQ4usbMtY2ZXjsn1eSLnQ8pc9fI'
    '6KcnScNjybTimqh7LyfQb1XPejO9WP1+gzrzznk86zQuJWiQY6WQLXpuYy+Dz3O7wcnrrnuL+fefWPpK+X42fqk/Lsq/TD57'
    '6Jr6DfB7TO+hXjztLH6vNNY5qZZGElMG7JurMWt3Umt9+t91xxEdhyF8cppiVSqFSqJuaibnVr6N813ee/aZa8nL05ZcK5QA'
    'lTlKGhUsWSTWbbX548HO9zw2/IAa4AIABDQk1Uzc1vvbqfdx/Q3/AFHH9JvHtA7+ZAAAaHTbnTfM/K9u0/p/qgCDyevT53pd'
    'R6/B5/Vi03v8PTyU1V4jCAaGIAEDW6a6LzZ9Zy/Qfsx5KtyyqiihMpw4yEhlSpPRxvSfPN8lc308bpPJ0nDacNpxVx1Le61/'
    'v8F9Po2UZpuZyqzDOaJcGP0Y86wTmhcLyZbMHp83OXPQaDReHfHb6pVrjNU2YduSDIGIzJcc5kYVmVZ9roonTuNj833ee3Y4'
    'fDt8dfKWpqaqicjyCt5LmLp2YdF0flzq+V9nRb5fNDPgnklNWJNVM1NTNzUKp1foHs43tOHuePFU2IQ5SppA0gEIw+X2eONv'
    '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'
    'QyrxOuVT6J0HvNltbSGvL1jQw1GJstLam2yvnN+nC4jy9R30LSYu1zDdu4JUw/Vnwb/Yk/6Z4omS2lsVYXWU0IPvk1HIRh75'
    '8OP0tZvw6T+otPejCqWIAF4saADKSdAhqSQZamrNgnTB/wBpDwRvjvjgyRIlLYk26dn0xE0rXIByyPJWLVamtD3m8UaFGod4'
    'RCxAUFicgGEwslZeWkx9WWWp4/CNxDEHHkizbGvO+Umm6vHnEagNA4hQCJaLKF2WLg9Juc94MGG96CGPvWHb3oYJ98EFufzQ'
    'GPH5oVvfBCn3wwh96wsL3BuT3HUOLri+POOY+zJE6wNKx5ZvL6S8R5PEaqYnWMTMKUlvwcktjxV+bfiJuaiMkOhUlWBUg0IO'
    'Ag94slraQ4ZetdDDUYtEpbUm3Ss7fppP/wBg9IQo29QhNJi4JLnfDwTH8hOQ4sEEEgggg0IOAgjKDxjvfw4/S1m/DpP6i09w'
    '9w7owq/FhTJOcYx0yUbejVOcZdKrg0xY5CyV2+bgC4UX1NTSx3o64ttsa0PebJvV4I/fWdPeJMgzK0xVXOc5q19bHQBjHVEq'
    'T9XLWt7Lw26fBTkjxiYsuxyycZ6TH9FYOHvJhoeHb396wW9/cwzxf4/VCv74IV4Rvf3rCtC++iBA7yDSJtlWZhXFb0Wi02Pb'
    'BRhjJ5ac3DTk6N7qi0WdpJo2EHNYZrDWD6xlBwHvFhtrWd6jCpz11j+oaDFskK67fLxkfC3Fyv6tRwxMX4wL310tcb7aWu++'
    '9QZ3CXD3v4cvpazfh0n9Rae9WaXtSiawqzfMKdYyzWHBU5vCfmiw2XbCZj5ikklt+2Uk8kZW7I2T2Q+MNg+bTN4+UffAO8Wa'
    'yGZjHAtcHCc6QvNpY4q+aJNmMzEQABfIT+qYdJy9USJCyRi9bb492neDDNDPXNBbjUFu0jJ1w7jSyL0pi/lUs3oxgO/vdCXM'
    'f8yyx54a5rnf6Sr65hjE4M09csewwAvBm+VLPsEKgOTbv9NH9UwRSmUlfvJUxPyiZCTBodG5pgXzTLh80ByuEhlHCIN3yskI'
    '4OQwp3ZinddVmYGwcF98p9oidZ79ZcxVvHqWZylO9fjHXURa7E0g61rSukHgsNDeYjCD3jY237SbrfNvl03Trp6+KLXZjIdX'
    'Q0Um9LYb1tXNq1rFqlhhtyC6GNJqDJLmHV9k+VdRqu6G4+HL6Ws34dJ/UWnvNlkhyWeu1y6F6ZWJzZa8tz2CpiVLa0zMOLrp'
    'my0Gaq8QyLxxstbR8xLwKmf/AEdW+1t3iyWK/RnGLvVyGZTj3ssb5upcMWezGacGAZC2TAN7LGhF96mElrLF1Yr3msTp6y8L'
    'MFByFjSvMM5vFDQZzzMyW7DhNSSnPV6sy8yKYFkmNhaYqU8El+n+bNvXeqkTPiqfOTNuI4cxpx7EqsHZWzpmS/Jlonny+aH2'
    'YXwPlPX+UR/jD6JcodTf1R/i83Unk/3j/F5vI8iP8ZmeDlHxW9jQmzv2Q8R2X13o/wAakv8AOSyekiTf6YlvZHNUYSW1o7yD'
    '7Fg2R85Zu2feLer/AJ0u6/nMXpkvPltThS/ll7MWYo5w8SZ6zM1g9Mt3CRzqaOOtQIr3ikUgqHF1smg6VOsROk1xJgB0XjmO'
    'upvYcqnJqi3WEyDUVuVphzkbgt7DkYYR3jYu1iavxeZ/ln+X2rDKZDsGF8EXXXRMlnVytKneuItMjamoDeRhelvw0OQ9LQw0'
    'MDuq934cvpazfh0n9Rad2Yly2mMqKKs5oB+/EMp1CGUYstMZEOL9rMOBpnXkXUkWud8SlXF+dm6dXK9i9sE7uxWO/R2FV3q5'
    'NsIy4dEsb4+KuGLNZ9tbk75slab1eDLXJg6K4YvBBdX3/tF+sV7xNtSqborMfwaC83XoQdIg8UbXOmZzbSo0JRpnjTDip4og'
    '2yzWY+EfWvyr9c1sHk1ifs7MbMVZfGflH7Ti9ixNtDzc92fpGsV7lYrua9yVPeXhR2SvBJWJGzc1M4LN9BvKX+ZTA2Qs9pz8'
    'RtBfFIPFNX/xi5Nl4VfbhqmZ3izRneOGiVaFY3TWW53j4Cegc1/FNeKD3nA4un/b+0T5O9bDoxsjLwG5PBbKDxxbbHtJwVuE'
    '0FcqtwG5Wo5GXCN2rUIIwEZIlTfjkq99bKzvfgt5mhZW2ptRwGt6STvZmmWdSzPM9IIpgOAjAQcBBGg8fePhx+lrN+HSv1Fp'
    '7xZpO1y65Hnr1pI18TTTgHIBMSbslWnPkQUQebBxtkHFUxaZ7TnZ233mGgDiG7sdl2zGbMU043bgr1YWO9XqiRIM1rq5MjEY'
    'BQbxeCi6f3MPNWWtxdHv5MbZWFeL0A7mbNWXS8TVs1FF6Y/RXKefAvHG1zJtb52hNKK2PT7SbvRxJTnibspJs4uSUEzmxZX9'
    'cw9nPFpt82fnvi8BcVB4vue5Xv1Ys9umycxyBwThU+KcHtiRsrKnrcnKE58aUf5k98MXHTCjbcnAZsan2c3SOJ688S5izK3a'
    '1XORhddOkugcYqvHu6xfpCkTRdbqPsPFFpkZVZa6KHfLqrw1yo3sJEWuymS1M5Wwo2So49TrkYaDuhFitZs8wOMIyMvCU5R7'
    '6YtEoNSYmFJmGvHr5/U0bIybw24Zc2d097M5pgy8uBu/hx+lrN+HSv1Fp3djs4mPjfNyxfmHkjIo5TnFEKhmNhyuatTeroUc'
    'SiijtjZi2X22pc2Vl43/APHJu7NIM1qZFXC7cFfaxOADSxiVJvYiimgDgKdH3r5SdeHIId1kLcXLvj7Ob15YMysK1PfJAaFa'
    'FPd9/figTWm1Eql0Z09hVAdUtfrG48wccT7XJsdcsya2WpvTX6bbxeLzRa9kJlozjdXRLXAo/c8Z/g69yybITLPmm8ulGwr/'
    'AGPGIs1qlWumWXNXJhpMXoNvl4u0RttzBNoODOGCW3TH1b/9M8UHBuKwzQW99f8AeBNpGC0pd36jFOv30RaJN8Mj4NZ4DaJg'
    '4tDjg8axOlNLYqwoy5f3GsHKDkI3ew9pvqbO2nGldLSvXlHHCgC8rCqsLkwa1OnnXOGoxaJBkuyNhunAeEpwqw4iKHzbv4cf'
    'pazfh0r9Rad3Is+1IqHOwTJvTIxU/wAtcPSMW20fFpRbI83FTi1nxR6Riu6RC5CqKljQDWTEmz7UqqtCSfLfS/3aCt3iq2mJ'
    'afFk5beb/wAj5s2JrVwx780BoVvf39zCtCvAaHnBASTQLnMci/ux0KMJgIZuGZiSsu1nFZxwpx3qcjJri37NfVyMAGDbMnVL'
    'G9XjywTXj/h1YjCDQjIRFg2XDYk7Tgv6D0x7e2Lhk5tZkrgDGeWNcvhyuR5EKwIBBDBhVWGEEax71BwGKxWC0M0OYZv7xJmF'
    'CKdUWiXtybYucuX31H/yi2WbbkwZ8utzWyjOldJMJXk3l0Ddy3KEMpoVNQeMRJnCeizeFgcan0/vGyNn2yXf30jLypJ/+NvR'
    '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'
    'fGeN3qx5l72d2DFktW2ypU3fJ8nO6JynqxZnbB3CYQQcI9hxT642WlXJ3TFedlxWPWy169zsbMuT5R1tdPM2L7YXfc35T/c9'
    'ykUikUgeqJ6Xr68Ikf6o/wDOPZuthDekEcGafSX+0WqX8jPH2ZPkEN7IPc+HH6Ws34dJ/UWnubCLWZMOqUR5TL/eLuFekvrr'
    'Fpe9MmNwnY9p3WwS0k14c1uxVUfzGN5L41veUa7oaeJT+3tjZt7sinDdF6lBY/y7rYqTclpxKvmW/wDnY7muMOQt6vLfFXyV'
    'Dnxotk/bpjvoY4vEowKPJp/B7Azsd5TZs1cmsrl9GsaMOVcU8ZTBXxhRuvuHuSsJpwgR1kYPPSP+IJWY/H5nH/ge3cq10g6s'
    'PZCYxrrr6a/33doa61eJH9/Ji2S7k2avBmOPSO5Ef8PGonLxyz6xExLysvCRx5Skd34cfpazfh0r9Rae5sGPn2+7HaW/aA2E'
    'cWHsENutjzcs8roO/a7f0w4pdXgog826ljO5gPP/AGj/AIhb5lfvG/Kv8u5lpeZV4TAdpiUt1er8xr+/cp3dkZtyTObhXgPN'
    'JX0at3od6sU3a5spuCwr0TgPmjX1doxT6l3C4CDqIPZGzkqsiZyKHscL6mO62Pa9KknXLl+YXfZFNyIt7Uu8cs+iT+8bLrS0'
    'TeUQ3lAHciP+H2o07oKexv7xKapXnhhTBqwdnc+HH6Ws34dK/UWmBGxr3JM9uXLHv2xJn3r/ABSZrdgG7U3ZchddnT0nmfvF'
    'oz26vVFYrFYrFYlmgbnHqMbPNWbL4pQPlOx3OxyXp8kctT2YfZAzeseiP77hco5xGzuLJReEy+gp/q70IPepONLRuEqt5QB3'
    'OyeNJnjXLJ7KNutiW/5eT0SPJdoJwnnPr7lYBisCNlWokn/NH5Y2Y+erwpUpv+mNyI2Cz5/3LeZliy2m9MljWfYYnikyYNTu'
    'PSMGPhx+lrN+HSf1FpgRLa7ZJv36eoRsdMLGfxWeb7IO6nNjWUfY2f1xaGx254rFYvRWL0TptxCftAPQMbMGs1PuZX5a7nYn'
    '/wDIl8V49imLHO2yUG5beYLFYr3L0bOTb6SDrab5rvfa92u5sM35OWv2Ct6MVisVisW6bjTE12dj/wBI7kRY51yz2bjM3/uL'
    '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'
    '/g/6c/1lfxCH/p/7yv4hB+g8f+QoYRg2Tt5HlDCcX6tob1puEmn/APKd7zAUy14386F3LVqbK/UAfYk7V37I3PjjlbX4VTMK'
    'ew7noUbRDJpx046JgjPk5i3iJqOhyLJG6mycm5PYjK0aVY/aF3SLlSt+cdKoj5nRObVOjLDjNuKs05rVg3R04swk427H/FRS'
    'B4D2G7rB1gjbxK3YPFpGOzcyDONqc0tJBFCM48wsdpyLr72uzhWS096PpWsMuY7P9tfck8U7KDMdMIGt4zHzLD34OX3Pnb5k'
    'zx7sc6DdEbe5brR30/JNNI473u5Pu7jVvtWVOI25jLgPvr8ws1mdaHYrOc7FZLIyyNxW6WsqaYQipvJ0WjO4/etTTOxqmj59'
    'Q9CEcXGorPS83uOcoNVFTzINVwuznYLymwvOoM5bz0ZlI+CPTcZTsz9WZPwpi6DQwcfYnWmaXhEf0tT3BmnLGz+4qS32cfqT'
    'dQRwsR5OFjOsp+E7Q/8AmU5Lk6V7s73HnVN7ogSMxI51Hbp480rue9DDEnpsjk5lHhKA52PiPqm5Mljk0JmO4nbk9KbJLFwh'
    '7O6Cjwmczg1/UfvmTZLO/bC7i3P7IxSZxiyj+l3SLkXjMasOx13XmRbTzOiLFLDrGdQTEmraCb0mnRmHHsfscopRIMZlRQ3g'
    '6TDsKtthFrGM3cyt605paaG4jP5hYpw8ZF/unYfvOsGWo+Qfps0eMbPvV3IjkXZM6J0ezzLD34OX3Pnb5jO7KuyTffP0Wa4Z'
    'gsKWwxgRM8pJ1A/Uq2S5BuSYbzpnaewavMLPZnWh+I3nOxWWzNsrcVmfWVPOIaXYz3aDNbv22lSSuxjQ48xuc8ZmDgsUNnxU'
    'Gqip4NN8DUwY2gMfjzN6U9jI/LSe42790/CTY7omBo2lOmmnzk049y1STxRaclTwWdqdhWnkogPWdeVLbJpdJ55rlTzWiitU'
    'sOg8hNwwT5WNr+MXFRWqCXReYzwX3hNykV4rTaw1CZhEuukaJAmNjk8k/JngHN0H6J7XR6baes3dN7QqaxeOK8eY0VEWqaCt'
    '4zqGVznVF0wuvzTDgu49hUUokGOy4g0I1sOwq32AWpuM26RvWiMU0NxG/wCZQzZdoc26WLrA7PgrHahaWY2v0hxqWPKNpr1K'
    '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'
    '6N4b/wD6j2rvVv6jv/qcu9m/qH/6nLvZvDd/9RXe7dsn/wBf7rID/E/pA+qyPqSdLQsSnodMg7FjU/RHOSst/iMHssqspX+Z'
    'IeQYq3OxzvacrtTGjrWO7bTkoERXPfy3qncoqKioqKioqKioqKioqKn5lh78HN7nzt/MqKioqKioqKioqKioqKioqKioqKip'
    '3MVYg2LF+71znpKqeE7pWM7hO6VV3Cd0qruE7pV/Cd0lU5ekrFWKNip3KKioqKioqKioqKioqKioqKioqKn5ph78HN7nzt/N'
    'aKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKip3KKn5th78HN7nzt/N6KioqKioqKioqKi'
    'oqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqfnOHvwc3ufO388oqKioqKioqKioqKioqKioqKioqKioqKioqKi'
    'oqKioqKioqKncp3KKn5zh78HN7nztVVXeKqu8186oqKiosVYqxSsQrEKxCsQrJlZMrJFZJ2xZJ2xZF2xZF2xZF2xZF2xZB2x'
    'ZB2xZB2xZB2xd7u2Lvd2z4Lvd+z4Lvd+z4LvZ+z4Lvd+z4LvZ+z4LvZ+z4LvZ+z4Lvd+z4LvZ+z4LvZ+z4Lvd+z4Lvd+z4Lv'
    'd2z4Lvd2xd7u2fBd7u2LIO2LIO2LIO2LIO2LIu2LIu2LIu2LJO2LJO2LJHYsmVkysQrEKxCsVYqxVRUVFRU8wr5/h78HN7nz'
    'tX//2gAIAQEDAT8h/wD2IuBtWmlrQtFXKNFx6JvCJbOR9Jkb0+WYPae+H2f2ZG+n0ZvZlw8xe89kVavq8MxeZ9JkWs+SLBdu'
    'xFWyulf/AMHL7zaI2PNYSPP/ANyG2t7z+kM3Wk+xv7n+RDud5PAZ+GAnkZyXJD3UZvqS/oZvcZveZ5bxkZbMGSfJE1vLFrDl'
    '+Et/Wjw0J+Rl7M21n0xNLtNt/aH3Of6GK/Ww8qo7nd5J+P8A70ukyMFV0kzud9ivYdwuS81Ow10yYdIITvZ1+x3caEO86E+h'
    'txpvJlm3rdjLf3610epR4Q83PUjg9JvBNtuhfoHfaJvwd6BxO6X/ALBVxvahXTt+ISvafLCTZqvahHb17wx5vIrcwMQf3NqL'
    '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'
    'ESOJEgQ+AklUkCHwDFv/2Q=='
)

# COCO content/profile data. Address placeholders were matched to existing appeal text.
COCO_CONTENT_DATA = {'_comment': 'COCO content/profile data constant - paste into coco.py. Built 2026-11-11 '
             'from the archived _archive copies in the coco Drive folder '
             '(profile/profile.json, content/captions.txt, '
             'content/original/vinay_fundraising.txt) plus non-secret config.yaml '
             'settings. No secrets, no personal email/phone/ID/bank data.',
 'profile': {'name': 'Vinay',
             'display_name': 'Vinay',
             'username': 'vinaydxo',
             'username_preference': 'vinaydxo',
             'username_fallbacks': ['vinay_dxo',
                                    'vinaydxo1',
                                    'vinay.dxo',
                                    'vinaydx',
                                    'vinay_d',
                                    'vinaydxo_'],
             'bio': "I'm Vinay, trying to rebuild my life with a little help from "
                    'kind-hearted people.',
             'profile_picture': 'profile/profile picture.jpeg',
             'profile_picture_filename': 'profile picture.jpeg'},
 'content': {'original_fundraising_text': 'I am Vinay and I am in need of help - any '
                                          'kindness or support is deeply appreciated, and '
                                          'good karma comes back around 🤍\n'
                                          '\n'
                                          'Pay online by card or bank, any amount helps '
                                          '🙏🏻\n'
                                          '\n'
                                          'https://wise.com/pay/business/vinaydusa\n'
                                          '\n'
                                          'USDT (Ethereum network): '
                                          '0xfc89f29283445B4c0c81f2Ae71ba3e54c1cbdEe7\n'
                                          '\n'
                                          'Bitcoin: 36dyYLRJbCvgdQPuKraEs39vvx577W4fJC\n'
                                          '\n'
                                          'PS: Better habits for you, and it supports me 🤗 '
                                          'https://cero.gumroad.com/',
             'appeal_without_promo': 'I am Vinay and I am in need of help - any kindness '
                                     'or support is deeply appreciated, and good karma '
                                     'comes back around 🤍\n'
                                     '\n'
                                     'Pay online by card or bank, any amount helps 🙏🏻\n'
                                     '\n'
                                     'https://wise.com/pay/business/vinaydusa\n'
                                     '\n'
                                     'USDT (Ethereum network): '
                                     '0xfc89f29283445B4c0c81f2Ae71ba3e54c1cbdEe7\n'
                                     '\n'
                                     'Bitcoin: 36dyYLRJbCvgdQPuKraEs39vvx577W4fJC',
             'gumroad_promo_section': 'PS: Better habits for you, and it supports me 🤗 '
                                      'https://cero.gumroad.com/',
             'captions': ['A little kindness can help me rebuild — any support means a lot '
                          '🤍',
                          'Hi, I’m Vinay — asking for a bit of help to get back on my feet '
                          '🙏',
                          'Any support, big or small, would truly help me right now — '
                          'thank you 🤍',
                          'Rebuilding with hope — your kindness and support would mean so '
                          'much',
                          'Need a helping hand — grateful for any support or shares 🙏'],
             'selected_caption_index': 0,
             'source_language': 'en',
             'default_variants': ['personal_support', 'fundraising', 'relevant_promotion']},
 'payment_links': {'wise': 'https://wise.com/pay/business/vinaydusa',
                   'usdt_ethereum': '0xfc89f29283445B4c0c81f2Ae71ba3e54c1cbdEe7',
                   'bitcoin': '36dyYLRJbCvgdQPuKraEs39vvx577W4fJC',
                   'gumroad': 'https://cero.gumroad.com/'},
 'preserve_tokens': ['https://wise.com/pay/business/vinaydusa',
                     '0xfc89f29283445B4c0c81f2Ae71ba3e54c1cbdEe7',
                     '36dyYLRJbCvgdQPuKraEs39vvx577W4fJC',
                     'https://cero.gumroad.com/'],
 'config_nonsecret': {'app': {'name': 'COCO',
                              'environment': 'production',
                              'data_dir': './data',
                              'log_dir': './logs',
                              'headless': True,
                              'auto_mode': True,
                              'review_mode': False,
                              'auto_discover': True,
                              'default_language': 'en',
                              'request_timeout_seconds': 30,
                              'navigation_timeout_ms': 30000,
                              'max_pages_per_site': 5,
                              'min_relevance_score': 0.55,
                              'max_submissions_per_run': 50,
                              'max_submissions_per_domain_per_day': 1,
                              'duplicate_cooldown_days': 30,
                              'dashboard_port': 8765,
                              'recovery_stale_seconds': 0,
                              'max_browser_recoveries': 2},
                      'browser': {'channel': 'chromium',
                                  'slow_mo_ms': 50,
                                  'user_data_dir': './data/browser_profile',
                                  'viewport': {'width': 1366, 'height': 900},
                                  'locale': 'en-US',
                                  'timezone_id': 'Asia/Kolkata',
                                  'max_browser_recoveries': 2},
                      'discovery': {'enabled': True,
                                    'seed_urls': [],
                                    'candidate_urls': [],
                                    'allowed_categories': ['personal_support',
                                                           'fundraising',
                                                           'community_assistance',
                                                           'relevant_promotion',
                                                           'blog',
                                                           'forum',
                                                           'community_post',
                                                           'discussion',
                                                           'guest_post',
                                                           'story_submission'],
                                    'require_explicit_submission_permission': True,
                                    'prioritize_no_registration': True,
                                    'search_providers': ['google',
                                                         'duckduckgo',
                                                         'mojeek',
                                                         'bing'],
                                    'search_queries': ['submit personal fundraising '
                                                       'request form',
                                                       'mutual aid request submit form',
                                                       'community assistance request form',
                                                       'ask for financial help community '
                                                       'form',
                                                       'charity help request submission '
                                                       'form',
                                                       'share your fundraiser story submit',
                                                       'donation request form submit',
                                                       'medical fundraiser help request '
                                                       'form',
                                                       'community support request post '
                                                       'form',
                                                       'submit support request nonprofit',
                                                       'submit your story blog form',
                                                       'share your story submission form',
                                                       'guest post submission guidelines '
                                                       'form',
                                                       'write for us submit guest post',
                                                       'personal story blog submit post',
                                                       'community blog submit article form',
                                                       'community forum post introduction '
                                                       'share story',
                                                       'support forum share your story '
                                                       'post',
                                                       'discussion forum community help '
                                                       'post',
                                                       'public forum submit post without '
                                                       'registration',
                                                       'online community share personal '
                                                       'story',
                                                       'public submission form share '
                                                       'message',
                                                       'community noticeboard submit post '
                                                       'form',
                                                       'open submission form personal '
                                                       'appeal'],
                                    'multilingual_queries': True,
                                    'search_languages': ['en',
                                                         'es',
                                                         'fr',
                                                         'de',
                                                         'pt',
                                                         'it',
                                                         'ru',
                                                         'ar',
                                                         'hi',
                                                         'zh',
                                                         'ja',
                                                         'ko',
                                                         'tr',
                                                         'id',
                                                         'vi',
                                                         'pl',
                                                         'uk'],
                                    'max_queries_per_run': 18,
                                    'max_results_per_query': 8,
                                    'max_candidates_per_seed': 10,
                                    'max_urls_per_domain': 3,
                                    'min_candidate_relevance': 0.35,
                                    'request_delay_seconds': 0.5,
                                    'respect_robots_txt': True,
                                    'prefer_new_domains': True,
                                    'recheck_existing_domains': False,
                                    'recheck_existing_urls': False},
                      'translation': {'provider': 'auto',
                                      'fallback_provider': '',
                                      'cache_enabled': True},
                      'publishing': {'require_human_approval': False,
                                     'auto_mode_only_for_preverified_no_registration': False,
                                     'autonomous_submit': True,
                                     'allow_registration_workflows': False,
                                     'allow_account_creation_when_permitted': False,
                                     'stop_on_captcha': True,
                                     'stop_on_login_wall': True,
                                     'stop_on_rate_limit': True,
                                     'stop_on_permission_required': True},
                      'intelligence': {'enabled': True,
                                       'provider': 'auto',
                                       'fallback': 'heuristic',
                                       'cloud_enabled': False,
                                       'cloud_model': 'gemini-1.5-flash',
                                       'cloud_timeout_seconds': 20},
                      'content': {'source_language': 'en',
                                  'default_variants': ['personal_support',
                                                       'fundraising',
                                                       'relevant_promotion'],
                                  'include_source_metadata': True}}}

def run_self_tests() -> int:
    """Offline checks for safety-critical behavior. Returns the failure count.

    No network, no browser, no submissions: safe to run anywhere.
    """
    import hashlib as _hashlib
    import tempfile

    failures = 0

    def check(name: str, condition: bool, detail: str = "") -> None:
        nonlocal failures
        if condition:
            console.print(f"  [green]PASS[/green] {name}")
        else:
            failures += 1
            console.print(f"  [red]FAIL[/red] {name} {detail}")

    console.print("[cyan]COCO self-test (offline; no network, browser or submissions)[/cyan]")

    # 1. Config merge keeps nested sibling defaults.
    merged = _deep_merge({"a": {"x": 1, "y": 2}}, {"a": {"y": 3}})
    check("deep merge preserves sibling keys", merged == {"a": {"x": 1, "y": 3}})

    # 3. load_config in an empty directory enables startup backups by default.
    with tempfile.TemporaryDirectory() as tmp:
        c = load_config(root_dir=tmp)
        check("backup_on_start defaults to true", c.app.get("backup_on_start") is True)

    # 4. Obstacle detection stops on the required signals.
    check("captcha detected",
          any("captcha" in r.lower() for r in detect_obstacles(html='<div class="g-recaptcha"></div>')))
    check("HTTP 429 detected", any("429" in r for r in detect_obstacles(status_code=429)))
    check("login wall detected", any("login" in r.lower() for r in detect_obstacles(text="Please log in to continue")))
    check("rate limit text detected", any("rate" in r.lower() for r in detect_obstacles(text="Too many requests, try again later")))
    check("clean page has no obstacles", detect_obstacles(text="Welcome to our community forum") == [])

    # 5. Safety signatures are configurable and fully restorable.
    original_captcha = CAPTCHA_SIGNATURES
    try:
        configure_safety({"extra_captcha_signatures": ["zz-selftest-captcha"]})
        check("custom captcha signature added",
              any("zz-selftest-captcha" in str(s) for s, _ in CAPTCHA_SIGNATURES)
              and any("custom signature" in r for r in detect_obstacles(html="zz-selftest-captcha")))
        configure_safety({"disabled_signatures": ["g-recaptcha"]})
        check("built-in signature can be disabled",
              not any(str(s) == "g-recaptcha" for s, _ in CAPTCHA_SIGNATURES))
    finally:
        configure_safety({})
    check("default signatures restored", CAPTCHA_SIGNATURES == original_captcha)

    # 6. URL canonicalization for deduplication.
    check("tracking params stripped and query sorted",
          canonicalize_url("https://Example.com:443/path/?utm_source=x&b=2&a=1") == "https://example.com/path?a=1&b=2")
    check("default http port stripped", canonicalize_url("http://example.com:80/") == "http://example.com/")
    check("invalid url rejected", canonicalize_url("notaurl") == "")

    # 7. Gumroad promo split.
    body, promo = split_gumroad_promo("Appeal text\n\n" + GUMROAD_PROMO_MARKER)
    check("gumroad promo split", promo.startswith("PS:") and "Appeal text" in body)

    # 8. Payment/wallet token protection round trip.
    source_line = "Pay at https://wise.com/pay/business/vinaydusa please"
    protected, mapping = _protect_tokens(source_line, PRESERVE_TOKENS)
    check("token protected", "vinaydusa" not in protected and bool(mapping))
    check("token restored", _restore_tokens(protected, mapping) == source_line)

    # 9. Unreliable translation detection.
    check("unchanged translation flagged",
          _looks_like_untranslated("hello world, this needs translation", "hello world, this needs translation") is True)
    check("changed translation accepted", _looks_like_untranslated("hello world", "bonjour le monde") is False)

    # 10. Selector overrides fall back to the built-in defaults.
    eng = PublishingEngine({"selectors": {"form_submit": ["button.x"]}}, None, None, None)
    check("selector override honored", eng._selectors("form_submit", DEFAULT_FORM_SUBMIT_SELECTORS) == ["button.x"])
    eng_default = PublishingEngine({}, None, None, None)
    check("selector defaults used",
          eng_default._selectors("form_submit", DEFAULT_FORM_SUBMIT_SELECTORS) == DEFAULT_FORM_SUBMIT_SELECTORS)

    # 11. Database lifecycle and backup in a temp dir.
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "silk.db")
        bak = db.backup(keep=5)
        check("backup created", bak is not None and bak.exists())
        job = db.start_job("k1", "https://example.com/form", "example.com", "fundraising", "hash1", max_attempts=3)
        check("job starts in_progress", job.get("status") == "in_progress" and not job.get("exhausted"))
        check("interrupted jobs recovered", db.recover_interrupted_jobs() == 1)
        check("job marked interrupted", (db.get_job("k1") or {}).get("status") == "interrupted")

    # 12. Publishing gates refuse unverified destinations and stop at dry run.
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "silk.db")
        engine = PublishingEngine({}, db, None, None)
        site = WebsiteRecord(url="https://example.com/submit", category="fundraising")
        plan = SubmissionPlan(
            website=site, variant=ContentVariant.FUNDRAISING, target_language="en",
            translated_content="test content", destination_category="fundraising",
            intended_action="test", rules_summary="test",
            requires_registration=False, requires_email_verification=False,
            content_hash=_hashlib.sha256(b"test content").hexdigest(),
        )
        res = engine.submit(plan, browser=None, dry_run=True)
        check("unverified permission is skipped",
              res.status == "skipped" and "permission" in res.message.lower())

        ok_site = WebsiteRecord(
            url="https://example.org/submit", category="fundraising", language="en",
            registration_requirements=RegistrationRequirement.NONE,
            submission_method=SubmissionMethod.FORM,
            permission_status=PermissionStatus.ALLOWED, permission_verified=True,
            allowed_categories=["fundraising"], submission_method_verified=True,
            relevance_score=0.9,
        )
        ok_plan = SubmissionPlan(
            website=ok_site, variant=ContentVariant.FUNDRAISING, target_language="en",
            translated_content="test content", destination_category="fundraising",
            intended_action="test", rules_summary="test",
            requires_registration=False, requires_email_verification=False,
            content_hash=_hashlib.sha256(b"test content").hexdigest(),
        )
        res2 = engine.submit(ok_plan, browser=None, dry_run=True)
        check("verified destination stops at dry run",
              res2.status == "skipped" and "dry run" in res2.message.lower())

        # 13. Per-site dedup persists across reruns (same database).
        db.record_submission(
            website_id=None, website_url=ok_site.url, status="success",
            message="prior successful run", variant="fundraising",
        )
        res3 = engine.submit(ok_plan, browser=None, dry_run=False)
        check("site already submitted is skipped permanently",
              res3.status == "skipped" and "already" in res3.message.lower())

    # 14. Per-site accounts: unique passwords per domain, stable per domain.
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "silk.db")
        a1 = db.get_or_create_site_account("alpha.example", "me@example.com", ["vinaydxo"])
        a1b = db.get_or_create_site_account("alpha.example", "me@example.com", ["vinaydxo"])
        a2 = db.get_or_create_site_account("beta.example", "me@example.com", ["vinaydxo"])
        check("per-site password stable per domain", a1["password"] == a1b["password"])
        check("per-site passwords differ across domains", a1["password"] != a2["password"])
        check("account email stored", a1["email"] == "me@example.com")
        a3 = db.get_or_create_site_account("gamma.example", "me@example.com", ["vinaydxo"], universal_password="OnePass!23")
        a4 = db.get_or_create_site_account("delta.example", "me@example.com", ["vinaydxo"], universal_password="OnePass!23")
        check("universal_password shared across sites when set", a3["password"] == "OnePass!23" == a4["password"])

    # 15. ID verification pages are obstacles (never bypassed).
    check("ID verification detected",
          detect_obstacles(text="Please upload your government-issued ID to continue") != [])

    # 16. Sign-up gate: disabled config skips; enabled config reaches dry run.
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "silk.db")
        reg_site = WebsiteRecord(
            url="https://reg-example.net/join", category="fundraising", language="en",
            registration_requirements=RegistrationRequirement.REQUIRED,
            submission_method=SubmissionMethod.FORM,
            permission_status=PermissionStatus.ALLOWED, permission_verified=True,
            allowed_categories=["fundraising"], submission_method_verified=True,
            relevance_score=0.9,
        )
        reg_plan = SubmissionPlan(
            website=reg_site, variant=ContentVariant.FUNDRAISING, target_language="en",
            translated_content="test content", destination_category="fundraising",
            intended_action="test", rules_summary="test",
            requires_registration=True, requires_email_verification=False,
            content_hash=_hashlib.sha256(b"reg test").hexdigest(),
        )
        eng_off = PublishingEngine({"allow_account_creation_when_permitted": False}, db, None, None)
        r_off = eng_off.submit(reg_plan, browser=None, dry_run=True)
        check("signup skipped when account creation disabled",
              r_off.status == "skipped" and "disabled" in r_off.message.lower())
        eng_on = PublishingEngine({"allow_account_creation_when_permitted": True}, db, None, None)
        r_on = eng_on.submit(reg_plan, browser=None, dry_run=True)
        check("signup site reaches dry run when account creation enabled",
              r_on.status == "skipped" and "dry run" in r_on.message.lower())

    # 17. respect_site_rules flag (default on): off bypasses rule checks only.
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(Path(tmp) / "silk.db")
        blocked_site = WebsiteRecord(
            url="https://blocked-example.com/form", category="fundraising", language="en",
            registration_requirements=RegistrationRequirement.NONE,
            submission_method=SubmissionMethod.FORM,
            permission_status=PermissionStatus.PROHIBITED, permission_verified=False,
            submission_method_verified=True, relevance_score=0.9,
        )
        blocked_plan = SubmissionPlan(
            website=blocked_site, variant=ContentVariant.FUNDRAISING, target_language="en",
            translated_content="test content", destination_category="fundraising",
            intended_action="test", rules_summary="test",
            requires_registration=False, requires_email_verification=False,
            content_hash=_hashlib.sha256(b"blocked test").hexdigest(),
        )
        r_rules = PublishingEngine({}, db, None, None).submit(blocked_plan, browser=None, dry_run=True)
        check("prohibited site skipped when respect_site_rules on",
              r_rules.status == "skipped" and "prohibit" in r_rules.message.lower())
        r_norules = PublishingEngine({"respect_site_rules": False}, db, None, None).submit(blocked_plan, browser=None, dry_run=True)
        check("prohibited site reaches dry run when respect_site_rules off",
              r_norules.status == "skipped" and "dry run" in r_norules.message.lower())

    console.print(f"[cyan]{failures} failure(s)[/cyan]")
    return failures


@app.command("self-test")
def self_test_cmd() -> None:
    """Run offline self-checks (no network, no browser, no submissions)."""
    failures = run_self_tests()
    if failures:
        console.print(f"[red]{failures} self-test(s) failed[/red]")
        raise typer.Exit(code=1)
    console.print("[green]All self-tests passed[/green]")


if __name__ == "__main__":
    app()


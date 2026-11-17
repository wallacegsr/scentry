"""Settings, all from SCENTRY_* environment variables (lists and maps are JSON)."""

from __future__ import annotations

import tempfile
from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SCENTRY_", env_file=".env", extra="ignore", env_ignore_empty=True
    )

    database_url: str = "sqlite:///./scentry.db"

    # --- web sign-in -------------------------------------------------------------
    # basic: one admin account. proxy: trust a user header from a reverse proxy
    # (Authelia, Authentik, oauth2-proxy). none: no sign-in at all.
    auth_mode: Literal["basic", "proxy", "none"] = "basic"
    admin_user: str = "admin"
    admin_password: str = ""
    proxy_user_header: str = "Remote-User"
    trusted_proxies: list[str] = Field(default_factory=list)  # CIDRs allowed to set it
    host: str = "0.0.0.0"  # noqa: S104 - a container listens on all interfaces
    port: int = 8080

    # --- fetching ----------------------------------------------------------------
    # {"github.com": "<token>"}: a token is only ever sent to the host it is keyed by.
    git_tokens: dict[str, str] = Field(default_factory=dict)
    # Optional token with no scopes, used only to lift GitHub's API rate limit when
    # scanning public Home Assistant repositories.
    public_github_token: str = ""
    allow_local_paths: bool = False
    clone_timeout: int = 300

    # --- scanning ----------------------------------------------------------------
    work_dir: str = Field(default_factory=tempfile.gettempdir)
    scanner_timeout: int = 900
    disabled_scanners: list[str] = Field(default_factory=list)
    semgrep_config: str = "p/default"
    # False: ignore files and inline "nosemgrep"/"nosec" comments in a repository are
    # not honoured, so a repository can't hide code from the scanners. Suppress in the
    # portal instead, where it is recorded with a reason and an expiry.
    honor_repo_ignores: bool = False
    poll_seconds: int = 5
    # Barkley's scan store, which keeps the packages each scan resolved. The runner
    # image sets it (on the /cache volume); unset, there are no advisory re-checks.
    barkley_store: str = ""
    # How often the advisories of each installed and offered version are asked again
    # (seconds of work, no code fetched). 0: never.
    recheck_hours: int = 24

    # --- Home Assistant sync (the hass-sync service) -------------------------------
    # Unset: off. The token is a long-lived access token of an administrator (HA lists
    # the Marketplace only for admins); a dedicated user for Scentry is best.
    hass_url: str = ""
    hass_token: str = ""
    hass_verify_tls: bool = True
    hass_ca_file: str = ""  # a CA bundle for a self-signed HA certificate
    hass_poll_seconds: int = 600  # fallback read of the installed list
    hass_scan_interval_hours: int = 168  # rescans of each installed version

    # --- notifications (the notify service) -----------------------------------------
    # Apprise URLs (https://github.com/caronc/apprise/wiki), separated by spaces or
    # commas: ntfy://, gotify://, discord://, tgram://, mailto://, pover://, json://...
    # Unset: off. They hold secrets, so only the notify service is given them.
    notify_urls: str = ""
    notify_score_below: int = 70  # an HA verdict under this is announced (Very Sus, BORK)
    notify_min_severity: Literal["critical", "high", "medium", "low"] = "high"  # my code
    notify_clean_updates: bool = False  # also announce offered updates that look fine
    notify_failures: bool = True  # a target whose scans start failing
    notify_max_wait_minutes: int = 15  # wait for the queue to drain, at most this long
    public_url: str = ""  # the portal's address, for links in messages


@lru_cache
def get_settings() -> Settings:
    return Settings()

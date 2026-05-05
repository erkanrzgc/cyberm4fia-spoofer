from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Callable, TypeVar

from dotenv import load_dotenv


ENV_FILE = Path(".env")
ENV_FILE_EXAMPLE = Path(".env.example")

if ENV_FILE.exists():
    load_dotenv(ENV_FILE)

T = TypeVar("T")


def _env(key: str, default: str = "", cast: Callable[[str], T] = str) -> T:
    val = os.getenv(key, default)
    if not val and not default:
        return default
    try:
        return cast(val)
    except (ValueError, TypeError):
        return default


# ── session ──
SPOOF_INTERFACE = _env("SPOOF_INTERFACE")
SPOOF_LOG_LEVEL = _env("SPOOF_LOG_LEVEL", "INFO")
SPOOF_LOG_FILE = _env("SPOOF_LOG_FILE", "logs/spoof.log")
SPOOF_AUTO_FIREWALL = _env("SPOOF_AUTO_FIREWALL", "true", cast=lambda v: v.lower() in ("1", "true", "yes"))
SPOOF_RESTORE_ON_EXIT = _env("SPOOF_RESTORE_ON_EXIT", "true", cast=lambda v: v.lower() in ("1", "true", "yes"))
SPOOF_SAVE_STATS = _env("SPOOF_SAVE_STATS", "true", cast=lambda v: v.lower() in ("1", "true", "yes"))

# ── dns spoofing defaults ──
SPOOF_DNS_ENABLED = _env("SPOOF_DNS_ENABLED", "true", cast=lambda v: v.lower() in ("1", "true", "yes"))
SPOOF_DNS_MODE = _env("SPOOF_DNS_MODE", "race")
SPOOF_DNS_INTERFACE = _env("SPOOF_DNS_INTERFACE")
SPOOF_DNS_SPOOF_IP = _env("SPOOF_DNS_SPOOF_IP", "192.168.1.100")
SPOOF_DNS_TARGET = _env("SPOOF_DNS_TARGET", "*.vulnweb.com")
SPOOF_DNS_MATCH_TYPE = _env("SPOOF_DNS_MATCH_TYPE", "wildcard")
SPOOF_DNS_TTL = _env("SPOOF_DNS_TTL", "300", cast=int)

# ── arp spoofing defaults ──
SPOOF_ARP_ENABLED = _env("SPOOF_ARP_ENABLED", "true", cast=lambda v: v.lower() in ("1", "true", "yes"))
SPOOF_ARP_INTERFACE = _env("SPOOF_ARP_INTERFACE")
SPOOF_ARP_INTERVAL = _env("SPOOF_ARP_INTERVAL", "2.0", cast=float)
SPOOF_ARP_GATEWAY = _env("SPOOF_ARP_GATEWAY", "192.168.1.1")
SPOOF_ARP_VICTIM = _env("SPOOF_ARP_VICTIM", "192.168.1.105")

# ── webhooks ──
DISCORD_WEBHOOK_URL = _env("DISCORD_WEBHOOK_URL")
SLACK_WEBHOOK_URL = _env("SLACK_WEBHOOK_URL")
TELEGRAM_BOT_TOKEN = _env("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = _env("TELEGRAM_CHAT_ID")
WEBHOOK_URL = _env("WEBHOOK_URL")

# ── callbacks ──
CALLBACK_DNS_HIT_CMD = _env("CALLBACK_DNS_HIT_CMD")
CALLBACK_ARP_SPOOF_CMD = _env("CALLBACK_ARP_SPOOF_CMD")

# ── plugins ──
SPOOF_ENABLED_PLUGINS = _env("SPOOF_ENABLED_PLUGINS")
SPOOF_PLUGIN_DIR = _env("SPOOF_PLUGIN_DIR", "plugins")


def enabled_plugins() -> list[str]:
    raw = SPOOF_ENABLED_PLUGINS
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


def webhook_url() -> Optional[str]:
    return WEBHOOK_URL or DISCORD_WEBHOOK_URL or SLACK_WEBHOOK_URL or None


def is_configured() -> bool:
    """Check if .env file exists and has meaningful content."""
    return ENV_FILE.exists()

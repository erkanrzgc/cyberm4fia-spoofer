from __future__ import annotations

import os
import sys
import re
from pathlib import Path
from typing import Optional, Any

import yaml
from pydantic import ValidationError
from loguru import logger

from spoof.models import (
    SpoofConfig,
    SpoofRule,
    ARPTarget,
    ARPVictim,
    MatchType,
    DNSAction,
    DNSMode,
    RecordType,
    DNSRecord,
    DNSConfig,
    ARPConfig,
    SessionConfig,
    LogConfig,
    PluginConfig,
    CallbackConfig,
    WebhookConfig,
)
from spoof.env import (
    SPOOF_LOG_LEVEL,
    SPOOF_LOG_FILE,
    SPOOF_AUTO_FIREWALL,
    SPOOF_RESTORE_ON_EXIT,
    SPOOF_SAVE_STATS,
    SPOOF_DNS_ENABLED,
    SPOOF_DNS_MODE,
    SPOOF_DNS_INTERFACE,
    SPOOF_DNS_SPOOF_IP,
    SPOOF_DNS_TARGET,
    SPOOF_DNS_MATCH_TYPE,
    SPOOF_DNS_TTL,
    SPOOF_ARP_ENABLED,
    SPOOF_ARP_INTERFACE,
    SPOOF_ARP_INTERVAL,
    SPOOF_ARP_GATEWAY,
    SPOOF_ARP_VICTIM,
    SPOOF_INTERFACE,
    SPOOF_PLUGIN_DIR,
    enabled_plugins,
    webhook_url as _env_webhook_url,
    CALLBACK_DNS_HIT_CMD,
    CALLBACK_ARP_SPOOF_CMD,
)


DEFAULT_CONFIG_PATHS = [
    Path("config/targets.yaml"),
    Path.home() / ".config" / "spoof" / "targets.yaml",
    Path("/etc/spoof/targets.yaml"),
]


def _resolve_config_path(custom_path: Optional[str | Path] = None) -> Path:
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return p
        raise FileNotFoundError(f"config not found: {custom_path}")

    for p in DEFAULT_CONFIG_PATHS:
        if p.exists():
            return p

    raise FileNotFoundError(
        "no config file found. run 'spoof init' or create config/targets.yaml"
    )


def load_config(config_path: Optional[str | Path] = None) -> SpoofConfig:
    path = _resolve_config_path(config_path)
    logger.info(f"loading config: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    return SpoofConfig.model_validate(raw)


def save_config(config: SpoofConfig, path: Optional[str | Path] = None) -> Path:
    target = Path(path) if path else DEFAULT_CONFIG_PATHS[0]
    target.parent.mkdir(parents=True, exist_ok=True)

    data = config.model_dump(exclude_defaults=False, exclude_none=True)

    with open(target, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    logger.info(f"config saved: {target}")
    return target


def merge_cli_overrides(
    config: SpoofConfig,
    *,
    mode: Optional[str] = None,
    interface: Optional[str] = None,
    domain: Optional[str] = None,
    spoof_ip: Optional[str] = None,
    gateway: Optional[str] = None,
    victim: Optional[str] = None,
    dns_mode: Optional[str] = None,
    log_level: Optional[str] = None,
) -> SpoofConfig:
    if mode:
        if mode in ("dns", "mitm"):
            config.dns.enabled = True
        else:
            config.dns.enabled = False
        if mode in ("arp", "mitm"):
            config.arp.enabled = True
        else:
            config.arp.enabled = False

    if interface:
        config.dns.interface = interface
        config.arp.interface = interface
        config.session.interface = interface

    if domain and spoof_ip:
        rule = SpoofRule(
            pattern=domain,
            match_type=MatchType.EXACT if "*" not in domain else MatchType.WILDCARD,
            redirect_ip=spoof_ip,
            action=DNSAction.REDIRECT,
        )
        config.dns.targets = [rule]

    if gateway and victim:
        target = ARPTarget(
            gateway=gateway,
            victims=[ARPVictim(ip=victim)],
        )
        config.arp.targets = [target]

    if dns_mode:
        config.dns.mode = DNSMode(dns_mode)

    if log_level:
        config.session.log.level = log_level.upper()

    return config


def create_default_config() -> SpoofConfig:
    return SpoofConfig(
        session=SessionConfig(
            interface=SPOOF_INTERFACE or None,
            log=LogConfig(level=SPOOF_LOG_LEVEL, file=SPOOF_LOG_FILE),
            auto_firewall=SPOOF_AUTO_FIREWALL,
            restore_on_exit=SPOOF_RESTORE_ON_EXIT,
            save_stats=SPOOF_SAVE_STATS,
            plugin=PluginConfig(
                enabled_plugins=enabled_plugins(),
                plugin_dir=SPOOF_PLUGIN_DIR,
            ),
            callback=CallbackConfig(
                on_dns_hit=CALLBACK_DNS_HIT_CMD or None,
                on_arp_spoof=CALLBACK_ARP_SPOOF_CMD or None,
                webhook=WebhookConfig(url=_env_webhook_url() or None),
            ),
        ),
        dns=DNSConfig(
            enabled=SPOOF_DNS_ENABLED,
            mode=DNSMode(SPOOF_DNS_MODE),
            interface=SPOOF_DNS_INTERFACE or None,
            ttl=SPOOF_DNS_TTL,
            targets=[
                SpoofRule(
                    pattern=SPOOF_DNS_TARGET,
                    match_type=MatchType(SPOOF_DNS_MATCH_TYPE),
                    action=DNSAction.REDIRECT,
                    redirect_ip=SPOOF_DNS_SPOOF_IP,
                ),
                SpoofRule(
                    pattern="blocked.org",
                    match_type=MatchType.EXACT,
                    action=DNSAction.BLOCK,
                ),
            ],
        ),
        arp=ARPConfig(
            enabled=SPOOF_ARP_ENABLED,
            interface=SPOOF_ARP_INTERFACE or None,
            interval=SPOOF_ARP_INTERVAL,
            targets=[
                ARPTarget(
                    gateway=SPOOF_ARP_GATEWAY,
                    victims=[ARPVictim(ip=SPOOF_ARP_VICTIM)],
                ),
            ],
        ),
    )


def init_config(path: Optional[str | Path] = None) -> Path:
    config = create_default_config()
    return save_config(config, path)

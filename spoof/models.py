from __future__ import annotations

from enum import Enum
from typing import Optional, Union, Pattern
from pydantic import BaseModel, Field, IPvAnyAddress
from pathlib import Path


class MatchType(str, Enum):
    EXACT = "exact"
    WILDCARD = "wildcard"
    REGEX = "regex"


class DNSAction(str, Enum):
    REDIRECT = "redirect"
    NXDOMAIN = "nxdomain"
    FORWARD = "forward"
    BLOCK = "block"


class DNSMode(str, Enum):
    RACE = "race"
    INTERCEPT = "intercept"


class RecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"


class DNSRecord(BaseModel):
    type: RecordType = RecordType.A
    value: str


class SpoofRule(BaseModel):
    pattern: str
    match_type: MatchType = MatchType.EXACT
    action: DNSAction = DNSAction.REDIRECT
    redirect_ip: Optional[str] = None
    record_type: RecordType = RecordType.A
    records: list[DNSRecord] = Field(default_factory=list)
    enabled: bool = True


class ARPVictim(BaseModel):
    ip: str
    mac: Optional[str] = None

    def __hash__(self) -> int:
        return hash(self.ip)


class ARPTarget(BaseModel):
    gateway: str
    gateway_mac: Optional[str] = None
    victims: list[ARPVictim] = Field(default_factory=list)
    enabled: bool = True


class DNSConfig(BaseModel):
    enabled: bool = True
    mode: DNSMode = DNSMode.RACE
    interface: Optional[str] = None
    targets: list[SpoofRule] = Field(default_factory=list)
    ttl: int = 300


class ARPConfig(BaseModel):
    enabled: bool = True
    interface: Optional[str] = None
    interval: float = 2.0
    targets: list[ARPTarget] = Field(default_factory=list)
    restore_on_exit: bool = True


class FirewallConfig(BaseModel):
    auto_setup: bool = True
    auto_cleanup: bool = True
    rules: list[str] = Field(default_factory=list)


class LogConfig(BaseModel):
    level: str = "INFO"
    file: Optional[str] = "logs/spoof.log"
    format: str = "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} | {module}:{function}:{line} | {message}"
    rotation: str = "10 MB"
    retention: str = "7 days"
    stats_enabled: bool = True


class WebhookConfig(BaseModel):
    url: Optional[str] = None
    events: list[str] = Field(default_factory=lambda: ["on_dns_hit", "on_arp_spoof", "on_error"])


class CallbackConfig(BaseModel):
    on_dns_hit: Optional[str] = None
    on_arp_spoof: Optional[str] = None
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)


class PluginConfig(BaseModel):
    enabled_plugins: list[str] = Field(default_factory=list)
    plugin_dir: str = "plugins"


class SessionConfig(BaseModel):
    interface: Optional[str] = None
    log: LogConfig = Field(default_factory=LogConfig)
    plugin: PluginConfig = Field(default_factory=PluginConfig)
    firewall: FirewallConfig = Field(default_factory=FirewallConfig)
    callback: CallbackConfig = Field(default_factory=CallbackConfig)
    auto_firewall: bool = True
    restore_on_exit: bool = True
    daemon: bool = False
    save_stats: bool = True


class SpoofConfig(BaseModel):
    session: SessionConfig = Field(default_factory=SessionConfig)
    dns: DNSConfig = Field(default_factory=DNSConfig)
    arp: ARPConfig = Field(default_factory=ARPConfig)

    class Config:
        extra = "allow"


class PacketLog(BaseModel):
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    query_domain: Optional[str] = None
    spoofed: bool = False
    action: Optional[str] = None
    details: Optional[str] = None


class SessionStats(BaseModel):
    dns_queries_total: int = 0
    dns_spoofed: int = 0
    dns_forwarded: int = 0
    dns_blocked: int = 0
    arp_packets_sent: int = 0
    arp_targets_active: int = 0
    start_time: Optional[float] = None
    uptime: float = 0.0
    platform: str = ""
    interfaces: list[str] = Field(default_factory=list)


class HealthCheckResult(BaseModel):
    check: str
    passed: bool
    message: str
    suggestion: Optional[str] = None


class HealthReport(BaseModel):
    platform: str
    is_root: bool
    checks: list[HealthCheckResult] = Field(default_factory=list)
    all_passed: bool = False
    summary: str = ""


class DiscoveryResult(BaseModel):
    ip: str
    mac: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    is_gateway: bool = False
    open_ports: list[int] = Field(default_factory=list)

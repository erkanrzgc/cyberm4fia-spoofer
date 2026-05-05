from __future__ import annotations

import socket
import threading
import time
from typing import Optional, Callable

import scapy.all as scapy
from rich.console import Console
from rich.table import Table
from loguru import logger

from spoof.models import DiscoveryResult


def _get_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


_oui_cache: dict[str, str] = {}


def _lookup_oui(mac: str) -> Optional[str]:
    global _oui_cache
    if mac in _oui_cache:
        return _oui_cache[mac]
    try:
        import httpx
        oui = mac.replace(":", "").upper()[:6]
        r = httpx.get(f"https://api.macvendors.com/{oui}", timeout=5)
        if r.status_code == 200:
            _oui_cache[mac] = r.text.strip()
            return _oui_cache[mac]
    except Exception:
        pass
    return None


def discover_network(interface: str, timeout: int = 3, console: Console | None = None) -> list[DiscoveryResult]:
    cons = console or Console()
    results: list[DiscoveryResult] = []

    own_ip = scapy.get_if_addr(interface)
    netmask = scapy.get_if_addr(interface, with_mask=True)

    cons.print("[cyan]scanning network...[/cyan]")
    try:
        ans, _ = scapy.arping(netmask, timeout=timeout, verbose=False, iface=interface, no_filter=True)
    except Exception as e:
        logger.error(f"arp scan failed: {e}")
        return results

    if not ans:
        cons.print("[yellow]no devices found[/yellow]")
        return results

    for sent, received in ans:
        ip = received.psrc
        mac = received.hwsrc
        hostname = _get_hostname(ip)

        result = DiscoveryResult(
            ip=ip,
            mac=mac,
            hostname=hostname,
            vendor=_lookup_oui(mac),
            is_gateway=False,
        )
        results.append(result)

    try:
        gateway = scapy.conf.route.route("0.0.0.0")[2]
        for r in results:
            if r.ip == gateway:
                r.is_gateway = True
    except Exception:
        pass

    return results


def display_discovery(results: list[DiscoveryResult], console: Console | None = None) -> None:
    cons = console or Console()

    table = Table(title="network discovery", title_style="bold cyan")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="green")
    table.add_column("Hostname", style="white")
    table.add_column("Vendor", style="dim")
    table.add_column("Role", style="yellow")

    for r in results:
        role = "[yellow]GATEWAY[/yellow]" if r.is_gateway else ""
        table.add_row(r.ip, r.mac, r.hostname or "-", r.vendor or "-", role)

    cons.print(table)
    cons.print(f"[dim]{len(results)} device(s) found[/dim]")

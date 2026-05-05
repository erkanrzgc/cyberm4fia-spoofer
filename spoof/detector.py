from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Optional, Callable

import scapy.all as scapy
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from loguru import logger

from spoof.platform import get_platform


class ARPEntry:
    __slots__ = ("ip", "mac", "timestamp", "count")
    def __init__(self, ip: str, mac: str):
        self.ip = ip
        self.mac = mac
        self.timestamp = time.time()
        self.count = 1


class Alert:
    __slots__ = ("timestamp", "alert_type", "severity", "message", "details")
    def __init__(self, alert_type: str, severity: str, message: str, details: str = ""):
        self.timestamp = time.time()
        self.alert_type = alert_type
        self.severity = severity
        self.message = message
        self.details = details

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "type": self.alert_type,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
        }


class SpoofDetector:

    def __init__(self, interface: str):
        self._interface = interface
        self._running = False
        self._lock = threading.Lock()

        self._arp_table: dict[str, dict[str, ARPEntry]] = defaultdict(dict)
        self._dns_cache: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(lambda: deque(maxlen=5)))
        self._arp_flood_window: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self._alerts: list[Alert] = []
        self._callbacks: list[Callable] = []

        self._platform = get_platform()

    @property
    def alerts(self) -> list[Alert]:
        return list(self._alerts)

    def on_alert(self, callback: Callable) -> None:
        self._callbacks.append(callback)

    def _add_alert(self, alert: Alert) -> None:
        self._alerts.append(alert)
        sev_colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "dim"}
        color = sev_colors.get(alert.severity, "white")
        logger.warning(f"[<{color}>{alert.severity}</{color}>] {alert.alert_type}: {alert.message}")

        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def _check_arp(self, packet) -> None:
        if not packet.haslayer(scapy.ARP):
            return

        arp = packet[scapy.ARP]
        if arp.op != 2:
            return

        src_ip = arp.psrc
        src_mac = arp.hwsrc
        dst_ip = arp.pdst
        dst_mac = arp.hwdst

        with self._lock:
            now = time.time()
            self._arp_flood_window[src_mac].append(now)

            flood_count = sum(1 for t in self._arp_flood_window[src_mac] if now - t < 2)
            if flood_count > 20:
                self._add_alert(Alert(
                    alert_type="arp_flood",
                    severity="HIGH",
                    message=f"ARP flood detected from {src_mac} ({src_ip})",
                    details=f"{flood_count} packets in 2s",
                ))

            if src_ip in self._arp_table:
                for existing_mac, entry in list(self._arp_table[src_ip].items()):
                    if now - entry.timestamp > 60:
                        del self._arp_table[src_ip][existing_mac]

            if src_ip in self._arp_table and src_mac not in self._arp_table[src_ip]:
                self._add_alert(Alert(
                    alert_type="arp_spoof",
                    severity="CRITICAL",
                    message=f"ARP spoof detected: {src_ip} has multiple MACs",
                    details=f"new={src_mac} old={list(self._arp_table[src_ip].keys())}",
                ))

            entry = self._arp_table[src_ip].get(src_mac)
            if entry:
                entry.timestamp = now
                entry.count += 1
            else:
                self._arp_table[src_ip][src_mac] = ARPEntry(src_ip, src_mac)

            if dst_mac == "00:00:00:00:00:00" or dst_mac == "ff:ff:ff:ff:ff:ff":
                return

            if dst_mac == "ff:ff:ff:ff:ff:ff:ff:ff" or "00:00:00" in dst_mac:
                return

    def _check_dns(self, packet) -> None:
        if not packet.haslayer(scapy.DNS):
            return

        dns = packet[scapy.DNS]
        if dns.qr != 1 or dns.ancount == 0:
            return

        try:
            qname = dns.qd.qname
            qname_str = qname.decode("utf-8") if isinstance(qname, bytes) else str(qname)
        except Exception:
            return

        answers = []
        if dns.ancount and dns.an:
            ans_list = dns.an if isinstance(dns.an, list) else [dns.an]
            for a in ans_list:
                if hasattr(a, "rdata") and a.type == 1:
                    answers.append(a.rdata)

        if not answers:
            return

        with self._lock:
            now = time.time()
            entry = self._dns_cache[qname_str]

            for answer_ip in answers:
                ip_entries = entry[answer_ip]
                ip_entries.append(now)

                for other_ip in list(entry.keys()):
                    if other_ip != answer_ip:
                        other_entries = entry[other_ip]
                        recent_other = sum(1 for t in other_entries if now - t < 10)
                        recent_this = sum(1 for t in ip_entries if now - t < 10)
                        if recent_other > 2 and recent_this > 2:
                            self._add_alert(Alert(
                                alert_type="dns_spoof",
                                severity="HIGH",
                                message=f"DNS spoof detected: {qname_str} has conflicting IPs",
                                details=f"{other_ip} vs {answer_ip}",
                            ))

    def _sniff_loop(self) -> None:
        bpf = "arp or (udp port 53)"

        def handler(pkt):
            if not self._running:
                return
            try:
                self._check_arp(pkt)
                self._check_dns(pkt)
            except Exception as e:
                logger.debug(f"detector handler error: {e}")

        try:
            scapy.sniff(
                iface=self._interface,
                filter=bpf,
                prn=handler,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            if self._running:
                logger.error(f"detector sniff error: {e}")

    def start(self) -> None:
        self._running = True
        threading.Thread(target=self._sniff_loop, daemon=True).start()
        logger.info(f"spoof detector started on {self._interface}")

    def stop(self) -> None:
        self._running = False
        logger.info("spoof detector stopped")

    def display_alerts(self, console: Optional[Console] = None) -> None:
        cons = console or Console()

        if not self._alerts:
            cons.print("[green]no spoofing detected — network looks clean[/green]")
            return

        table = Table(title="Spoof Detection Alerts", title_style="bold red")
        table.add_column("Severity", style="bold")
        table.add_column("Type", style="cyan")
        table.add_column("Message", style="white")
        table.add_column("Details", style="dim")

        for a in self._alerts[-20:]:
            sev = f"[red]{a.severity}[/red]" if a.severity == "CRITICAL" else f"[yellow]{a.severity}[/yellow]"
            table.add_row(sev, a.alert_type, a.message, a.details[:60])

        cons.print(table)

        critical = sum(1 for a in self._alerts if a.severity == "CRITICAL")
        high = sum(1 for a in self._alerts if a.severity == "HIGH")
        cons.print(
            f"[dim]{len(self._alerts)} alerts: "
            f"[red]{critical} critical[/red], "
            f"[yellow]{high} high[/yellow][/dim]"
        )

    def export_alerts(self, filepath: str = "alerts.json") -> None:
        import json
        with open(filepath, "w") as f:
            json.dump([a.to_dict() for a in self._alerts], f, indent=2)
        logger.info(f"alerts exported: {filepath} ({len(self._alerts)} entries)")

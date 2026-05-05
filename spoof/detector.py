from __future__ import annotations

import hashlib
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
    __slots__ = ("timestamp", "alert_type", "severity", "message", "details", "dedup_key", "count")
    def __init__(self, alert_type: str, severity: str, message: str, details: str = ""):
        self.timestamp = time.time()
        self.alert_type = alert_type
        self.severity = severity
        self.message = message
        self.details = details
        self.dedup_key = hashlib.md5(f"{alert_type}:{message}".encode()).hexdigest()
        self.count = 1

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "type": self.alert_type,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
            "count": self.count,
        }


class SpoofDetector:

    DEDUP_WINDOW = 30
    BASELINE_DURATION = 10
    ARP_FLOOD_THRESHOLD = 20
    ARP_FLOOD_WINDOW = 2
    DNS_CONFLICT_THRESHOLD = 2
    DNS_CONFLICT_WINDOW = 10
    DNS_RESPONSE_FAST_MS = 5

    def __init__(self, interface: str, gateway_ip: Optional[str] = None):
        self._interface = interface
        self._gateway_ip = gateway_ip
        self._running = False
        self._lock = threading.Lock()

        self._arp_table: dict[str, dict[str, ARPEntry]] = defaultdict(dict)
        self._dns_cache: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(lambda: deque(maxlen=8)))
        self._arp_flood_window: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self._dns_query_times: dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
        self._alerts: list[Alert] = []
        self._dedup_registry: dict[str, float] = {}
        self._callbacks: list[Callable] = []

        self._stats = {
            "arp_packets": 0,
            "dns_responses": 0,
            "gratuitous_arp": 0,
            "arp_flood_alerts": 0,
            "arp_spoof_alerts": 0,
            "dns_spoof_alerts": 0,
            "dns_timing_alerts": 0,
        }

        self._baseline_until: float = 0.0
        self._platform = get_platform()

    @property
    def alerts(self) -> list[Alert]:
        return list(self._alerts)

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def on_alert(self, callback: Callable) -> None:
        self._callbacks.append(callback)

    def _add_alert(self, alert: Alert) -> None:
        now = time.time()
        key = alert.dedup_key

        if key in self._dedup_registry and now - self._dedup_registry[key] < self.DEDUP_WINDOW:
            if self._alerts and self._alerts[-1].dedup_key == key:
                self._alerts[-1].count += 1
                self._alerts[-1].timestamp = now
            return

        self._dedup_registry[key] = now

        old_keys = [k for k, v in self._dedup_registry.items() if now - v > self.DEDUP_WINDOW * 3]
        for k in old_keys:
            del self._dedup_registry[k]

        self._alerts.append(alert)

        sev_colors = {"CRITICAL": "red bold", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "dim"}
        color = sev_colors.get(alert.severity, "white")
        logger.warning(f"[{color}]{alert.severity}[/{color}] {alert.alert_type}: {alert.message}")

        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def _check_arp(self, packet) -> None:
        if not packet.haslayer(scapy.ARP):
            return

        arp = packet[scapy.ARP]
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        dst_ip = arp.pdst
        dst_mac = arp.hwdst

        with self._lock:
            self._stats["arp_packets"] += 1
            now = time.time()

            if arp.op == 1 and src_ip == dst_ip:
                self._stats["gratuitous_arp"] += 1
                self._add_alert(Alert(
                    alert_type="gratuitous_arp",
                    severity="MEDIUM",
                    message=f"Gratuitous ARP from {src_mac} claiming {src_ip}",
                    details=f"gratuitous ARP can indicate ARP spoofing or IP conflict",
                ))
                return

            if arp.op != 2:
                return

            if src_ip == "0.0.0.0" or src_mac == "00:00:00:00:00:00":
                return

            self._arp_flood_window[src_mac].append(now)
            flood_count = sum(1 for t in self._arp_flood_window[src_mac] if now - t < self.ARP_FLOOD_WINDOW)
            if flood_count > self.ARP_FLOOD_THRESHOLD:
                self._stats["arp_flood_alerts"] += 1
                self._add_alert(Alert(
                    alert_type="arp_flood",
                    severity="HIGH",
                    message=f"ARP flood from {src_mac} ({src_ip})",
                    details=f"{flood_count} packets in {self.ARP_FLOOD_WINDOW}s",
                ))

            for ip_str, macs in list(self._arp_table.items()):
                for existing_mac in list(macs.keys()):
                    if now - macs[existing_mac].timestamp > 120:
                        del macs[existing_mac]
                if not macs:
                    del self._arp_table[ip_str]

            if src_ip in self._arp_table and src_mac not in self._arp_table[src_ip]:
                old_macs = list(self._arp_table[src_ip].keys())

                is_gw = self._gateway_ip and src_ip == self._gateway_ip
                severity = "CRITICAL" if is_gw else "HIGH"
                self._stats["arp_spoof_alerts"] += 1

                self._add_alert(Alert(
                    alert_type="arp_spoof",
                    severity=severity,
                    message=f"ARP spoof detected: {src_ip} has multiple MACs {'[GATEWAY!]' if is_gw else ''}",
                    details=f"new={src_mac} old={old_macs}",
                ))

            entry = self._arp_table[src_ip].get(src_mac)
            if entry:
                entry.timestamp = now
                entry.count += 1
            else:
                self._arp_table[src_ip][src_mac] = ARPEntry(src_ip, src_mac)

    def _check_dns(self, packet) -> None:
        if not packet.haslayer(scapy.DNS):
            return

        dns = packet[scapy.DNS]

        if dns.qr == 0 and dns.qdcount > 0:
            try:
                qname = dns.qd.qname
                qname_str = qname.decode("utf-8") if isinstance(qname, bytes) else str(qname)
                key = f"q:{qname_str}|{dns.id}"
                self._dns_query_times[key].append(time.time())
            except Exception:
                pass
            return

        if dns.qr != 1 or dns.ancount == 0:
            return

        with self._lock:
            self._stats["dns_responses"] += 1
            now = time.time()

        try:
            qname = dns.qd.qname
            qname_str = qname.decode("utf-8") if isinstance(qname, bytes) else str(qname)
        except Exception:
            return

        dns_id = dns.id
        query_key = f"q:{qname_str}|{dns_id}"

        with self._lock:
            times = self._dns_query_times.get(query_key)
            if times:
                query_time = times[-1]
                response_ms = (now - query_time) * 1000
                if response_ms < self.DNS_RESPONSE_FAST_MS and response_ms > 0:
                    self._stats["dns_timing_alerts"] += 1
                    self._add_alert(Alert(
                        alert_type="dns_fast_response",
                        severity="MEDIUM",
                        message=f"Suspiciously fast DNS response for {qname_str}",
                        details=f"{response_ms:.1f}ms — may indicate local spoofing",
                    ))

                stale_keys = [k for k, v in self._dns_query_times.items() if now - (v[-1] if v else 0) > 30]
                for k in stale_keys:
                    del self._dns_query_times[k]

        answers = []
        if dns.ancount and dns.an:
            ans_list = dns.an if isinstance(dns.an, list) else [dns.an]
            for a in ans_list:
                if hasattr(a, "rdata"):
                    answers.append((a.type, a.rdata))

        if not answers:
            return

        with self._lock:
            entry = self._dns_cache[qname_str]

            for ans_type, ans_data in answers:
                key = f"{ans_type}:{ans_data}"
                ip_entries = entry[key]
                ip_entries.append(now)

                for other_key in list(entry.keys()):
                    if other_key == key:
                        continue
                    recent_other = sum(1 for t in entry[other_key] if now - t < self.DNS_CONFLICT_WINDOW)
                    recent_this = sum(1 for t in ip_entries if now - t < self.DNS_CONFLICT_WINDOW)
                    if recent_other > self.DNS_CONFLICT_THRESHOLD and recent_this > self.DNS_CONFLICT_THRESHOLD:
                        self._stats["dns_spoof_alerts"] += 1
                        self._add_alert(Alert(
                            alert_type="dns_spoof",
                            severity="HIGH",
                            message=f"DNS spoof detected: {qname_str} has conflicting records",
                            details=f"{other_key} vs {key}",
                        ))

    def start(self) -> None:
        self._running = True
        self._baseline_until = time.time() + self.BASELINE_DURATION
        threading.Thread(target=self._sniff_loop, daemon=True).start()
        logger.info(
            f"spoof detector started on {self._interface} "
            f"(baseline: {self.BASELINE_DURATION}s, gateway: {self._gateway_ip or 'auto'})"
        )

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

    def stop(self) -> None:
        self._running = False
        logger.info("spoof detector stopped")

    def display_status(self, console: Optional[Console] = None) -> None:
        cons = console or Console()
        s = self._stats
        _a = self._alerts

        cons.print(Panel(
            f"[bold cyan]detector status[/bold cyan]\n"
            f" ARP packets seen: [cyan]{s['arp_packets']}[/cyan]  "
            f" DNS responses: [cyan]{s['dns_responses']}[/cyan]\n"
            f" Gratuitous ARP:  [yellow]{s['gratuitous_arp']}[/yellow]  "
            f" ARP floods: [yellow]{s['arp_flood_alerts']}[/yellow]\n"
            f" ARP spoof:       [red]{s['arp_spoof_alerts']}[/red]  "
            f" DNS spoof: [red]{s['dns_spoof_alerts']}[/red]  "
            f" Fast DNS: [yellow]{s['dns_timing_alerts']}[/yellow]\n"
            f" Total alerts:    [bold]{len(_a)}[/bold]",
            border_style="cyan",
        ))

    def display_alerts(self, console: Optional[Console] = None) -> None:
        cons = console or Console()

        if not self._alerts:
            cons.print("[green]no spoofing detected — network looks clean[/green]")
            return

        table = Table(title="Spoof Detection Alerts", title_style="bold red")
        table.add_column("Sev", style="bold", width=6)
        table.add_column("Type", style="cyan", width=10)
        table.add_column("Message", style="white")
        table.add_column("×", justify="right", style="dim", width=3)
        table.add_column("Time", style="dim", width=12)

        for a in sorted(self._alerts, key=lambda x: x.timestamp)[-25:]:
            sev = {"CRITICAL": "[red bold]CRIT[/]", "HIGH": "[yellow]HIGH[/]", "MEDIUM": "[cyan]MED [/]", "LOW": "[dim]LOW [/]"}.get(a.severity, a.severity)
            ts = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
            table.add_row(sev, a.alert_type[:10], a.message[:55], str(a.count) if a.count > 1 else "", ts)

        cons.print(table)

        crit = sum(1 for a in self._alerts if a.severity == "CRITICAL")
        high = sum(1 for a in self._alerts if a.severity == "HIGH")
        med = sum(1 for a in self._alerts if a.severity == "MEDIUM")
        cons.print(
            f"[dim]{len(self._alerts)} unique alerts: "
            f"[red]{crit} crit[/red] "
            f"[yellow]{high} high[/yellow] "
            f"[cyan]{med} med[/cyan][/dim]"
        )

    def export_alerts(self, filepath: str = "alerts.json") -> None:
        import json
        with open(filepath, "w") as f:
            json.dump([a.to_dict() for a in self._alerts], f, indent=2)
        logger.info(f"alerts exported: {filepath} ({len(self._alerts)} entries)")

    def get_gateway_ip(self) -> Optional[str]:
        if self._gateway_ip:
            return self._gateway_ip
        try:
            gw = scapy.conf.route.route("0.0.0.0")[2]
            if gw and gw != "0.0.0.0":
                self._gateway_ip = gw
                return gw
        except Exception:
            pass
        return None

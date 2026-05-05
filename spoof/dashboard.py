from __future__ import annotations

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive

from spoof.session import SpoofSession
from spoof.models import SessionStats


class StatsPanel(Static):
    stats: SessionStats = SessionStats()

    def on_mount(self) -> None:
        self.set_interval(1, self.refresh_stats)

    def refresh_stats(self) -> None:
        self.refresh()

    def render(self) -> str:
        s = self.stats
        return (
            f"[bold cyan]Session Stats[/bold cyan]\n"
            f"─────────────────────────\n"
            f"DNS Queries:  [bold]{s.dns_queries_total}[/bold]\n"
            f"DNS Spoofed:  [bold green]{s.dns_spoofed}[/bold green]\n"
            f"DNS Blocked:  [bold red]{s.dns_blocked}[/bold red]\n"
            f"DNS Forward:  [dim]{s.dns_forwarded}[/dim]\n"
            f"─\n"
            f"ARP Packets:  [bold]{s.arp_packets_sent}[/bold]\n"
            f"ARP Active:   [bold yellow]{s.arp_targets_active}[/bold yellow]\n"
            f"─\n"
            f"Uptime:       [dim]{s.uptime:.1f}s[/dim]\n"
        )


class LogPanel(Static):
    messages: reactive[list[str]] = reactive([])

    def add_message(self, msg: str) -> None:
        self.messages = (self.messages + [msg])[-20:]

    def render(self) -> str:
        return (
            "[bold cyan]Live Log[/bold cyan]\n"
            "─────────────────────────\n"
            + "\n".join(self.messages[-15:])
        )


class TargetPanel(Static):
    dns_rules: list = []
    arp_targets: list = []

    def render(self) -> str:
        out = "[bold cyan]Active Targets[/bold cyan]\n"
        out += "─────────────────────────\n"

        out += "[green]DNS Targets:[/green]\n"
        if self.dns_rules:
            for r in self.dns_rules[:10]:
                ip = r.redirect_ip or "BLOCK"
                out += f"  {r.pattern} → [dim]{ip}[/dim] ({r.match_type.value})\n"
        else:
            out += "  [dim]none[/dim]\n"

        out += "[yellow]ARP Targets:[/yellow]\n"
        if self.arp_targets:
            for t in self.arp_targets[:10]:
                for v in t.victims:
                    out += f"  gw:{t.gateway} ↔ victim:{v.ip}\n"
        else:
            out += "  [dim]none[/dim]\n"

        return out


class DashboardApp(App):
    CSS = """
    StatsPanel { border: solid green; padding: 1; }
    LogPanel { border: solid cyan; padding: 1; }
    TargetPanel { border: solid yellow; padding: 1; }
    """

    def __init__(self, session: SpoofSession):
        super().__init__()
        self._session = session

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical():
                yield StatsPanel()
            with Vertical():
                yield TargetPanel()
                yield LogPanel()
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(1, self._poll_stats)

    def _poll_stats(self) -> None:
        stats = self._session.stats
        stats_panel = self.query_one(StatsPanel)
        stats_panel.stats = stats

        target_panel = self.query_one(TargetPanel)
        target_panel.dns_rules = self._session.config.dns.targets
        target_panel.arp_targets = self._session.config.arp.targets

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, ListView, ListItem
from textual.containers import Container
from textual.binding import Binding
from textual.screen import Screen

from spoof.session import SpoofSession
from spoof.banner import render_banner, BANNER_ART
from spoof.models import SessionStats


class MenuOption(ListItem):
    def __init__(self, label: str, key: str, description: str):
        super().__init__()
        self.option_key = key
        self._label = label
        self._desc = description

    def compose(self) -> ComposeResult:
        yield Static(f"[bold]{self._label}[/bold]\n  [dim]{self._desc}[/dim]")


class MainMenu(Screen):
    BINDINGS = [
        Binding("1", "select_1", "DNS Spoof"),
        Binding("2", "select_2", "ARP Spoof"),
        Binding("3", "select_3", "MITM Mode"),
        Binding("4", "select_4", "Targets"),
        Binding("5", "select_5", "Stats"),
        Binding("6", "select_6", "Dashboard"),
        Binding("0", "quit", "Exit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("[bold cyan]CYBERM4FIA[/bold cyan] — cross-platform dns & arp spoofing toolkit", id="title")
        yield Static("")
        yield ListView(
            MenuOption("[1] DNS Spoofing", "1", "Start DNS spoofing with configured targets"),
            MenuOption("[2] ARP Spoofing", "2", "Start ARP cache poisoning attack"),
            MenuOption("[3] MITM Mode", "3", "Launch DNS + ARP spoofing together"),
            MenuOption("[4] Target Management", "4", "Add, remove, or view targets"),
            MenuOption("[5] Session Stats", "5", "View current session statistics"),
            MenuOption("[6] Live Dashboard", "6", "Open real-time monitoring dashboard"),
            MenuOption("[0] Exit", "0", "Quit CyberM4fia"),
        )
        yield Footer()

    def action_select_1(self) -> None:
        self.app.trigger_action("dns_spoof")

    def action_select_2(self) -> None:
        self.app.trigger_action("arp_spoof")

    def action_select_3(self) -> None:
        self.app.trigger_action("mitm")

    def action_select_4(self) -> None:
        self.app.trigger_action("targets")

    def action_select_5(self) -> None:
        self.app.trigger_action("stats")

    def action_select_6(self) -> None:
        self.app.trigger_action("dashboard")


class SpoofMenu(App):
    CSS = """
    #title { text-align: center; margin: 1 0; }
    ListView { margin: 1 2; }
    ListItem { padding: 1 2; }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "\n".join(BANNER_ART.strip().split("\n")[:3]),
            id="banner",
        )
        yield MainMenu()
        yield Footer()

    def on_mount(self) -> None:
        self.title = "CYBERM4FIA"

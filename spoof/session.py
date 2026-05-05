from __future__ import annotations

import signal
import threading
import time
import json
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from loguru import logger

from spoof.models import (
    SpoofConfig,
    SessionStats,
    SpoofRule,
    ARPTarget,
    DNSMode,
)
from spoof.logger import setup_logger, get_logger
from spoof.config import load_config, merge_cli_overrides, save_config
from spoof.platform import get_platform
from spoof.firewall import get_firewall
from spoof.core.dns_spoofer import DNSSpoofer
from spoof.core.arp_spoofer import ARPSpoofer
from spoof.callback import CallbackManager
from spoof.plugin_manager import PluginManager
from spoof.banner import render_banner


class SpoofSession:
    def __init__(
        self,
        config: SpoofConfig,
        config_path: Optional[Path] = None,
    ):
        self._config = config
        self._config_path = config_path
        self._platform = get_platform()
        self._firewall = get_firewall()
        self._dns_spoofer: Optional[DNSSpoofer] = None
        self._arp_spoofer: Optional[ARPSpoofer] = None
        self._callback: Optional[CallbackManager] = None
        self._plugin_manager = PluginManager(config.session.plugin.plugin_dir)
        self._running = False
        self._console = Console()

        setup_logger(config.session.log)
        self._logger = get_logger()

    @property
    def config(self) -> SpoofConfig:
        return self._config

    @property
    def stats(self) -> SessionStats:
        s = SessionStats(platform=self._platform.name())
        if self._dns_spoofer:
            dns_s = self._dns_spoofer.stats
            s.dns_queries_total = dns_s.dns_queries_total
            s.dns_spoofed = dns_s.dns_spoofed
            s.dns_forwarded = dns_s.dns_forwarded
            s.dns_blocked = dns_s.dns_blocked
        if self._arp_spoofer:
            arp_s = self._arp_spoofer.stats
            s.arp_packets_sent = arp_s.arp_packets_sent
            s.arp_targets_active = arp_s.arp_targets_active
        return s

    def setup(self) -> None:
        self._logger.info("setting up spoof session")
        self._logger.info(f"platform: {self._platform.name()}")
        self._logger.info(f"root: {self._platform.is_root()}")

        if not self._platform.is_root():
            self._logger.warning("not running as root — root required for raw socket operations")

        iface = self._config.session.interface or self._config.dns.interface or self._config.arp.interface
        if not iface:
            iface = self._platform.get_default_interface()
            self._logger.info(f"using default interface: {iface}")

        self._config.session.interface = iface or ""
        self._config.dns.interface = iface or ""
        self._config.arp.interface = iface or ""

        self._callback = CallbackManager(
            on_dns_hit_cmd=self._config.session.callback.on_dns_hit,
            on_arp_spoof_cmd=self._config.session.callback.on_arp_spoof,
            webhook_url=self._config.session.callback.webhook.url,
        )

        if self._config.session.plugin.enabled_plugins:
            self._plugin_manager.load_all(self._config.session.plugin.enabled_plugins)
        else:
            from spoof.env import enabled_plugins as _env_plugins
            _ep = _env_plugins()
            if _ep:
                self._plugin_manager.load_all(_ep)

    def _setup_firewall(self) -> None:
        if not self._config.session.auto_firewall:
            return
        if self._config.dns.enabled:
            try:
                self._firewall.setup_dns_redirect()
                self._logger.info("firewall dns redirect rules set up")
            except PermissionError:
                self._logger.warning("cannot set up firewall — run as root")

    def _start_dns(self) -> None:
        if not self._config.dns.enabled:
            return
        if not self._config.dns.targets:
            self._logger.warning("dns spoofing enabled but no targets configured")
            return

        self._dns_spoofer = DNSSpoofer(
            rules=self._config.dns.targets,
            interface=self._config.dns.interface or self._config.session.interface or "",
            mode=self._config.dns.mode,
        )
        if self._callback:
            self._dns_spoofer.on_hit(self._callback.on_dns_hit)
        self._dns_spoofer.on_hit(self._plugin_manager.trigger_dns_hit)
        self._dns_spoofer.start()

    def _start_arp(self) -> None:
        if not self._config.arp.enabled:
            return
        if not self._config.arp.targets:
            self._logger.warning("arp spoofing enabled but no targets configured")
            return

        self._arp_spoofer = ARPSpoofer(
            targets=self._config.arp.targets,
            interface=self._config.arp.interface or self._config.session.interface or "",
            interval=self._config.arp.interval,
        )
        if self._callback:
            self._arp_spoofer.on_hit(self._callback.on_arp_spoof)
        self._arp_spoofer.on_hit(self._plugin_manager.trigger_arp_spoof)
        self._arp_spoofer.start()

    def start(self) -> None:
        self.setup()
        self._logger.info("starting spoof session")
        self._running = True

        self._plugin_manager.trigger_session_start()
        self._setup_firewall()

        if self._config.arp.enabled:
            self._platform.enable_ip_forward()
            self._logger.info("ip forwarding enabled")

        self._start_dns()
        self._start_arp()

        self._console.print()
        render_banner(self._console)
        self._console.print(Panel(
            "[bold green]session active[/bold green]  |  "
            f"[cyan]interface:[/cyan] {self._config.session.interface}  |  "
            f"[cyan]dns:[/cyan] {'on' if self._config.dns.enabled else 'off'}  |  "
            f"[cyan]arp:[/cyan] {'on' if self._config.arp.enabled else 'off'}  |  "
            "[dim]ctrl+c to stop[/dim]",
            border_style="green",
        ))

        def handler(sig, frame):
            if self._running:
                self._console.print("\n[yellow]shutting down...[/yellow]")
                self.stop()

        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

        self._logger.info("session running — press ctrl+c to stop")

    def stop(self, save_stats_file: Optional[Path] = None) -> None:
        if not self._running:
            return
        self._running = False

        self._logger.info("stopping spoof session")

        if self._dns_spoofer:
            self._dns_spoofer.stop()

        if self._arp_spoofer:
            restore = self._config.session.restore_on_exit and self._config.arp.restore_on_exit
            self._arp_spoofer.stop(restore=restore)

        if self._config.arp.enabled:
            self._platform.disable_ip_forward()
            self._logger.info("ip forwarding disabled")

        if self._config.session.auto_firewall and self._config.session.firewall.auto_cleanup:
            try:
                self._firewall.cleanup()
                self._logger.info("firewall rules cleaned up")
            except PermissionError:
                pass

        self._plugin_manager.trigger_session_stop()
        self._display_final_stats()

        if save_stats_file or self._config.session.save_stats:
            self._save_stats(save_stats_file)

    def _display_final_stats(self) -> None:
        s = self.stats
        self._console.print()
        self._console.print(Panel(
            f"[bold]session stats[/bold]\n\n"
            f"[cyan]dns queries:[/cyan] {s.dns_queries_total}  "
            f"[green]spoofed:[/green] {s.dns_spoofed}  "
            f"[red]blocked:[/red] {s.dns_blocked}  "
            f"[dim]forwarded:[/dim] {s.dns_forwarded}\n"
            f"[cyan]arp packets:[/cyan] {s.arp_packets_sent}  "
            f"[dim]active targets:[/dim] {s.arp_targets_active}",
            border_style="cyan",
        ))

    def _save_stats(self, filepath: Optional[Path] = None) -> None:
        path = filepath or Path("logs") / "stats.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.stats.model_dump()
        data["uptime"] = time.time() - (data.get("start_time") or time.time())
        data["timestamp"] = time.time()
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        self._logger.info(f"stats saved: {path}")

    def reload_config(self, config_path: Optional[Path] = None) -> None:
        self._logger.info("reloading configuration")
        self._config = load_config(config_path or self._config_path)


def create_session(config: SpoofConfig, config_path: Optional[Path] = None) -> SpoofSession:
    return SpoofSession(config, config_path)
